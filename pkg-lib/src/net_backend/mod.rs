use std::sync::atomic::{AtomicU64, Ordering};
use std::{cell::RefCell, rc::Rc};
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
};
use thiserror::Error;

mod curl_backend;
#[cfg(feature = "library")]
mod reqwest_backend;

use crate::callback::Callback;

pub use curl_backend::CurlBackend;
#[cfg(not(feature = "library"))]
pub use curl_backend::CurlBackend as DefaultNetBackend;
#[cfg(feature = "library")]
pub use reqwest_backend::ReqwestBackend;
#[cfg(feature = "library")]
pub use reqwest_backend::ReqwestBackend as DefaultNetBackend;

pub enum DownloadBackendWriter {
    ToFile(File),
    ToBuf(Vec<u8>),
}

impl Write for DownloadBackendWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            DownloadBackendWriter::ToFile(file) => file.write(buf),
            DownloadBackendWriter::ToBuf(items) => items.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            DownloadBackendWriter::ToFile(file) => file.flush(),
            DownloadBackendWriter::ToBuf(items) => items.flush(),
        }
    }
}

impl DownloadBackendWriter {
    pub fn to_inner_buf(self) -> Vec<u8> {
        match self {
            DownloadBackendWriter::ToBuf(items) => items,
            _ => panic!("Logic error, should be a buffer going here"),
        }
    }
    pub fn to_inner_file(self) -> File {
        match self {
            DownloadBackendWriter::ToFile(file) => file,
            _ => panic!("Logic error, should be a file handle going here"),
        }
    }
}

pub trait DownloadBackend {
    fn new() -> Result<Self, DownloadError>
    where
        Self: Sized;

    fn download(
        &self,
        remote_path: &str,
        remote_len: Option<u64>,
        writer: &mut DownloadBackendWriter,
        callback: Rc<RefCell<dyn Callback>>,
    ) -> Result<(), DownloadError>;

    fn download_to_file(
        &self,
        remote_path: &str,
        remote_len: Option<u64>,
        local_path: &Path,
        callback: Rc<RefCell<dyn Callback>>,
    ) -> Result<(), DownloadError> {
        // Download to a private temporary name and rename it into place, rather than writing
        // the destination directly. Writing directly truncates the file before the first byte
        // arrives, so anyone reading it meanwhile sees an empty or half-written file, and a
        // download that fails leaves a 0-byte file behind that looks like a valid cached one.
        // Two callers fetching the same key concurrently hit exactly that: one truncated the
        // pubkey cache while the other parsed it and got "missing field `pkey`". Rename within
        // a directory is atomic, so a reader sees either the old file or the complete new one.
        //
        // The temporary name carries pid and a counter because two threads in one process would
        // otherwise pick the same one and race each other instead.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let mut tmp_name = local_path.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(format!(
            ".{}.{}.part",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let tmp_path = local_path.with_file_name(tmp_name);

        // Not File::create: it follows a symlink at the final component, which is exactly how a
        // planted link in the download directory turned a download into a write to an arbitrary
        // path with the caller's privileges. See repo_manager::ensure_private_dir.
        let mut output =
            DownloadBackendWriter::ToFile(crate::repo_manager::create_file_nofollow(&tmp_path)?);
        let result = self.download(remote_path, remote_len, &mut output, callback);
        drop(output);
        if result.is_err() {
            // Leave nothing that a later run could mistake for a cached download.
            let _ = std::fs::remove_file(&tmp_path);
            return result;
        }
        std::fs::rename(&tmp_path, local_path)?;
        Ok(())
    }

    fn download_to_buf(
        &self,
        remote_path: &str,
        callback: Rc<RefCell<dyn Callback>>,
    ) -> Result<Vec<u8>, DownloadError> {
        let mut output = DownloadBackendWriter::ToBuf(Vec::new());
        self.download(remote_path, None, &mut output, callback)?;
        Ok(output.to_inner_buf())
    }

    fn file_size(&self) -> Option<usize> {
        None
    }
}

#[derive(Error, Debug)]
pub enum DownloadError {
    // Specific variant for timeout errors
    #[error("Download timed out")]
    Timeout,
    // Specific variant for HTTP status errors (e.g., 404, 500)
    #[cfg(feature = "library")]
    #[error("HTTP error status: {0}")]
    HttpStatus(reqwest::StatusCode),
    // Fallback for other generic reqwest errors
    #[cfg(feature = "library")]
    #[error("Other reqwest error: {0}")]
    Reqwest(reqwest::Error),
    // IO errors remain the same
    #[error("IO error: {0}")]
    IO(#[from] io::Error),
    #[error("General error: {0}")]
    Other(String),
}

#[cfg(feature = "library")]
impl From<reqwest::Error> for DownloadError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            DownloadError::Timeout
        } else if err.is_status() {
            DownloadError::HttpStatus(
                err.status()
                    .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            )
        } else {
            DownloadError::Reqwest(err)
        }
    }
}
