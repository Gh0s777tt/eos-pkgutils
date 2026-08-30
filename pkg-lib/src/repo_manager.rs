use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::File;
use std::path::Path;
use std::rc::Rc;
use std::{fs, path::PathBuf};

use crate::backend::wrap_io_err;
use crate::callback::Callback;
#[cfg(feature = "library")]
use crate::net_backend::DownloadError;
use crate::net_backend::{DownloadBackend, DownloadBackendWriter};
use crate::package::RemoteName;
use crate::{backend::Error, package::PackageError, PackageName};
use crate::{DOWNLOAD_DIR, PACKAGES_REMOTE_DIR};
use serde_derive::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

/// Make `path` a directory only we can write into, or fail.
///
/// WHY THIS EXISTS. The default download path is `/tmp/pkg_download/`, a fixed name under a
/// world-writable directory, and the files in it are named predictably (`<remote>_<pkg>.pkgar`).
/// Nothing checked who owned that directory. Any local user could create it first, or drop a
/// symlink named after a package into it, and `File::create` -- which follows symlinks -- then
/// wrote the download through that link with the privileges of whoever ran `pkg`. Demonstrated
/// before this fix: an unprivileged user planted a link and root's `pkg` created a 868,992-byte
/// root-owned file at the attacker's chosen path. That is an arbitrary file write as root.
///
/// Two things are checked, because either alone leaves a hole: the directory must belong to us
/// (someone else's directory is refused outright rather than used), and it must not be writable
/// by group or other (otherwise they can still plant entries in a directory we do own). The
/// second is repaired rather than rejected -- we own it, so tightening it is both safe and
/// kinder than failing a build over a stale mode.
fn ensure_private_dir(path: &Path) -> Result<(), Error> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(wrap_io_err!(path, "Creating dir"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(wrap_io_err!(path, "Securing dir"))?;
            return Ok(());
        }
        Err(err) => return Err(Error::IO(err, path.to_path_buf(), "Reading metadata")),
    };

    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::IO(
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "download path is a symlink or not a directory; refusing to use it",
            ),
            path.to_path_buf(),
            "Checking dir",
        ));
    }

    let us = unsafe { libc::geteuid() };
    if meta.uid() != us {
        return Err(Error::IO(
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "download path belongs to uid {}, not to us (uid {us}); refusing to use it",
                    meta.uid()
                ),
            ),
            path.to_path_buf(),
            "Checking owner",
        ));
    }

    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode & !0o022))
            .map_err(wrap_io_err!(path, "Securing dir"))?;
    }
    Ok(())
}

/// Create a file for writing, refusing to follow a symlink at the final component.
///
/// The directory check above closes the door; this one keeps it shut if a link was planted
/// before the mode was tightened, or if a caller points the download path somewhere looser.
pub(crate) fn create_file_nofollow(path: &Path) -> std::io::Result<File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}
/// Remote package management
pub struct RepoManager {
    /// http sources
    pub remotes: Vec<RemoteName>,
    /// file sources
    pub locals: Vec<RemoteName>,
    /// detailed http + file sources
    pub remote_map: BTreeMap<RemoteName, RemotePath>,
    pub download_path: PathBuf,
    pub download_backend: Rc<Box<dyn DownloadBackend>>,

    pub callback: Rc<RefCell<dyn Callback>>,
}

impl Debug for RepoManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoManager")
            .field("remotes", &self.remotes)
            .field("locals", &self.locals)
            .field("remote_map", &self.remote_map)
            .field("download_path", &self.download_path)
            .finish()
    }
}

impl Clone for RepoManager {
    fn clone(&self) -> Self {
        Self {
            remotes: self.remotes.clone(),
            locals: self.locals.clone(),
            remote_map: self.remote_map.clone(),
            download_path: self.download_path.clone(),
            download_backend: self.download_backend.clone(),
            callback: self.callback.clone(),
        }
    }
}

/// same as pkgar_core::PublicKey
pub type RepoPublicKey = [u8; 32];

#[derive(Clone, Debug, Deserialize, Serialize)]

/// same as pkgar_keys::PublicKeyFile
pub struct RepoPublicKeyFile {
    #[serde(
        serialize_with = "hex::serialize",
        deserialize_with = "hex::deserialize"
    )]
    pub pkey: RepoPublicKey,
}

impl RepoPublicKeyFile {
    pub fn new(pubkey: RepoPublicKey) -> Self {
        Self { pkey: pubkey }
    }

    pub fn open(file: impl AsRef<Path>) -> Result<RepoPublicKeyFile, Error> {
        let file = file.as_ref();
        let content = fs::read_to_string(file).map_err(wrap_io_err!(file, "Reading"))?;
        toml::from_str(&content).map_err(|e| Error::TomlRead(e))
    }

    pub fn save(&self, file: impl AsRef<Path>) -> Result<(), Error> {
        let file = file.as_ref();
        fs::write(file, toml::to_string(&self).unwrap()).map_err(wrap_io_err!(file, "Writing"))
    }
}

#[derive(Clone, Debug)]
pub struct RemotePath {
    /// URL/Path to packages
    pub path: String,
    /// URL to public key
    pub pubpath: String,
    /// Unique ID
    pub name: RemoteName,
    /// Embedded public key, lazily loaded
    pub pubkey: Option<RepoPublicKey>,
}

impl RemotePath {
    pub fn is_local(&self) -> bool {
        self.pubpath.is_empty()
    }
}

const PUB_TOML: &str = "id_ed25519.pub.toml";

impl RepoManager {
    pub fn new(
        callback: Rc<RefCell<dyn Callback>>,
        download_backend: Box<dyn DownloadBackend>,
    ) -> Self {
        Self {
            remotes: Vec::new(),
            locals: Vec::new(),
            download_path: DOWNLOAD_DIR.into(),
            download_backend: Rc::new(download_backend),
            callback: callback,
            remote_map: BTreeMap::new(),
        }
    }

    /// override from default
    pub fn set_download_path(&mut self, path: PathBuf) {
        self.download_path = path;
    }

    /// override from existing callback
    pub fn set_callback(&mut self, callback: Rc<RefCell<dyn Callback>>) {
        self.callback = callback;
    }

    /// read [install_path]/etc/pkg.d with specified target. Will reset existing remotes / locals list.
    pub fn update_remotes(&mut self, target: &str, install_path: &Path) -> Result<(), Error> {
        self.remotes = Vec::new();
        self.locals = Vec::new();
        self.remote_map = BTreeMap::new();

        let repos_path = install_path.join(PACKAGES_REMOTE_DIR);
        let mut repo_files = Vec::new();
        for entry_res in
            fs::read_dir(&repos_path).map_err(wrap_io_err!(&repos_path, "Reading dir"))?
        {
            let entry = entry_res.map_err(wrap_io_err!(&repos_path, "Reading dir item"))?;
            let path = entry.path();
            if path.is_file() {
                repo_files.push(path);
            }
        }
        repo_files.sort();
        for repo_file in repo_files {
            let data =
                fs::read_to_string(&repo_file).map_err(wrap_io_err!(&repo_file, "Reading"))?;
            for line in data.lines() {
                if !line.starts_with('#') {
                    self.add_remote(line.trim(), target)?;
                }
            }
        }
        // optional local path
        let local_pub_path = install_path.join("pkg");
        let _ = self.add_local("installer_key", "", target, &local_pub_path);
        Ok(())
    }

    fn extract_host(path: &str) -> Option<&str> {
        path.split("://")
            .nth(1)?
            .split('/')
            .next()?
            .split(':')
            .next()
    }

    /// Add a remote target. The domain url will be used as a host (unique identifier).
    pub fn add_remote(&mut self, url: &str, target: &str) -> Result<(), Error> {
        let host = Self::extract_host(url)
            .ok_or_else(|| Error::RepoPathInvalid(url.into()))?
            .to_string();

        if self
            .remote_map
            .insert(
                host.clone(),
                RemotePath {
                    path: format!("{}/{}", url, target),
                    pubpath: format!("{}/{}", url, PUB_TOML),
                    name: host.clone(),
                    pubkey: None,
                },
            )
            .is_none()
        {
            self.remotes.push(host);
        };

        Ok(())
    }

    /// Add a local directory target. Specify a host as a unique identifier.
    pub fn add_local(
        &mut self,
        host: &str,
        path: &str,
        target: &str,
        pubkey_dir: &Path,
    ) -> Result<(), Error> {
        let pubkey_path = pubkey_dir.join(PUB_TOML);
        if !pubkey_path.is_file() {
            return Err(Error::RepoPathInvalid(
                pubkey_path.to_string_lossy().to_string(),
            ));
        }
        // load to check for failure early
        let pubkey = RepoPublicKeyFile::open(&pubkey_path).map_err(|e| {
            // probably corrupted
            let _ = fs::remove_file(&pubkey_path);
            e
        })?;
        if self
            .remote_map
            .insert(
                host.into(),
                RemotePath {
                    path: if path.is_empty() {
                        path.into()
                    } else {
                        format!("{}/{}", path, target)
                    },
                    // signifies local repository
                    pubpath: "".into(),
                    name: host.into(),
                    pubkey: Some(pubkey.pkey),
                },
            )
            .is_none()
        {
            self.locals.push(host.into());
        };
        Ok(())
    }

    /// Download a toml file. Wrapper to local_search() + download().
    fn sync_toml(&self, package_name: &PackageName) -> Result<(String, RemoteName), Error> {
        let file = format!("{package_name}.toml");
        if let Some((r, path)) = self.local_search(&file)? {
            let toml = fs::read_to_string(&path).map_err(wrap_io_err!(&path, "Reading"))?;
            return Ok((toml, r));
        }
        let mut writer = DownloadBackendWriter::ToBuf(Vec::new());
        match self.download(&file, None, &mut writer) {
            Ok(r) => {
                let text = writer.to_inner_buf();
                let toml = String::from_utf8(text)
                    .map_err(|_| Error::ContentIsNotValidUnicode(file.into()))?;
                Ok((toml, r))
            }
            Err(Error::ValidRepoNotFound) => {
                Err(PackageError::PackageNotFound(package_name.to_owned()).into())
            }
            Err(e) => Err(e),
        }
    }

    /// Download a pkgar file to specified path. Wrapper to local_search() + download().
    fn sync_pkgar(
        &self,
        package_name: &PackageName,
        len_hint: u64,
        dst_path: PathBuf,
    ) -> Result<(PathBuf, RemoteName), Error> {
        let file = format!("{package_name}.pkgar");
        if let Some((r, path)) = self.local_search(&file)? {
            return Ok((path, r));
        }
        let mut writer = DownloadBackendWriter::ToFile(
            create_file_nofollow(&dst_path).map_err(wrap_io_err!(&dst_path, "Creating"))?,
        );
        match self.download(&file, Some(len_hint), &mut writer) {
            Ok(r) => Ok((dst_path, r)),
            Err(Error::ValidRepoNotFound) => {
                Err(PackageError::PackageNotFound(package_name.to_owned()).into())
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_local_path(&self, remote: &RemoteName, file: &str, ext: &str) -> PathBuf {
        self.download_path.join(format!("{}_{file}.{ext}", remote))
    }

    /// Downloads all keys
    pub fn sync_keys(&mut self) -> Result<(), Error> {
        self.sync_keys_internal(false, false)
    }

    /// Downloads all keys forcibly
    pub fn force_sync_keys(&mut self) -> Result<(), Error> {
        self.sync_keys_internal(true, false)
    }

    /// Downloads all keys forcibly for testing
    pub fn test_sync_keys(&mut self) -> Result<(), Error> {
        self.sync_keys_internal(true, true)
    }

    fn sync_keys_internal(&mut self, force: bool, cleanup: bool) -> Result<(), Error> {
        let download_dir = self.download_path.clone();
        ensure_private_dir(&download_dir)?;
        for (_, remote) in self.remote_map.iter_mut() {
            if remote.pubkey.is_some() {
                continue;
            }
            // download key if not exists
            if force || remote.pubkey.is_none() {
                let local_keypath = download_dir.join(format!("pub_key_{}.toml", remote.name));
                if force || !local_keypath.exists() {
                    self.download_backend.download_to_file(
                        &remote.pubpath,
                        None,
                        &local_keypath,
                        self.callback.clone(),
                    )?;
                }
                let pubkey = RepoPublicKeyFile::open(&local_keypath).map_err(|e| {
                    // probably corrupted
                    let _ = fs::remove_file(&local_keypath);
                    e
                })?;
                if cleanup {
                    let _ = fs::remove_file(&local_keypath);
                }
                remote.pubkey = Some(pubkey.pkey);
            }
        }

        Ok(())
    }

    /// Download to dest and report which remotes it's downloaded from.
    pub fn download(
        &self,
        file: &str,
        len: Option<u64>,
        mut dest: &mut DownloadBackendWriter,
    ) -> Result<RemoteName, Error> {
        ensure_private_dir(&self.download_path)?;

        for rname in self.remotes.iter() {
            let Some(remote) = self.remote_map.get(rname) else {
                continue;
            };
            if remote.path == "" {
                // installer repository
                continue;
            }

            let remote_path = format!("{}/{}", remote.path, file);
            let res =
                self.download_backend
                    .download(&remote_path, len, &mut dest, self.callback.clone());
            match res {
                Ok(_) => return Ok(rname.into()),
                #[cfg(feature = "library")]
                Err(DownloadError::HttpStatus(_)) => continue,
                Err(e) => {
                    return Err(Error::Download(e));
                }
            };
        }

        Err(Error::ValidRepoNotFound)
    }

    /// Locate and return path and report which locals it's downloaded from.
    pub fn local_search(&self, file: &str) -> Result<Option<(RemoteName, PathBuf)>, Error> {
        ensure_private_dir(&self.download_path)?;

        for rname in self.locals.iter() {
            let Some(remote) = self.remote_map.get(rname) else {
                continue;
            };
            if remote.path == "" {
                // installer repository
                continue;
            }

            let remote_path = Path::new(&remote.path).join(file);
            match remote_path.metadata() {
                Ok(e) => {
                    if e.is_file() {
                        return Ok(Some((rname.into(), remote_path)));
                    } else {
                        continue;
                    }
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        continue;
                    } else {
                        return Err(Error::IO(err, remote_path, "Reading metadata"));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Download a pkgar file to the download path. Wrapper to sync_pkgar().
    pub fn get_package_pkgar(
        &self,
        package: &PackageName,
        len_hint: u64,
    ) -> Result<(PathBuf, &RemotePath), Error> {
        // A scratch name, not a shared one. The download lands here before the remote it came
        // from is known, and is then renamed to `<remote>_<package>.pkgar`. Naming it
        // `_<package>.pkgar` meant two concurrent fetches of the same package wrote the same
        // file and then both tried to rename it: the first won, the second failed with ENOENT on
        // a file it had just written. Nothing reads this name, so making it unique costs nothing.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let scratch = format!(
            ".{}.{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let local_path = self.get_local_path(&scratch, package.as_str(), "pkgar");
        let (local_path, remote) = self.sync_pkgar(&package, len_hint, local_path)?;
        if let Some(r) = self.remote_map.get(&remote) {
            if r.is_local() {
                return Ok((local_path, r));
            }
            let new_local_path = self.get_local_path(&r.name, package.as_str(), "pkgar");
            if new_local_path != local_path {
                fs::rename(&local_path, &new_local_path)
                    .map_err(wrap_io_err!(new_local_path, "Renaming"))?;
            }
            Ok((new_local_path, r))
        } else {
            // the pubkey cache is failing to download?
            Err(Error::RepoCacheNotFound(package.clone()))
        }
    }

    /// Fetch a toml file. Wrapper to sync_toml() with notifies fetch callback.
    pub fn get_package_toml(&self, package: &PackageName) -> Result<(String, RemoteName), Error> {
        self.callback.borrow_mut().fetch_package_name(&package);
        self.sync_toml(package)
    }

    /// Download an arbitrary file (e.g. `repo.toml.sig`) to a String, checking
    /// local repos first. Unlike `sync_toml` this does not append `.toml`.
    pub fn download_to_string(&self, file: &str) -> Result<(String, RemoteName), Error> {
        if let Some((r, path)) = self.local_search(file)? {
            let s = fs::read_to_string(&path).map_err(wrap_io_err!(&path, "Reading"))?;
            return Ok((s, r));
        }
        let mut writer = DownloadBackendWriter::ToBuf(Vec::new());
        let r = self.download(file, None, &mut writer)?;
        let s = String::from_utf8(writer.to_inner_buf())
            .map_err(|_| Error::ContentIsNotValidUnicode(file.into()))?;
        Ok((s, r))
    }

    /// Get remote info, if available
    pub fn get_remote_info(&self, remote: &RemoteName) -> Option<&RemotePath> {
        self.remote_map.get(remote)
    }
}

#[cfg(test)]
mod download_dir_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(&dir);
        dir
    }

    /// The hole itself: a symlink planted under the download directory turned a download into a
    /// write to whatever it pointed at, with the privileges of whoever ran `pkg`.
    #[test]
    fn a_planted_symlink_does_not_receive_the_download() {
        let dir = scratch("pkg_test_planted_symlink");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("outside");
        let link = dir.join("static.example.org_ncurses.pkgar");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = create_file_nofollow(&link).expect_err("a symlink must not be opened for writing");
        assert!(
            !target.exists(),
            "the link target was created, so the write followed the link: {err}"
        );
    }

    /// A directory anyone can write into is still plantable even when we own it, so the mode is
    /// repaired rather than trusted.
    #[test]
    fn a_world_writable_download_dir_is_tightened() {
        let dir = scratch("pkg_test_world_writable_dir");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

        ensure_private_dir(&dir).expect("a directory we own should be repaired, not rejected");

        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o022,
            0,
            "group/other write survived: mode is {:o}",
            mode
        );
    }

    /// A download path that is itself a symlink redirects every file we write, so it is refused
    /// outright instead of repaired -- we cannot know who controls the far end.
    #[test]
    fn a_symlinked_download_dir_is_refused() {
        let real = scratch("pkg_test_symlinked_dir_target");
        let link = scratch("pkg_test_symlinked_dir");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(
            ensure_private_dir(&link).is_err(),
            "a symlinked download path was accepted"
        );
        let _ = fs::remove_file(&link);
    }

    /// A directory we create must not be group/other writable in the first place.
    #[test]
    fn a_new_download_dir_is_private() {
        let dir = scratch("pkg_test_new_dir_private");
        ensure_private_dir(&dir).expect("creating a fresh download dir");
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "fresh dir is {:o}, expected 0700", mode);
    }
}
