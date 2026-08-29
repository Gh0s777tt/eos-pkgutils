#[cfg(feature = "library")]
pub mod pkgar_backend;

use std::{io, path::PathBuf};
use thiserror::Error;

use crate::{net_backend::DownloadError, package::PackageError, PackageName};
#[cfg(feature = "library")]
use crate::{package::RemotePackage, PackageState, RemoteName, RemotePath, Repository};

// todo: make this better
#[derive(Error, Debug)]
pub enum Error {
    #[error("Please add repos")]
    ValidRepoNotFound,
    #[error("Repository path is not valid: {0:?}")]
    RepoPathInvalid(String),
    #[error("Repository recursed infinitely with: {0:?}")]
    RepoRecursion(Vec<PackageName>),
    #[error("Cached package {0:?} source repo is not found")]
    RepoCacheNotFound(PackageName),
    #[error("Public key for {0:?} is not available")]
    RepoNotLoaded(String),
    #[error("Package {0:?} not found")]
    PackageNotFound(PackageName),
    #[error("Package {0:?} not installed")]
    PackageNotInstalled(PackageName),
    #[error("Package {0:?} name invalid")]
    PackageNameInvalid(String),
    #[error("{0}")]
    Package(#[from] PackageError),
    #[error("Path {0:?} isn't a Valid Unicode String")]
    PathIsNotValidUnicode(String),
    #[error("Content of {0:?} is not a valid UTF-8 content")]
    ContentIsNotValidUnicode(String),
    #[error("You don't have permissions required for this action, try performing it as root")]
    MissingPermissions,
    #[error("Cancelled by user")]
    Interrupted,

    #[error("Package {0:?} is protected")]
    ProtectedPackage(PackageName),

    #[error("IO error: {0}, {2} {1:?}")]
    IO(io::Error, PathBuf, &'static str),
    #[error("Download error: {0}")]
    Download(#[from] DownloadError),
    #[error("Download error: {0}")]
    TomlRead(#[from] toml::de::Error),
    #[error(
        "repo.toml manifest is unsigned but a manifest key is pinned (R-703); refusing to trust it"
    )]
    RepoManifestUnsigned,
    #[error("repo.toml manifest signature invalid: {0}")]
    RepoManifestSigInvalid(&'static str),
    /// V2-MS15: the index is older than one this machine has already accepted.
    #[error(
        "repo.toml is a rollback: serial {got} is below the {seen} this machine has already \
         accepted. A correctly signed OLD index is still a valid signature, so refusing it is \
         the only thing that stops a replay."
    )]
    RepoManifestRollback { got: u64, seen: u64 },
    /// V2-MS15: the index passed its expiry -- a host may be freezing updates.
    #[error(
        "repo.toml expired at {expires} (now {now}). A host that keeps serving the newest \
         signed index forever cannot be caught by the serial alone, because its serial equals \
         the watermark."
    )]
    RepoManifestExpired { expires: u64, now: u64 },
    // R-V2-MS13: the two errors that make the pinned manifest key guard *content*.
    // They sit next to the R-703 pair on purpose -- same trust anchor, same failure family.
    #[error(
        "package {package:?} does not match the signed repo manifest (R-V2-MS13): \
         manifest says blake3 {expected:?}, downloaded pkgar has {actual:?}"
    )]
    ManifestHashMismatch {
        package: PackageName,
        expected: String,
        actual: String,
    },
    #[error(
        "package {0:?} is not listed in the signed repo manifest (R-V2-MS13); refusing to install it"
    )]
    PackageNotInManifest(PackageName),
    #[cfg(feature = "library")]
    #[error("pkgar error: {0}")]
    Pkgar(Box<pkgar::Error>),
}

#[cfg(feature = "library")]
impl From<pkgar::Error> for Error {
    fn from(value: pkgar::Error) -> Self {
        Error::Pkgar(Box::new(value))
    }
}

macro_rules! wrap_io_err {
    ($path:expr, $context:expr) => {
        |source| {
            if source.kind() == std::io::ErrorKind::PermissionDenied {
                Error::MissingPermissions
            } else {
                Error::IO(source, $path.to_path_buf(), $context)
            }
        }
    };
}

pub(crate) use wrap_io_err;

#[cfg(feature = "library")]
pub trait Backend {
    /// individually install a package
    fn install(&mut self, package: RemotePackage) -> Result<(), Error>;
    /// individually uninstall a package
    fn uninstall(&mut self, package: PackageName) -> Result<(), Error>;
    /// individually upgrade a package
    fn upgrade(&mut self, package: &RemotePackage) -> Result<(), Error>;
    /// download package TOML data
    fn get_package_detail(&self, package: &PackageName) -> Result<RemotePackage, Error>;
    /// get remote repository detail
    fn get_remote_detail(&self, package: &RemoteName) -> Result<RemotePath, Error>;
    /// download repo TOML data
    fn get_repository_detail(&self) -> Result<Repository, Error>;
    /// get state of current installation
    fn get_package_state(&self) -> PackageState;
    /// check if there's pending transaction conflicts before committing
    fn commit_check_conflict(&self) -> Result<&Vec<pkgar::TransactionConflict>, Error>;
    /// commit all pending changes, and set state of current installation
    fn commit_state(&mut self, new_state: PackageState) -> Result<usize, Error>;
    /// abort all pending changes
    fn abort_state(&mut self) -> Result<usize, Error>;
}
