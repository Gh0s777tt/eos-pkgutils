pub mod backend;
pub mod callback;
#[cfg(feature = "library")]
pub use library::Library;
#[cfg(feature = "library")]
pub use library_builder::LibraryBuilder;
pub mod net_backend;
pub use package::*;
pub use package_state::*;
pub use repo_manager::*;

#[cfg(feature = "library")]
mod library;
#[cfg(feature = "library")]
mod library_builder;
mod package;
mod package_state;
mod repo_manager;

#[cfg(feature = "library")]
mod sorensen;

#[cfg(feature = "library")]
mod manifest_sig;

const DOWNLOAD_DIR: &str = "/tmp/pkg_download/";
const PACKAGES_TOML_PATH: &str = "etc/pkg/packages.toml";
const PACKAGES_REMOTE_DIR: &str = "etc/pkg.d";
// R-703/R-702: in-image-pinned public key for the repo.toml manifest signature.
#[cfg(feature = "library")]
const REPO_SIGN_PUBKEY_PATH: &str = "etc/pkg/eos-repo-sign.pub.toml";
#[cfg(feature = "library")]
const PACKAGES_HEAD_DIR: &str = "var/lib/packages";
