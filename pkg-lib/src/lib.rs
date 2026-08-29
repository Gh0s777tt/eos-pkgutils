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
// R-F21: public, because redox_installer has to read this database to decide which
// files a live install may copy. It previously guessed a legacy layout (`/pkg`) that no
// longer exists, and failed with ENOENT before copying anything.
pub const PACKAGES_TOML_PATH: &str = "etc/pkg/packages.toml";
const PACKAGES_REMOTE_DIR: &str = "etc/pkg.d";
// R-703/R-702: in-image-pinned public key for the repo.toml manifest signature.
#[cfg(feature = "library")]
const REPO_SIGN_PUBKEY_PATH: &str = "etc/pkg/eos-repo-sign.pub.toml";
/// V2-MS15: where the rollback watermark lives, relative to the install root.
///
/// A plain file, deliberately named next to the pinned key so the two are found together.
/// Root can delete it -- this is a limit of the mechanism, not a secret: it makes the ratchet
/// a defence against a network attacker, not against a local one.
const REPO_STATE_PATH: &str = "etc/pkg/repo-state.toml";
#[cfg(feature = "library")]
pub const PACKAGES_HEAD_DIR: &str = "var/lib/packages";
