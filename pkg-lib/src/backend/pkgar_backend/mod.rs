use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

use pkgar::{MergedTransaction, PackageFile, Transaction};
use pkgar_core::{PackageSrc, PublicKey};

use super::{Backend, Error};
use crate::{
    backend::wrap_io_err,
    callback::Callback,
    package::{RemotePackage, Repository},
    package_state::PackageState,
    repo_manager::RepoManager,
    Package, PackageName, RemoteName, RemotePath, RepoPublicKeyFile, REPO_STATE_PATH,
};

/// Package backend using pkgar
pub struct PkgarBackend {
    /// Root path, usually "/"
    install_path: PathBuf,
    /// Things in "/etc/pkg/package.toml"
    packages: PackageState,
    /// Things in "/etc/pkg.d" and inet
    repo_manager: RepoManager,
    /// temporary commit
    commits: Option<MergedTransaction>,
    keys_synced: bool,
    callback: Rc<RefCell<dyn Callback>>,
    /// R-V2-MS13: the signature-verified `repo.toml`, fetched at most once per process.
    /// Outer `None` = not loaded yet; `Some(None)` = no manifest key is pinned, so the
    /// R-703 legacy/dev behaviour (warn, do not enforce) applies and we must not keep
    /// re-reading the key file for every package.
    verified_index: RefCell<Option<Option<Repository>>>,
}

impl PkgarBackend {
    pub fn new(install_path: PathBuf, repo_manager: RepoManager) -> Result<Self, Error> {
        let packages = PackageState::from_sysroot(&install_path)?;

        // TODO: Use File::lock. This only checks permission
        packages
            .to_sysroot(&install_path)
            .map_err(wrap_io_err!(&install_path, "Writing"))?;

        let dir = install_path.join(crate::PACKAGES_HEAD_DIR);
        fs::create_dir_all(&dir).map_err(wrap_io_err!(&dir, "Creating dir"))?;

        let callback = repo_manager.callback.clone();

        Ok(PkgarBackend {
            install_path,
            packages,
            repo_manager,
            // packages_lock,
            commits: Some(MergedTransaction::new()),
            keys_synced: false,
            callback,
            verified_index: RefCell::new(None),
        })
    }

    fn add_transaction(&mut self, transaction: Transaction, src: Option<&PackageFile>) {
        let mut commits = self
            .commits
            .take()
            .unwrap_or_else(|| MergedTransaction::new());
        commits.merge(transaction, src);
        self.commits = Some(commits);
    }

    // reads /var/lib/packages/[package].pkgar_head
    fn get_package_head(&self, package: &PackageName) -> Result<PackageFile, Error> {
        let path = self
            .install_path
            .join(crate::PACKAGES_HEAD_DIR)
            .join(format!("{package}.pkgar_head"));

        let Some(pkg) = self.packages.installed.get(package) else {
            return Err(Error::PackageNotInstalled(package.clone()));
        };
        let Some(remote) = self.packages.pubkeys.get(&pkg.remote) else {
            return Err(Error::RepoCacheNotFound(package.clone()));
        };

        let pkg = PackageFile::new(&path, &remote.pkey).map_err(Error::from)?;

        Ok(pkg)
    }

    /// R-703: verify `repo.toml`'s hybrid signature (ed25519 layer) against the
    /// in-image-pinned key. If no key is pinned (legacy/dev repo) we proceed with
    /// a loud warning — per-package pkgar ed25519 signatures are still enforced —
    /// but once a key is pinned a missing/invalid signature is a hard failure.
    fn verify_repo_manifest(&self, manifest: &[u8]) -> Result<(), Error> {
        let pinned = match self.pinned_manifest_key() {
            Some(k) => k,
            None => {
                let key_path = self.install_path.join(crate::REPO_SIGN_PUBKEY_PATH);
                eprintln!(
                    "pkg: WARNING — no pinned repo-manifest key at {}; repo.toml is NOT signature-verified (R-703).",
                    key_path.display()
                );
                return Ok(());
            }
        };
        let (sig_toml, _) = self
            .repo_manager
            .download_to_string("repo.toml.sig")
            .map_err(|_| Error::RepoManifestUnsigned)?;
        crate::manifest_sig::verify_manifest_ed25519(&pinned, manifest, &sig_toml)
            .map_err(Error::RepoManifestSigInvalid)
    }

    /// R-703/R-V2-MS13: the in-image-pinned ed25519 manifest key, if the image ships one.
    /// `None` means "legacy/dev repo": nothing pins the index, so nothing downstream of it
    /// can be enforced either. Single source of truth for both callers.
    fn pinned_manifest_key(&self) -> Option<[u8; 32]> {
        let key_path = self.install_path.join(crate::REPO_SIGN_PUBKEY_PATH);
        fs::read_to_string(&key_path)
            .ok()
            .and_then(|s| crate::manifest_sig::load_pinned_ed25519(&s))
    }

    /// R-V2-MS13: refuse any `.pkgar` whose pkgar header hash is not the one the
    /// signature-verified `repo.toml` names for this package.
    ///
    /// This is the step that was missing: R-703 authenticated the *index* with the pinned
    /// key, but nothing ever compared that index against the bytes being installed, so the
    /// only thing standing between a compromised package host and arbitrary code was the
    /// pkgar key -- which the client downloads from that same host (`repo_manager.rs`
    /// `PUB_TOML` / `sync_keys_internal`). Comparing one 32-byte value covers the whole
    /// payload: `header.blake3` is the blake3 of the entry table, `Header::entries()`
    /// re-hashes the entry table against it, and `Transaction` hashes every extracted file
    /// against its `Entry::blake3`.
    ///
    /// Takes the already-open `PackageFile` rather than re-reading the path, so the header
    /// checked here comes from the same file descriptor `Transaction` then extracts from.
    fn enforce_manifest_blake3(
        &self,
        package: &PackageName,
        pkg: &PackageFile,
    ) -> Result<(), Error> {
        if self.verified_index.borrow().is_none() {
            // V2-MS14: a source with no remotes is exempt, and this is not a hole -- it is the
            // difference between shipping this and breaking every image build. With `remotes`
            // empty, RepoManager::download() never reaches the network: every byte comes from
            // a local directory the operator chose, so there is no attacker in the path for a
            // signature to exclude. Concretely, redox_installer installs from cookbook/repo
            // and writes the pinned key into the new sysroot BEFORE install_packages, while
            // repo.toml.sig is only produced later, at publish time. Without this branch the
            // pinned key would be present, the signature absent, and the build would die on
            // RepoManifestUnsigned.
            //
            // get_repository_detail() is what runs verify_repo_manifest(); with no pinned
            // key it would return an unauthenticated index, and enforcing hashes out of an
            // unauthenticated index buys nothing -- so keep the R-703 behaviour instead.
            let loaded = if index_enforcement_applies(
                self.pinned_manifest_key().is_some(),
                !self.repo_manager.remotes.is_empty(),
            ) {
                Some(Backend::get_repository_detail(self)?)
            } else {
                None
            };
            *self.verified_index.borrow_mut() = Some(loaded);
        }

        let cache = self.verified_index.borrow();
        let Some(Some(index)) = cache.as_ref() else {
            return Ok(());
        };
        check_against_index(index, package, pkg.header().blake3)
    }

    /// V2-MS15: (watermark, now). Both degrade to 0 rather than to a guess.
    ///
    /// The watermark lives in a plain file, which a root user can delete -- this is not a TPM
    /// counter and must not be described as one. It does not make things worse than they were
    /// (root already substitutes the pinned key), but it is the reason this is rollback
    /// *detection* for a network attacker, not for a local one.
    fn freshness_state(&self) -> (u64, u64) {
        let mark = fs::read_to_string(self.install_path.join(REPO_STATE_PATH))
            .ok()
            .and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("serial = ")?.trim().parse::<u64>().ok())
            })
            .unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (mark, now)
    }

    /// V2-MS15: advance the watermark. Never lowers it -- that is the whole point.
    fn record_manifest_serial(&self, serial: u64) {
        let (mark, _) = self.freshness_state();
        if serial <= mark {
            return;
        }
        let path = self.install_path.join(REPO_STATE_PATH);
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        // Best effort: a read-only sysroot must not stop an install, it just means the
        // machine keeps the watermark it already had.
        let _ = fs::write(&path, format!("serial = {serial}\n"));
    }

    fn remove_package_head(&mut self, package: &PackageName) -> Result<(), Error> {
        let path = self
            .install_path
            .join(crate::PACKAGES_HEAD_DIR)
            .join(format!("{package}.pkgar_head"));

        fs::remove_file(&path).map_err(wrap_io_err!(&path, "Removing file"))?;
        Ok(())
    }

    fn create_head(
        &self,
        archive_path: &Path,
        package: &PackageName,
        pubkey: &PublicKey,
    ) -> Result<(), Error> {
        // creates a head file
        let head_path = self
            .install_path
            .join(crate::PACKAGES_HEAD_DIR)
            .join(format!("{package}.pkgar_head"));

        let mut package = PackageFile::new(archive_path, &pubkey)?;
        package.split(&head_path, None::<&Path>)?;

        Ok(())
    }

    fn sync_keys(&mut self) -> Result<(), Error> {
        if self.keys_synced {
            return Ok(());
        }

        for (name, map) in &mut self.repo_manager.remote_map {
            if map.pubkey.is_none() {
                if let Some(pubk) = self.packages.pubkeys.get(name) {
                    map.pubkey = Some(pubk.pkey)
                }
            }
        }

        self.repo_manager.sync_keys()?;

        self.keys_synced = true;
        Ok(())
    }
}

/// The pinned public key for a remote, or a typed error saying which remote lacks one.
///
/// R-F06: the two call sites below used to unwrap this Option directly. `pubkey` is None
/// whenever a remote's key has not been loaded -- an ordinary, reachable state, not a bug --
/// so installing or upgrading from such a remote PANICKED the package manager instead of
/// reporting the problem. Anyone able to get a keyless remote into /etc/pkg.d could stop the
/// machine installing or upgrading anything: a denial of service out of a missing file.
///
/// Error::RepoNotLoaded already exists for exactly this ("Public key for {0:?} is not
/// available") and sync_keys() already returns it, so this reports the same failure in the
/// same words instead of inventing a second vocabulary for it.
fn require_pubkey(repo: &RemotePath) -> Result<&crate::repo_manager::RepoPublicKey, Error> {
    repo.pubkey
        .as_ref()
        .ok_or_else(|| Error::RepoNotLoaded(repo.name.to_string()))
}

/// R-V2-MS13: compare one package's pkgar header hash with the entry that the
/// signature-verified `repo.toml` carries for it.
///
/// Split out of `enforce_manifest_blake3` so the decision itself is testable without a
/// signed repository, a network, or a real `.pkgar` on disk.
///
/// Fails closed on a package the manifest does not list: `repo.toml` is generated *from*
/// the repo directory (`src/bin/repo_builder.rs`), so a downloadable `.pkgar` with no
/// manifest entry means the index and the payload directory disagree -- exactly the state
/// an attacker who can add files to the host would produce.
/// V2-MS15: is this index fresh enough to act on?
///
/// The signature says "we published this"; it does not say "this is current". Two distinct
/// attacks live in that gap and each needs its own field, which is why one is not enough:
///
///   * ROLLBACK -- serve an older, still correctly signed index so a machine reinstalls a
///     version with a known hole. Caught by `serial`: the client keeps a watermark and never
///     goes backwards.
///   * FREEZE -- serve the newest signed index forever so security fixes never arrive. The
///     serial equals the watermark, so the ratchet sees nothing wrong. Caught by `expires`.
///
/// `now == 0` means the caller has no trustworthy clock. Then the expiry half is deliberately
/// skipped rather than guessed at: on a machine without an RTC every index would look expired
/// and the package manager would refuse to work at all. The ratchet still applies, so this
/// degrades to rollback-only protection instead of to nothing -- and the caller says so aloud.
fn check_manifest_freshness(
    serial: u64,
    expires: u64,
    watermark: u64,
    now: u64,
) -> Result<(), Error> {
    if serial < watermark {
        return Err(Error::RepoManifestRollback {
            got: serial,
            seen: watermark,
        });
    }
    if expires != 0 && now != 0 && now > expires {
        return Err(Error::RepoManifestExpired { expires, now });
    }
    Ok(())
}

/// V2-MS14: should the signed index be enforced for this source?
///
/// Two conditions, and the second one is what keeps image builds alive. With no pinned key
/// there is nothing to authenticate the index against, so enforcing hashes out of an
/// unauthenticated index buys nothing (R-703 behaviour, unchanged). With no remotes,
/// `RepoManager::download()` never reaches the network -- every byte comes from a local
/// directory the operator chose, so there is no attacker in the path for a signature to
/// exclude. That second case is exactly an image build: redox_installer writes the pinned key
/// into the new sysroot BEFORE install_packages, while `repo.toml.sig` is only produced later,
/// at publish time. Without the exemption the key would be present, the signature absent, and
/// every build would die on RepoManifestUnsigned.
fn index_enforcement_applies(has_pinned_key: bool, has_remotes: bool) -> bool {
    has_pinned_key && has_remotes
}

fn check_against_index(
    index: &Repository,
    package: &PackageName,
    header_blake3: [u8; 32],
) -> Result<(), Error> {
    let Some(expected) = index.packages.get(package.as_str()) else {
        return Err(Error::PackageNotInManifest(package.clone()));
    };
    // Producer side is `blake3::Hash::to_hex()` (lowercase) in cook/package.rs; compare
    // case-insensitively anyway so a hand-edited manifest cannot fail for cosmetics.
    let actual = hex::encode(header_blake3);
    if expected.eq_ignore_ascii_case(&actual) {
        Ok(())
    } else {
        Err(Error::ManifestHashMismatch {
            package: package.clone(),
            expected: expected.clone(),
            actual,
        })
    }
}

impl Backend for PkgarBackend {
    fn install(&mut self, package: RemotePackage) -> Result<(), Error> {
        self.sync_keys()?;
        if package.package.version.is_empty() {
            return Ok(()); // metapackage
        }
        // TODO: Actually use that specific remote
        let (local_path, repo) = self
            .repo_manager
            .get_package_pkgar(&package.package.name, package.package.network_size)?;
        // R-F06: both of these used to unwrap the Option directly. `pubkey` is
        // Option<RepoPublicKey> and is None whenever a remote's key has not been loaded --
        // an ordinary, reachable state, not a bug -- so installing from such a remote
        // PANICKED the package manager instead of reporting the problem. Anyone able to get
        // a keyless remote into /etc/pkg.d could therefore stop the machine installing or
        // upgrading anything: a denial of service out of a missing file.
        //
        // Error::RepoNotLoaded already exists for exactly this ("Public key for {0:?} is not
        // available") and sync_keys() below already returns it, so this reports the same
        // failure in the same words rather than inventing a second vocabulary for it.
        let pubkey = require_pubkey(&repo)?;
        let mut pkg = PackageFile::new(&local_path, pubkey)?;
        // R-V2-MS13: bind these bytes to the pinned manifest key before anything is
        // extracted. Metapackages never reach this line -- they return above on an empty
        // version -- which is deliberate: they have no .pkgar, and repo.toml carries their
        // `version` string in the hash column (repo_builder.rs falls back to `version`
        // when a package toml has no `blake3`), so hashing them is meaningless.
        self.enforce_manifest_blake3(&package.package.name, &pkg)?;
        self.callback.borrow_mut().install_extract(&package);
        let install = Transaction::install(&mut pkg, &self.install_path)?;
        self.create_head(&local_path, &package.package.name, pubkey)?;
        self.add_transaction(install, Some(&pkg));
        Ok(())
    }

    fn uninstall(&mut self, package: PackageName) -> Result<(), Error> {
        if self.packages.protected.contains(&package) {
            return Err(Error::ProtectedPackage(package));
        }
        self.sync_keys()?;

        let mut pkg = self.get_package_head(&package)?;
        let remove = Transaction::remove(&mut pkg, &self.install_path)?;
        self.add_transaction(remove, Some(&pkg));

        self.remove_package_head(&package)?;

        Ok(())
    }

    fn upgrade(&mut self, package: &RemotePackage) -> Result<(), Error> {
        self.sync_keys()?;

        let name = &package.package.name;
        let mut pkg = self.get_package_head(name)?;
        let (local_path, repo) = self
            .repo_manager
            .get_package_pkgar(name, package.package.network_size)?;
        // R-F06: same as install() above -- a missing remote key gets reported, not
        // panicked on. Upgrade is the worse place to abort: it can leave the machine on the
        // old version with nothing said about why the new one never arrived.
        let pubkey = require_pubkey(&repo)?;
        let mut pkg2 = PackageFile::new(&local_path, pubkey)?;
        // R-V2-MS13: same gate as install(), on the replacement bytes.
        self.enforce_manifest_blake3(name, &pkg2)?;
        let update = Transaction::replace(&mut pkg, &mut pkg2, &self.install_path)?;
        self.create_head(&local_path, &name, pubkey)?;
        self.add_transaction(update, Some(&pkg));
        Ok(())
    }

    fn get_package_detail(&self, package: &PackageName) -> Result<RemotePackage, Error> {
        let (toml, remote) = self.repo_manager.get_package_toml(package)?;
        Ok(RemotePackage {
            package: Package::from_toml(&toml)?,
            remote,
        })
    }

    fn get_remote_detail(&self, package: &RemoteName) -> Result<RemotePath, Error> {
        self.repo_manager
            .get_remote_info(package)
            .map(|e| e.to_owned())
            .ok_or(Error::ValidRepoNotFound)
    }

    /// TODO: Multiple repository support
    fn get_repository_detail(&self) -> Result<Repository, Error> {
        let repo_str = PackageName::new("repo".to_string())?;
        let (toml, _) = self.repo_manager.get_package_toml(&repo_str)?;
        // R-703: authenticate the package index before trusting it.
        self.verify_repo_manifest(toml.as_bytes())?;
        let repo = Repository::from_toml(&toml)?;
        // V2-MS15: the signature proves origin, not currency. Check freshness here, where the
        // index has just been authenticated -- doing it later would mean trusting a parse of
        // bytes nobody vouched for.
        let (watermark, now) = self.freshness_state();
        check_manifest_freshness(repo.serial, repo.expires, watermark, now)?;
        self.record_manifest_serial(repo.serial);
        Ok(repo)
    }

    fn get_package_state(&self) -> PackageState {
        self.packages.clone()
    }

    fn commit_check_conflict(&self) -> Result<&Vec<pkgar::TransactionConflict>, Error> {
        let transaction = self
            .commits
            .as_ref()
            .ok_or_else(|| Error::Pkgar(Box::new(pkgar::Error::DataNotInitialized)))?;
        Ok(transaction.get_possible_conflicts())
    }

    fn commit_state(&mut self, new_state: PackageState) -> Result<usize, Error> {
        let mut transaction = self
            .commits
            .take()
            .ok_or_else(|| Error::Pkgar(Box::new(pkgar::Error::DataNotInitialized)))?
            .into_transaction();
        self.callback
            .borrow_mut()
            .commit_start(transaction.pending_commit());
        while transaction.pending_commit() > 0 {
            self.callback.borrow_mut().commit_increment(&transaction);
            if let Err(e) = transaction.commit_one() {
                self.add_transaction(transaction, None);
                return Err(Error::from(e));
            }
        }
        self.callback.borrow_mut().commit_end();

        self.packages = new_state;
        for (k, v) in &self.repo_manager.remote_map {
            let Some(pubkey) = v.pubkey else {
                return Err(Error::RepoNotLoaded(k.to_string()));
            };
            let pk = RepoPublicKeyFile::new(pubkey);
            self.packages.pubkeys.insert(k.to_string(), pk);
        }
        self.packages
            .to_sysroot(&self.install_path)
            .map_err(wrap_io_err!(&self.install_path, "Writing"))?;
        Ok(transaction.total_committed())
    }

    fn abort_state(&mut self) -> Result<usize, Error> {
        let mut transaction = self
            .commits
            .take()
            .ok_or_else(|| Error::Pkgar(Box::new(pkgar::Error::DataNotInitialized)))?
            .into_transaction();
        self.callback
            .borrow_mut()
            .abort_start(transaction.pending_commit());
        while transaction.pending_commit() > 0 {
            self.callback.borrow_mut().commit_increment(&transaction);
            if let Err(e) = transaction.abort_one() {
                self.add_transaction(transaction, None);
                return Err(Error::from(e));
            }
        }
        self.callback.borrow_mut().abort_end();
        Ok(transaction.total_committed())
    }
}


#[cfg(test)]
mod rf06_tests {
    use super::*;

    use crate::repo_manager::RepoPublicKey;

    fn remote(pubkey: Option<RepoPublicKey>) -> RemotePath {
        RemotePath {
            path: "https://example.invalid/pkg".to_string(),
            pubpath: "https://example.invalid/key".to_string(),
            name: "test-remote".to_string(),
            pubkey,
        }
    }

    /// The regression itself: a remote with no loaded key must produce an error naming that
    /// remote, NOT a panic. Before R-F06 this path unwrapped the None and aborted the
    /// process, which turned a missing key file into a denial of service.
    #[test]
    fn missing_pubkey_is_an_error_naming_the_remote() {
        let err = require_pubkey(&remote(None)).expect_err("a keyless remote must not succeed");
        match err {
            Error::RepoNotLoaded(name) => assert_eq!(name, "test-remote"),
            other => panic!("expected RepoNotLoaded, got {other:?}"),
        }
    }

    /// Proves the check is not simply always-failing: with a key present it returns that key.
    /// A test that cannot pass is as useless as one that cannot fail.
    #[test]
    fn present_pubkey_is_returned() {
        let r = remote(Some([7u8; 32]));
        assert!(require_pubkey(&r).is_ok(), "a remote with a key must succeed");
    }
}


#[cfg(test)]
mod v2ms13_tests {
    use super::*;

    use std::collections::BTreeMap;

    fn index(entries: &[(&str, &str)]) -> Repository {
        Repository {
            build_id: "deadbeef".into(),
            packages: entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<String, String>>(),
            ..Default::default()
        }
    }

    fn name(s: &str) -> PackageName {
        PackageName::new(s).unwrap()
    }

    /// The regression: bytes whose pkgar header hash is not the one the signed manifest
    /// names must be refused. Before V2-MS13 nothing compared these two values at all.
    #[test]
    fn substituted_payload_is_rejected() {
        let want = [0x11u8; 32];
        let idx = index(&[("base", &hex::encode(want))]);
        let err = check_against_index(&idx, &name("base"), [0x22u8; 32])
            .expect_err("a pkgar the manifest does not vouch for must not install");
        match err {
            Error::ManifestHashMismatch {
                package,
                expected,
                actual,
            } => {
                assert_eq!(package.as_str(), "base");
                assert_eq!(expected, hex::encode(want));
                assert_eq!(actual, hex::encode([0x22u8; 32]));
            }
            other => panic!("expected ManifestHashMismatch, got {other:?}"),
        }
    }

    /// A test that cannot pass is as useless as one that cannot fail: the genuine package
    /// must still install, and an uppercase manifest entry is not a security event.
    #[test]
    fn matching_payload_is_accepted() {
        let want = [0x11u8; 32];
        let idx = index(&[("base", &hex::encode(want).to_uppercase())]);
        assert!(check_against_index(&idx, &name("base"), want).is_ok());
    }

    /// V2-MS14: the exemption that keeps image builds alive must itself be pinned down,
    /// or someone will delete it as a redundant condition and break every build.
    #[test]
    fn index_is_enforced_only_for_a_pinned_key_and_a_real_remote() {
        assert!(
            index_enforcement_applies(true, true),
            "a pinned key plus a network remote is the case this milestone exists for"
        );
        assert!(
            !index_enforcement_applies(true, false),
            "an image build has the pinned key but no remotes and no repo.toml.sig yet; \
             enforcing here would fail every build on RepoManifestUnsigned"
        );
        assert!(
            !index_enforcement_applies(false, true),
            "with no pinned key the index is unauthenticated, so enforcing its hashes \
             would assert nothing (R-703 behaviour, deliberately unchanged)"
        );
        assert!(!index_enforcement_applies(false, false));
    }

    /// V2-MS15: a correctly signed OLD index must be refused. The signature cannot tell
    /// "ours" from "ours, from last month" -- only the watermark can.
    #[test]
    fn rollback_to_an_older_signed_index_is_refused() {
        match check_manifest_freshness(4, 0, 7, 1_000)
            .expect_err("an index below the watermark is a replay, however well signed")
        {
            Error::RepoManifestRollback { got, seen } => {
                assert_eq!((got, seen), (4, 7));
            }
            other => panic!("expected RepoManifestRollback, got {other:?}"),
        }
    }

    /// The freeze case the counter cannot see: serial equals the watermark, so only the
    /// expiry catches a host that serves the newest signed index forever.
    #[test]
    fn frozen_index_at_the_watermark_is_caught_by_expiry() {
        match check_manifest_freshness(7, 500, 7, 1_000)
            .expect_err("an expired index must not be acted on")
        {
            Error::RepoManifestExpired { expires, now } => {
                assert_eq!((expires, now), (500, 1_000));
            }
            other => panic!("expected RepoManifestExpired, got {other:?}"),
        }
    }

    /// A gate that only ever refuses is not a gate: the current index must pass, and moving
    /// the serial forward must be allowed.
    #[test]
    fn current_index_passes_and_may_advance() {
        assert!(check_manifest_freshness(7, 2_000, 7, 1_000).is_ok());
        assert!(check_manifest_freshness(8, 2_000, 7, 1_000).is_ok());
    }

    /// No usable clock means rollback-only protection, not a package manager that refuses to
    /// work. Degrading to half the protection beats degrading to none -- or to a brick.
    #[test]
    fn without_a_clock_expiry_is_skipped_but_the_ratchet_holds() {
        assert!(
            check_manifest_freshness(7, 500, 7, 0).is_ok(),
            "now == 0 means no trustworthy clock; every index would look expired"
        );
        assert!(
            check_manifest_freshness(3, 500, 7, 0).is_err(),
            "the ratchet does not depend on a clock and must still refuse a rollback"
        );
    }

    /// Backward compatibility: an index published before V2-MS15 has no fields at all, which
    /// serde renders as zeros. It must keep working against a fresh machine.
    #[test]
    fn pre_v2ms15_index_without_fields_still_installs() {
        assert!(check_manifest_freshness(0, 0, 0, 1_000).is_ok());
    }

    /// Fail closed, not open, on a package the signed index does not list.
    #[test]
    fn unlisted_package_is_rejected() {
        let idx = index(&[("base", &hex::encode([0x11u8; 32]))]);
        match check_against_index(&idx, &name("evil"), [0x11u8; 32])
            .expect_err("an unlisted package must not install")
        {
            Error::PackageNotInManifest(p) => assert_eq!(p.as_str(), "evil"),
            other => panic!("expected PackageNotInManifest, got {other:?}"),
        }
    }

    /// repo_builder.rs writes the package `version` into the hash column when a package
    /// toml has no `blake3` (metapackages). Such an entry can never match a real header
    /// hash, which is why install() must keep returning early for metapackages.
    #[test]
    fn non_hash_manifest_entry_never_matches() {
        let idx = index(&[("dev-essentials", "TODO")]);
        assert!(check_against_index(&idx, &name("dev-essentials"), [0u8; 32]).is_err());
    }
}
