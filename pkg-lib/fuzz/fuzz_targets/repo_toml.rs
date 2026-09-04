#![no_main]
//! Feed arbitrary text to the parser that reads a package index off a mirror.
//!
//! `repo.toml` is the trust anchor of the whole repository: it lists every package's blake3 hash,
//! and a signature over it authenticates the lot. A device fetches it from a host it does not
//! control, and `Repository::from_toml` runs on those bytes -- so this parser sees attacker-chosen
//! input on every update, before any of it has been shown to be genuine.
//!
//! WHICH LAYER GUARANTEES WHAT, because the first version of this target got it wrong. It asserted
//! that no key in the index could be an empty string, and libFuzzer produced one in seconds: TOML
//! permits `"" = "..."` and `Repository::from_toml` faithfully returns it. That is NOT a defect.
//! Validation lives in `PackageName::new`, which rejects an empty name, `/`, a NUL, more than one
//! `.` and a duplicate OS prefix -- and `Library::get_all_package_names` filters every index key
//! through it, discarding what fails. So an unusable key is inert: nothing builds a URL or a path
//! from it.
//!
//! The parser accepts what TOML permits and the name type is the gate. This target therefore
//! asserts what the code actually promises:
//!
//!   * parsing TERMINATES without panicking, on any input;
//!   * parsing is DETERMINISTIC, because the anti-rollback ratchet compares `serial` across two
//!     fetches and "the same index" has to be a fact about the bytes;
//!   * every key `PackageName::new` ACCEPTS is safe to use as a path component -- which is the
//!     boundary that matters, tested where it is actually drawn.
//!
//! A target that fires on correct behaviour is worse than no target: it teaches people to ignore
//! fuzz crashes.

use libfuzzer_sys::fuzz_target;
// The package is `redox-pkg`; its LIB TARGET is named `pkg` (pkg-lib/Cargo.toml `[lib]`),
// which is the name every caller uses -- the installer included.
use pkg::{PackageName, Repository};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return; // the real caller reads a String, so non-UTF-8 never reaches here
    };
    let Ok(repo) = Repository::from_toml(text) else {
        return; // refusing malformed input is the expected outcome, not a failure
    };

    let again = Repository::from_toml(text).expect("text that parsed once must parse again");
    assert_eq!(repo.serial, again.serial, "serial is not deterministic");
    assert_eq!(repo.expires, again.expires, "expires is not deterministic");
    assert_eq!(
        repo.packages.len(),
        again.packages.len(),
        "the package list is not deterministic"
    );

    for key in repo.packages.keys() {
        // The index may contain anything TOML allows. What must hold is that whatever survives
        // `PackageName::new` is safe to paste into a URL path -- `repo_manager.rs` builds one with
        // `format!("{}/{}", remote.path, file)`, so the name is a path component by construction.
        //
        // THIS IS THE CONTRACT THE CODE HAS, measured rather than assumed, because two earlier
        // versions of this target asserted a stricter one and reported correct behaviour as a
        // crash:
        //
        //     "."      ACCEPTED      "a.b"    ACCEPTED
        //     ".."     rejected      "a.b.c"  rejected      ""       rejected
        //     "a/b"    rejected      "a\0b"   rejected      "a:b"    rejected
        //
        // At most one `.` is the rule, which is what rejects `..` -- so there is no traversal, and
        // a bare `.` slips through as the degenerate case of a rule written for `name.target`.
        // That wart is recorded in the roadmap rather than asserted here: a target that fires on
        // behaviour the code intends teaches people to ignore fuzz crashes.
        if let Ok(name) = PackageName::new(key.clone()) {
            let s = name.as_str();
            assert!(!s.is_empty(), "an accepted package name is empty");
            assert!(!s.contains('/'), "an accepted package name has a separator: {s:?}");
            assert!(!s.contains('\0'), "an accepted package name has a NUL: {s:?}");
            assert!(s != "..", "an accepted package name traverses upward: {s:?}");
            assert!(
                s.chars().filter(|c| *c == '.').count() <= 1,
                "an accepted package name has more than one dot: {s:?}"
            );
        }
    }
});
