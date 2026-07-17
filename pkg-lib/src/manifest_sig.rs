//! E-OS R-703 — verify the package-repo manifest (`repo.toml`) signature.
//!
//! `repo.toml` lists every package's blake3 hash, so a signature over it
//! authenticates the whole index and blocks rollback / freeze / substitution
//! of the package set (individual `.pkgar` files are already ed25519-signed).
//!
//! The signature is the hybrid ed25519 + ML-DSA-65 produced by
//! `tools/eos-repo-sign`. On-device we verify the **ed25519** layer against an
//! **in-image-pinned** public key (`--classical-only` semantics); ML-DSA
//! verification stays host-side until it is viable on the Redox target. Reusing
//! the pinned key — not one fetched next to the repo — is what closes the TOFU
//! gap (R-702).

use ed25519_dalek::{Signature, VerifyingKey};

/// Extract `key = "<hex>"` from a flat eos-repo-sign `.sig` / `.pub.toml` file
/// (TOML section headers and comments are ignored).
fn field_hex(text: &str, key: &str) -> Option<Vec<u8>> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return hex_decode(v.trim().trim_matches('"'));
            }
        }
    }
    None
}

/// Panic-free hex decode over bytes (never slices a multi-byte char).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.trim().as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nib(b[i])? << 4) | nib(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Load the pinned ed25519 manifest-signing public key (32 bytes) from the
/// `eos-repo-sign.pub.toml` shipped in the image. `None` means no manifest key
/// is pinned (legacy/dev repo) — the caller then proceeds unverified with a warning.
pub fn load_pinned_ed25519(pub_toml: &str) -> Option<[u8; 32]> {
    field_hex(pub_toml, "ed25519")?.try_into().ok()
}

/// Verify the ed25519 layer of `repo.toml.sig` over the raw `repo.toml` bytes
/// against the pinned key. Uses `verify_strict` (rejects non-canonical sigs).
pub fn verify_manifest_ed25519(
    pinned: &[u8; 32],
    manifest: &[u8],
    sig_toml: &str,
) -> Result<(), &'static str> {
    let vk = VerifyingKey::from_bytes(pinned)
        .map_err(|_| "pinned manifest key is not a valid ed25519 key")?;
    let sig_bytes: [u8; 64] = field_hex(sig_toml, "ed25519")
        .ok_or("repo.toml.sig has no ed25519 field")?
        .try_into()
        .map_err(|_| "repo.toml.sig ed25519 is not 64 bytes")?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(manifest, &sig)
        .map_err(|_| "repo.toml signature does not match the pinned key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_sig_toml(sk: &SigningKey, msg: &[u8]) -> String {
        let sig = sk.sign(msg);
        let hexsig: String = sig
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        format!(
            "# hybrid signature\n[hybrid_signature]\nversion = 1\ned25519 = \"{hexsig}\"\nml_dsa_65 = \"00\"\n"
        )
    }

    #[test]
    fn accepts_valid_rejects_tampered() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pinned = sk.verifying_key().to_bytes();
        let manifest = b"build_id = \"x\"\n[packages]\nbase = \"blake3:ab\"\n";
        let sig = make_sig_toml(&sk, manifest);

        // valid manifest + valid sig + correct pinned key -> OK
        assert!(verify_manifest_ed25519(&pinned, manifest, &sig).is_ok());
        // tampered manifest -> rejected
        assert!(verify_manifest_ed25519(&pinned, b"tampered index", &sig).is_err());
        // wrong pinned key -> rejected
        let other = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(verify_manifest_ed25519(&other, manifest, &sig).is_err());
        // malformed / missing sig -> rejected
        assert!(verify_manifest_ed25519(&pinned, manifest, "no ed25519 here").is_err());
        assert!(verify_manifest_ed25519(&pinned, manifest, "ed25519 = \"zz\"").is_err());
    }

    #[test]
    fn load_pinned_parses_pubkey() {
        let toml = format!(
            "[public_keys]\ned25519 = \"{}\"\nml_dsa_65 = \"ff\"\n",
            "ab".repeat(32)
        );
        assert_eq!(load_pinned_ed25519(&toml), Some([0xab_u8; 32]));
        assert_eq!(load_pinned_ed25519("garbage = 1"), None);
        // wrong length ed25519 -> None
        assert_eq!(load_pinned_ed25519("ed25519 = \"abab\""), None);
    }
}
