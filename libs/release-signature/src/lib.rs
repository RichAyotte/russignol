//! Maintainer release-signature contract.
//!
//! A detached Ed25519 signature over a release image's SHA-256 lets the host
//! verify a card's authenticity before flashing. The signed payload is the raw
//! 32-byte digest, so `sign` and `verify` share one `message` helper and cannot
//! disagree on what the signature covers. `host-utility` links only `verify`
//! (its `MAINTAINER_PUBKEY` is the trust anchor); `xtask` links `sign`,
//! `public_key`, and `generate_seed`. The signing seed never reaches the device.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// SHA-256 digest length in bytes — the signed payload is the raw digest.
const DIGEST_LEN: usize = 32;

/// Ed25519 seed length in bytes.
const SEED_LEN: usize = 32;

/// Why a release signature could not be produced or accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// The image hash was not a 32-byte hex SHA-256.
    MalformedDigest,
    /// The signature was not 64 valid bytes of hex.
    MalformedSignature,
    /// The public key was not a valid Ed25519 point.
    MalformedKey,
    /// The signature did not verify against the key and image hash.
    VerificationFailed,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::MalformedDigest => "image hash is not a valid 32-byte SHA-256",
            Self::MalformedSignature => "release signature is not valid 64-byte hex",
            Self::MalformedKey => "maintainer public key is invalid",
            Self::VerificationFailed => {
                "release signature does not match the image — do not flash this image"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SignatureError {}

/// The raw signed payload for `image_sha256_hex`: its 32 decoded digest bytes.
/// Both `sign` and `verify` route through this, so they cannot disagree on what
/// the signature covers.
fn message(image_sha256_hex: &str) -> Result<[u8; DIGEST_LEN], SignatureError> {
    let digest = hex::decode(image_sha256_hex).map_err(|_| SignatureError::MalformedDigest)?;
    digest
        .try_into()
        .map_err(|_| SignatureError::MalformedDigest)
}

/// The detached-signature sidecar path for `image`: the image path with
/// `.sig` appended to its full file name. Signing writes the sidecar here and
/// the flash-time verifier looks for it here, so the naming recipe has a
/// single home.
#[must_use]
pub fn sidecar_path(image: &Path) -> PathBuf {
    let mut sidecar = image.as_os_str().to_os_string();
    sidecar.push(".sig");
    PathBuf::from(sidecar)
}

/// Generate a fresh signing seed from the OS CSPRNG.
///
/// # Errors
///
/// Returns an error if the OS random source is unavailable.
pub fn generate_seed() -> Result<Zeroizing<[u8; SEED_LEN]>, getrandom::Error> {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    getrandom::fill(seed.as_mut())?;
    Ok(seed)
}

/// The Ed25519 public key for `seed`, deterministic from the seed.
#[must_use]
pub fn public_key(seed: &[u8; SEED_LEN]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign the raw digest bytes of `image_sha256_hex` with `seed`, returning the
/// detached signature as hex. Verifiable by `verify` under `public_key(seed)`.
///
/// # Errors
///
/// Returns [`SignatureError::MalformedDigest`] if `image_sha256_hex` is not a
/// 32-byte hex SHA-256.
pub fn sign(seed: &[u8; SEED_LEN], image_sha256_hex: &str) -> Result<String, SignatureError> {
    let digest = message(image_sha256_hex)?;
    let signing_key = SigningKey::from_bytes(seed);
    Ok(hex::encode(signing_key.sign(&digest).to_bytes()))
}

/// Verify detached `signature_hex` over the raw bytes of `image_sha256_hex`
/// against `pubkey`. A valid signature binds the maintainer to that exact image
/// content, since the SHA-256 uniquely identifies it.
///
/// # Errors
///
/// Returns a [`SignatureError`] if the digest, signature, or key is malformed,
/// or [`SignatureError::VerificationFailed`] if the signature does not match.
pub fn verify(
    pubkey: &[u8; 32],
    image_sha256_hex: &str,
    signature_hex: &str,
) -> Result<(), SignatureError> {
    let digest = message(image_sha256_hex)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| SignatureError::MalformedSignature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| SignatureError::MalformedSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(pubkey).map_err(|_| SignatureError::MalformedKey)?;
    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic seed — a test fixture, never a production key.
    const DEV_SEED: [u8; 32] = [7u8; 32];

    // --- sidecar naming ---

    /// `.sig` is appended to the whole name — `with_extension` semantics
    /// (replacing `.xz`) would break the sign/verify rendezvous.
    #[test]
    fn sidecar_path_appends_sig_to_the_full_name() {
        assert_eq!(
            sidecar_path(Path::new("/tmp/dir/foo.img.xz")),
            Path::new("/tmp/dir/foo.img.xz.sig")
        );
    }

    #[test]
    fn sidecar_path_works_on_a_bare_filename() {
        assert_eq!(
            sidecar_path(Path::new("image.img")),
            Path::new("image.img.sig")
        );
    }

    // --- keygen ---

    #[test]
    fn public_key_matches_independent_implementation() {
        // Expected value cross-checked against OpenSSL's Ed25519 derivation for
        // this seed, so the test anchors correctness to a second implementation
        // rather than to our own output.
        let seed: [u8; 32] =
            hex::decode("9d61b19deffa4a0eca66b56a6d76ec8dc55ffe0f6c6f8be82bff56cf5e3e6f2c")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            hex::encode(public_key(&seed)),
            "685104cd6fc5b6fc78132deba1b30e9437c4936f5e1af9bfb7e373e582949d0b"
        );
    }

    #[test]
    fn public_key_is_deterministic_and_seed_dependent() {
        assert_eq!(public_key(&DEV_SEED), public_key(&DEV_SEED));
        assert_ne!(public_key(&DEV_SEED), public_key(&[9u8; 32]));
    }

    #[test]
    fn generate_seed_produces_distinct_seeds() {
        let a = generate_seed().unwrap();
        let b = generate_seed().unwrap();
        assert_ne!(*a, *b);
    }

    // --- sign then verify ---

    #[test]
    fn sign_then_verify_roundtrips() {
        let pk = public_key(&DEV_SEED);
        let digest_hex = hex::encode([0xab_u8; 32]);
        let sig = sign(&DEV_SEED, &digest_hex).unwrap();
        assert_eq!(verify(&pk, &digest_hex, &sig), Ok(()));
    }

    #[test]
    fn sign_rejects_tampered_digest() {
        let pk = public_key(&DEV_SEED);
        let digest = [0xab_u8; 32];
        let sig = sign(&DEV_SEED, &hex::encode(digest)).unwrap();
        let mut tampered = digest;
        tampered[0] ^= 0x01;
        assert_eq!(
            verify(&pk, &hex::encode(tampered), &sig),
            Err(SignatureError::VerificationFailed)
        );
    }

    #[test]
    fn sign_rejects_wrong_key() {
        let digest_hex = hex::encode([0xab_u8; 32]);
        let sig = sign(&DEV_SEED, &digest_hex).unwrap();
        let other = public_key(&[9u8; 32]);
        assert_eq!(
            verify(&other, &digest_hex, &sig),
            Err(SignatureError::VerificationFailed)
        );
    }

    // --- verify malformed-input handling ---

    #[test]
    fn verify_rejects_malformed_signature() {
        let pk = public_key(&DEV_SEED);
        let digest_hex = hex::encode([0xab_u8; 32]);
        assert_eq!(
            verify(&pk, &digest_hex, "not-hex"),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn verify_rejects_short_signature() {
        let pk = public_key(&DEV_SEED);
        let digest_hex = hex::encode([0xab_u8; 32]);
        assert_eq!(
            verify(&pk, &digest_hex, "00ff"),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn verify_rejects_malformed_digest() {
        let pk = public_key(&DEV_SEED);
        let sig_hex = "0".repeat(128);
        assert_eq!(
            verify(&pk, "xyz", &sig_hex),
            Err(SignatureError::MalformedDigest)
        );
    }
}
