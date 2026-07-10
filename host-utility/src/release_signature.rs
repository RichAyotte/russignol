//! Maintainer release-signature policy.
//!
//! The host verifies a detached Ed25519 signature over a release image's
//! SHA-256 before flashing, against a maintainer public key embedded in this
//! binary. The signing key stays offline; the public key is the trust anchor
//! and lives here — on the operator-trusted host, never on the SD card. The Pi
//! has no secure boot, so an on-device anchor would be attacker-mutable; only a
//! trusted host can establish authenticity.
//!
//! The sign/verify contract itself lives in `russignol-release-signature`, so
//! the signer (`xtask`) and this verifier cannot disagree on what was signed.
//! This module owns only the host-side policy: the embedded key, and whether an
//! unsigned image may proceed.

use russignol_release_signature::{SignatureError, verify};

/// The maintainer public key that signs releases.
pub const MAINTAINER_PUBKEY: Option<[u8; 32]> = Some([
    0x92, 0x4e, 0xa4, 0x05, 0x2e, 0x28, 0xf7, 0xdc, 0xc5, 0x97, 0xde, 0xb6, 0xc3, 0xfd, 0x37, 0x03,
    0xc7, 0x37, 0x70, 0x11, 0x89, 0x9c, 0xeb, 0xc3, 0x62, 0x93, 0xfa, 0x9f, 0x04, 0xd8, 0x12, 0x62,
]);

/// Why a release could not be accepted for flashing.
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseSignatureError {
    /// The image carried a signature that could not be verified.
    Signature(SignatureError),
    /// The image is unsigned and the operator did not allow unsigned flashing.
    UnsignedRefused,
}

impl std::fmt::Display for ReleaseSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signature(e) => e.fmt(f),
            Self::UnsignedRefused => f.write_str(
                "image is not maintainer-signed; re-run with --allow-unsigned to flash it anyway",
            ),
        }
    }
}

impl std::error::Error for ReleaseSignatureError {}

impl From<SignatureError> for ReleaseSignatureError {
    fn from(e: SignatureError) -> Self {
        Self::Signature(e)
    }
}

/// The trust decision for a flash, when the policy permits proceeding.
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureVerdict {
    /// A maintainer signature was verified against the embedded key.
    Verified,
    /// The build embeds no maintainer key; proceeding unverified.
    Unavailable,
    /// The image is unsigned but the operator allowed unsigned flashing.
    UnsignedAllowed,
}

/// Apply the flash-time signature policy, given the embedded maintainer key
/// (`None` when the build embeds none), the image hash, an optional detached
/// signature for the image, and whether the operator allowed unsigned images.
///
/// Returns the verdict to proceed under, or the reason to refuse.
///
/// # Errors
///
/// Returns [`ReleaseSignatureError::Signature`] if a present signature fails to
/// verify, or [`ReleaseSignatureError::UnsignedRefused`] if the image is
/// unsigned and `allow_unsigned` is false.
pub fn check_release_signature(
    maintainer_pubkey: Option<&[u8; 32]>,
    image_sha256_hex: &str,
    signature_hex: Option<&str>,
    allow_unsigned: bool,
) -> Result<SignatureVerdict, ReleaseSignatureError> {
    let Some(pubkey) = maintainer_pubkey else {
        return Ok(SignatureVerdict::Unavailable);
    };
    match signature_hex {
        Some(sig) => {
            verify(pubkey, image_sha256_hex, sig)?;
            Ok(SignatureVerdict::Verified)
        }
        None if allow_unsigned => Ok(SignatureVerdict::UnsignedAllowed),
        None => Err(ReleaseSignatureError::UnsignedRefused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_release_signature::{public_key, sign};

    /// A deterministic seed — a test fixture, never a production key.
    const DEV_SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn policy_no_key_is_unavailable() {
        let digest = hex::encode([0xab_u8; 32]);
        assert_eq!(
            check_release_signature(None, &digest, None, false),
            Ok(SignatureVerdict::Unavailable)
        );
    }

    #[test]
    fn policy_valid_signature_verifies() {
        let pk = public_key(&DEV_SEED);
        let digest = hex::encode([0xab_u8; 32]);
        let sig = sign(&DEV_SEED, &digest).unwrap();
        assert_eq!(
            check_release_signature(Some(&pk), &digest, Some(&sig), false),
            Ok(SignatureVerdict::Verified)
        );
    }

    #[test]
    fn policy_bad_signature_refuses() {
        let pk = public_key(&DEV_SEED);
        let digest = [0xab_u8; 32];
        let sig = sign(&DEV_SEED, &hex::encode(digest)).unwrap();
        let mut tampered = digest;
        tampered[0] ^= 0x01;
        assert_eq!(
            check_release_signature(Some(&pk), &hex::encode(tampered), Some(&sig), false),
            Err(ReleaseSignatureError::Signature(
                SignatureError::VerificationFailed
            ))
        );
    }

    #[test]
    fn policy_unsigned_refused_without_flag() {
        let pk = public_key(&DEV_SEED);
        let digest = hex::encode([0xab_u8; 32]);
        assert_eq!(
            check_release_signature(Some(&pk), &digest, None, false),
            Err(ReleaseSignatureError::UnsignedRefused)
        );
    }

    #[test]
    fn policy_unsigned_allowed_with_flag() {
        let pk = public_key(&DEV_SEED);
        let digest = hex::encode([0xab_u8; 32]);
        assert_eq!(
            check_release_signature(Some(&pk), &digest, None, true),
            Ok(SignatureVerdict::UnsignedAllowed)
        );
    }
}
