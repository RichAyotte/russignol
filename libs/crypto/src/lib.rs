//! Shared encryption utilities for Russignol secret keys
//!
//! Provides PIN-based encryption using:
//! - **scrypt** for key derivation (hardened parameters for brute-force resistance)
//! - **AES-256-GCM** for authenticated encryption
//!
//! # File Format
//!
//! Encrypted blobs carry a 1-byte version tag as their first byte. Two layouts
//! are recognized:
//!
//! ```text
//! v2 (current write target):
//!   [version=0x02 : 1][salt : 16 raw bytes][nonce : 12][ciphertext : variable]
//!
//! v1 (legacy, decrypt-only):
//!   [salt_len=22 : 1][salt : 22 b64-ASCII bytes][nonce : 12][ciphertext : variable]
//! ```
//!
//! Dispatch is by the first byte: `0x02` selects v2, `22` (`0x16`) selects v1,
//! anything else is rejected. v1 always starts with `22` because the legacy
//! writer used `password-hash`'s `SaltString::generate`, which produces 16
//! random bytes encoded to a fixed 22-character base64 string and then stored
//! those 22 ASCII bytes as the salt. This makes `0x02` an unambiguous v2
//! discriminator and reserves `0x03..=0xFF` (excluding `0x16`) for future
//! formats.
//!
//! v1 stays decryptable because devices already in the field hold blobs whose
//! KDF input is the 22-byte b64-ASCII slice; any change to that input derives
//! a different key for the same PIN. v2 fixes the layout (raw 16-byte salts)
//! so the crate no longer depends on `password-hash`.
//!
//! # Security Properties
//! - 256 MB memory-hard key derivation (safe for 512 MB device)
//! - ~8-10 seconds derivation time on Raspberry Pi Zero 2W
//! - Authenticated encryption prevents tampering

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng, rand_core::RngCore},
};
use log::debug;
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

/// Path to a v1-format encrypted secret keys file. New devices never write
/// here; the path remains canonical for legacy blobs that pre-date the v2
/// layout and for any blob mid-migration to v2.
pub const SECRET_KEYS_ENC_PATH: &str = "/keys/secret_keys.enc";

/// Path to a v2-format encrypted secret keys file. Fresh setups write here
/// directly; a v1→v2 migration writes here after re-encryption (or moves the
/// blob here unchanged when the v1-named file is already v2 format).
pub const SECRET_KEYS_ENC_V2_PATH: &str = "/keys/secret_keys.enc.v2";

/// v2 blob version byte. v1 is implicit through `LEGACY_SALT_LEN`.
const FORMAT_V2: u8 = 0x02;

/// First byte of every legacy v1 blob: the b64-encoded length of a 16-byte
/// salt is invariably 22.
const LEGACY_SALT_LEN: u8 = 22;

/// Raw salt size used by v2.
const V2_SALT_LEN: usize = 16;

/// AES-GCM nonce size in bytes.
const NONCE_LEN: usize = 12;

/// Identifies which on-disk layout a blob used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobFormat {
    V1Legacy,
    V2,
}

/// Hardened scrypt parameters: `log_n=18`, r=8, p=4 (256 MB, ~8s on `RPi` Zero 2W @ 1.3 GHz)
/// - `log_n=18` provides 256 MB memory-hardness (safe for 512 MB device)
/// - p=4 quadruples CPU work without increasing memory
///
/// # Panics
///
/// Cannot panic: scrypt parameters are hardcoded valid constants.
#[must_use]
pub fn scrypt_params() -> scrypt::Params {
    scrypt::Params::new(18, 8, 4).expect("valid scrypt params")
}

/// Derive a 32-byte encryption key from a password and an opaque salt slice.
///
/// Both v1 and v2 funnel through this single call: v1 hands in the 22-byte
/// b64-ASCII slice the legacy writer persisted, v2 hands in the 16 raw bytes.
/// `scrypt::scrypt` does not interpret the salt, so feeding it the bytes the
/// writer stored verbatim keeps key derivation byte-identical to the writer's.
///
/// # Errors
///
/// Returns an error if scrypt key derivation fails.
pub fn derive_key(password: &[u8], salt: &[u8]) -> io::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let params = scrypt_params();

    debug!("Deriving key using scrypt (log_n=18, r=8, p=4, 256 MB memory)...");
    let start = std::time::Instant::now();

    scrypt::scrypt(password, salt, &params, &mut key)
        .map_err(|e| io::Error::other(format!("Scrypt key derivation failed: {e}")))?;

    debug!("Key derived in {:?}", start.elapsed());
    Ok(key)
}

/// Encrypt secret keys JSON, returning a v2 encrypted blob.
///
/// Output bytes: `[0x02 : 1][salt : 16 raw bytes][nonce : 12][ciphertext : variable]`.
///
/// # Errors
///
/// Returns an error if key derivation, AES-GCM initialization, or encryption fails.
pub fn encrypt(password: &[u8], plaintext: &str) -> io::Result<Vec<u8>> {
    debug!("Encrypting data...");

    let mut salt = [0u8; V2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;

    debug!("Encrypting with AES-256-GCM");
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("AES-GCM initialization failed: {e}"),
        )
    })?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Encryption failed: {e}"),
        )
    })?;

    let mut output = Vec::with_capacity(1 + V2_SALT_LEN + NONCE_LEN + ciphertext.len());
    output.write_all(&[FORMAT_V2])?;
    output.write_all(&salt)?;
    output.write_all(nonce.as_ref())?;
    output.write_all(&ciphertext)?;

    debug!("Encryption complete: {} bytes", output.len());
    Ok(output)
}

/// Decrypt a blob and report which layout produced it.
///
/// Callers that need to act on the format (e.g. stage a v2 rewrite when they
/// see a v1) consume the returned `BlobFormat`. Callers that just want the
/// plaintext can use `decrypt`, which discards it.
///
/// # Errors
///
/// Returns an error if the version byte is unknown, the data is malformed,
/// the salt slice is the wrong size, key derivation fails, or AES-GCM
/// authentication fails (e.g., wrong PIN).
pub fn decrypt_with_format(
    password: &[u8],
    encrypted: &[u8],
) -> io::Result<(Zeroizing<String>, BlobFormat)> {
    debug!("Decrypting data ({} bytes)...", encrypted.len());

    let Some(&version_byte) = encrypted.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Encrypted data is empty",
        ));
    };

    let (salt, format, after_salt) = match version_byte {
        LEGACY_SALT_LEN => {
            let salt_end = 1 + LEGACY_SALT_LEN as usize;
            if encrypted.len() < salt_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Encrypted data too short for legacy salt",
                ));
            }
            (
                &encrypted[1..salt_end],
                BlobFormat::V1Legacy,
                &encrypted[salt_end..],
            )
        }
        FORMAT_V2 => {
            let salt_end = 1 + V2_SALT_LEN;
            if encrypted.len() < salt_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Encrypted data too short for v2 salt",
                ));
            }
            (
                &encrypted[1..salt_end],
                BlobFormat::V2,
                &encrypted[salt_end..],
            )
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown format version",
            ));
        }
    };

    if after_salt.len() < NONCE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Encrypted data too short for nonce",
        ));
    }
    let nonce = Nonce::from_slice(&after_salt[..NONCE_LEN]);
    let ciphertext = &after_salt[NONCE_LEN..];
    debug!(
        "Parsed: format={format:?}, salt={} bytes, ciphertext={} bytes",
        salt.len(),
        ciphertext.len()
    );

    let key = derive_key(password, salt)?;

    debug!("Decrypting with AES-256-GCM");
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("AES-GCM initialization failed: {e}"),
        )
    })?;

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Decryption failed (wrong PIN?): {e}"),
        )
    })?;

    // UTF-8 validation may reject the bytes; if it does, zeroize the rejected
    // buffer before returning so plaintext never drops through a non-zeroizing
    // path.
    let plaintext = String::from_utf8(plaintext).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Decrypted data is not valid UTF-8",
        )
    })?;

    Ok((Zeroizing::new(plaintext), format))
}

/// Decrypt a blob and return only the plaintext.
///
/// Thin wrapper around `decrypt_with_format` for callers that don't care which
/// layout produced the blob.
///
/// # Errors
///
/// Same conditions as `decrypt_with_format`.
pub fn decrypt(password: &[u8], encrypted: &[u8]) -> io::Result<Zeroizing<String>> {
    decrypt_with_format(password, encrypted).map(|(plaintext, _)| plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const FIXTURE_PIN: &[u8] = b"123456";
    const FIXTURE_PLAINTEXT: &str = r#"{"consensus":"edsk_fixture"}"#;
    const LEGACY_V1_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/legacy_v1.bin");

    #[test]
    fn test_decrypt_legacy_fixture() {
        let plaintext = decrypt(FIXTURE_PIN, LEGACY_V1_FIXTURE).unwrap();
        assert_eq!(plaintext.as_str(), FIXTURE_PLAINTEXT);
    }

    #[test]
    fn test_legacy_fixture_wrong_pin_fails() {
        let result = decrypt(b"wrong-pin", LEGACY_V1_FIXTURE);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong PIN"));
    }

    #[test]
    fn test_decrypt_with_format_returns_v1_for_fixture() {
        let (_, format) = decrypt_with_format(FIXTURE_PIN, LEGACY_V1_FIXTURE).unwrap();
        assert_eq!(format, BlobFormat::V1Legacy);
    }

    #[test]
    fn test_decrypt_with_format_returns_v2_for_fresh_blob() {
        let pin = b"123456";
        let plaintext = "secret";
        let bytes = encrypt(pin, plaintext).unwrap();
        let (_, format) = decrypt_with_format(pin, &bytes).unwrap();
        assert_eq!(format, BlobFormat::V2);
    }

    #[test]
    fn test_v2_roundtrip() {
        let pin = b"123456";
        let plaintext = r#"{"consensus": "edsk..."}"#;
        let bytes = encrypt(pin, plaintext).unwrap();
        assert_eq!(decrypt(pin, &bytes).unwrap().as_str(), plaintext);
    }

    #[test]
    fn test_v2_format_invariants() {
        let plaintext = "hello";
        let bytes = encrypt(b"pin", plaintext).unwrap();
        assert_eq!(bytes[0], FORMAT_V2);
        assert_eq!(
            bytes.len(),
            1 + V2_SALT_LEN + NONCE_LEN + plaintext.len() + 16,
            "v2 blob length must be header + ciphertext + 16-byte GCM tag"
        );
    }

    #[test]
    fn test_v2_wrong_pin_fails() {
        let bytes = encrypt(b"correct", "secret data").unwrap();
        let result = decrypt(b"wrong", &bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong PIN"));
    }

    #[test]
    fn test_unknown_version_byte_fails() {
        let mut blob = vec![0xFF];
        blob.extend(std::iter::repeat_n(0u8, 64));
        let err = decrypt(b"any", &blob).unwrap_err();
        assert!(err.to_string().contains("unknown format version"));
    }

    #[test]
    fn test_truncated_v2_data_error() {
        let result = decrypt(b"any", &[FORMAT_V2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_scrypt_timing() {
        let salt = [0u8; V2_SALT_LEN];
        let start = std::time::Instant::now();
        let _ = derive_key(b"123456", &salt).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_mins(1),
            "Scrypt took too long: {elapsed:?}"
        );
        println!("Scrypt completed in {elapsed:?}");
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let password = b"test_pin";
        let salt = [7u8; V2_SALT_LEN];

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2, "Same password+salt must produce same key");
    }

    #[test]
    fn test_empty_data_error() {
        let result = decrypt(b"password", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data_error() {
        let result = decrypt(b"password", &[LEGACY_SALT_LEN]);
        assert!(result.is_err());
    }

    /// Compile-time guarantee that decrypted plaintext zeros its backing
    /// storage on drop. If a future change drops the `Zeroizing` wrapper
    /// from the return type, this assertion fails to compile.
    const _: fn() = || {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Zeroizing<String>>();
    };
}
