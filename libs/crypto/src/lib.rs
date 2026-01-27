//! Shared encryption utilities for Russignol secret keys
//!
//! Provides PIN-based encryption using:
//! - **scrypt** for key derivation (hardened parameters for brute-force resistance)
//! - **AES-256-GCM** for authenticated encryption
//!
//! # File Format
//! ```text
//! [salt_len:1][salt:variable][nonce:12][ciphertext:variable]
//! ```
//!
//! # Security Properties
//! - 256 MB memory-hard key derivation (safe for 512 MB device)
//! - ~8-10 seconds derivation time on Raspberry Pi Zero 2W
//! - Authenticated encryption prevents tampering

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use log::debug;
use scrypt::password_hash::SaltString;
use std::io::{self, Write};

/// Path to encrypted secret keys file
pub const SECRET_KEYS_ENC_PATH: &str = "/keys/secret_keys.enc";

/// Hardened scrypt parameters: `log_n=18`, r=8, p=4 (256 MB, ~8s on `RPi` Zero 2W @ 1.3 GHz)
/// - `log_n=18` provides 256 MB memory-hardness (safe for 512 MB device)
/// - p=4 quadruples CPU work without increasing memory
#[must_use]
pub fn scrypt_params() -> scrypt::Params {
    scrypt::Params::new(18, 8, 4, 32).expect("valid scrypt params")
}

/// Derive a 32-byte encryption key from password and salt using scrypt
pub fn derive_key(password: &[u8], salt: &SaltString) -> io::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let params = scrypt_params();

    debug!("Deriving key using scrypt (log_n=18, r=8, p=4, 256 MB memory)...");
    let start = std::time::Instant::now();

    scrypt::scrypt(password, salt.as_str().as_bytes(), &params, &mut key)
        .map_err(|e| io::Error::other(format!("Scrypt key derivation failed: {e}")))?;

    debug!("Key derived in {:?}", start.elapsed());
    Ok(key)
}

/// Encrypt secret keys JSON, returning the encrypted blob
///
/// Returns bytes in format: `[salt_len:1][salt:variable][nonce:12][ciphertext:variable]`
pub fn encrypt(password: &[u8], plaintext: &str) -> io::Result<Vec<u8>> {
    debug!("Encrypting data...");

    // Generate salt and derive key
    let salt = SaltString::generate(&mut OsRng);
    let key = derive_key(password, &salt)?;

    // Encrypt with AES-256-GCM
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

    // Pack into file format: [salt_len][salt][nonce][ciphertext]
    let mut output = Vec::new();
    let salt_bytes = salt.as_str().as_bytes();
    // Salt strings are base64-encoded and always fit in a u8 (max ~22 bytes)
    let salt_len = u8::try_from(salt_bytes.len())
        .map_err(|_| io::Error::other("Salt length exceeds 255 bytes"))?;
    output.write_all(&[salt_len])?;
    output.write_all(salt_bytes)?;
    output.write_all(nonce.as_ref())?;
    output.write_all(&ciphertext)?;

    debug!("Encryption complete: {} bytes", output.len());
    Ok(output)
}

/// Decrypt secret keys from encrypted blob
///
/// Expects bytes in format: `[salt_len:1][salt:variable][nonce:12][ciphertext:variable]`
pub fn decrypt(password: &[u8], encrypted: &[u8]) -> io::Result<String> {
    debug!("Decrypting data ({} bytes)...", encrypted.len());

    // Parse salt length
    if encrypted.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Encrypted data is empty",
        ));
    }
    let salt_len = encrypted[0] as usize;
    let mut offset = 1;

    // Parse salt
    if encrypted.len() < offset + salt_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Encrypted data too short for salt",
        ));
    }
    let salt_bytes = &encrypted[offset..offset + salt_len];
    let salt_str = std::str::from_utf8(salt_bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Salt is not valid UTF-8: {e}"),
        )
    })?;
    let salt = SaltString::from_b64(salt_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to decode salt: {e}"),
        )
    })?;
    offset += salt_len;

    // Parse nonce (12 bytes for AES-GCM)
    if encrypted.len() < offset + 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Encrypted data too short for nonce",
        ));
    }
    let nonce = Nonce::from_slice(&encrypted[offset..offset + 12]);
    offset += 12;

    // Remaining bytes are ciphertext
    let ciphertext = &encrypted[offset..];
    debug!(
        "Parsed: salt={} bytes, ciphertext={} bytes",
        salt_len,
        ciphertext.len()
    );

    // Derive key
    let key = derive_key(password, &salt)?;

    // Decrypt with AES-256-GCM
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

    String::from_utf8(plaintext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Decrypted data is not valid UTF-8: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = b"123456";
        let plaintext = r#"{"consensus": "edsk..."}"#;

        let encrypted = encrypt(password, plaintext).unwrap();
        let decrypted = decrypt(password, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let plaintext = "secret data";
        let encrypted = encrypt(b"correct", plaintext).unwrap();
        let result = decrypt(b"wrong", &encrypted);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong PIN"));
    }

    #[test]
    fn test_scrypt_timing() {
        let salt = SaltString::generate(&mut OsRng);
        let start = std::time::Instant::now();
        let _ = derive_key(b"123456", &salt).unwrap();
        let elapsed = start.elapsed();

        // Should complete within 60s even on slow hardware
        assert!(
            elapsed < Duration::from_secs(60),
            "Scrypt took too long: {elapsed:?}"
        );
        println!("Scrypt completed in {elapsed:?}");
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let password = b"test_pin";
        let salt = SaltString::generate(&mut OsRng);

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
        let result = decrypt(b"password", &[22]); // salt_len=22 but no salt data
        assert!(result.is_err());
    }
}
