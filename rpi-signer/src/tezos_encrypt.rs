//! Encryption utilities for Tezos signer secret keys
//!
//! This module handles both encryption (during first-boot setup) and
//! decryption (during normal operation) of secret keys.
//! Core encryption logic is in russignol-crypto; this module provides
//! file I/O for the signer process.

use log::info;
use std::fs;
use std::io;
use std::path::Path;

// Re-export for convenience
pub use russignol_crypto::SECRET_KEYS_ENC_PATH;

// Keys partition paths
pub const KEYS_MOUNT: &str = "/keys";

/// Decrypt secret keys from /`keys/secret_keys.enc`
///
/// Returns the decrypted JSON string containing secret keys
pub fn decrypt_secret_keys(password: &[u8]) -> io::Result<String> {
    let encrypted = fs::read(SECRET_KEYS_ENC_PATH).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to read encrypted secret keys {SECRET_KEYS_ENC_PATH}: {e}"),
        )
    })?;

    russignol_crypto::decrypt(password, &encrypted)
}

/// Encrypt secret keys JSON and write to /`keys/secret_keys.enc`
pub fn encrypt_secret_keys(password: &[u8], secret_keys_json: &str) -> io::Result<()> {
    let encrypted = russignol_crypto::encrypt(password, secret_keys_json)?;
    fs::write(SECRET_KEYS_ENC_PATH, encrypted)?;
    info!("Encrypted secret keys written to {SECRET_KEYS_ENC_PATH}");
    Ok(())
}

/// Set proper permissions and ownership on key files
///
/// During first boot, files are created as root. This function:
/// 1. Changes ownership to russignol (so files are readable after privilege drop)
/// 2. Sets mode 400 (read-only by owner)
pub fn set_key_permissions() -> io::Result<()> {
    use log::warn;
    use std::os::unix::fs::PermissionsExt;

    // russignol user UID/GID (from /etc/passwd)
    const RUSSIGNOL_UID: u32 = 1000;
    const RUSSIGNOL_GID: u32 = 1000;

    let key_files = [
        Path::new(SECRET_KEYS_ENC_PATH),
        &Path::new(KEYS_MOUNT).join("public_keys"),
        &Path::new(KEYS_MOUNT).join("public_key_hashs"),
        &Path::new(KEYS_MOUNT).join("chain_info.json"),
    ];

    for path in key_files {
        if path.exists() {
            // Set ownership to russignol user (required for reading after privilege drop)
            let result = unsafe {
                let c_path = std::ffi::CString::new(path.to_str().unwrap_or("")).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid path: {e}"))
                })?;
                libc::chown(c_path.as_ptr(), RUSSIGNOL_UID, RUSSIGNOL_GID)
            };
            if result != 0 {
                warn!(
                    "Failed to chown {}: {}",
                    path.display(),
                    io::Error::last_os_error()
                );
            } else {
                info!("Set {} owner to russignol", path.display());
            }

            // Set mode 400 (read-only by owner)
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o400);
            fs::set_permissions(path, perms)?;
            info!("Set {} to mode 400 (read-only)", path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Core encryption tests are in russignol-crypto.
    // This module only provides file I/O wrapper, so no additional tests needed.
}
