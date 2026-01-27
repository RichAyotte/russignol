//! Wallet management for loading and saving keys from disk in OCaml-compatible format.
//
// Corresponds to the file management logic originally in `main.rs`.

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::UnencryptedSigner;

// OCaml-compatible format structures
#[derive(Debug, Serialize, Deserialize)]
/// Key entry in OCaml format
pub struct OcamlKeyEntry<T> {
    /// Key name/alias
    pub name: String,
    /// Key value
    pub value: T,
}

#[derive(Debug, Serialize, Deserialize)]
/// Public key value in OCaml format
pub struct OcamlPublicKeyValue {
    /// Key locator (e.g., "unencrypted:...")
    pub locator: String,
    /// Base58-encoded public key
    pub key: String,
}

// Internal representation of a key stored on disk.
#[derive(Debug, Clone)]
/// Stored key information
pub struct StoredKey {
    /// Key alias
    pub alias: String,
    /// Base58-encoded public key hash
    pub public_key_hash: String,
    /// Base58-encoded public key
    pub public_key: String,
    /// Optional base58-encoded secret key
    pub secret_key: Option<String>,
}

/// Manages keys in OCaml-compatible format
///
/// Supports split storage where public keys and secret keys can be in different directories.
/// This is useful for the Russignol architecture where:
/// - Public keys are stored on /keys/ (read-only after setup)
/// - Decrypted secret keys are stored in /run/ (tmpfs, memory-only)
pub struct KeyManager {
    /// Directory for `public_keys` and `public_key_hashs` files
    base_dir: PathBuf,
    /// Optional separate directory for `secret_keys` file
    /// If None, uses `base_dir`
    secret_keys_dir: Option<PathBuf>,
}

impl KeyManager {
    /// Create a new key manager with all files in the same directory
    pub fn new(base_dir: Option<PathBuf>) -> Self {
        let base_dir = base_dir.unwrap_or_else(|| {
            ProjectDirs::from("org", "tezos", "signer").map_or_else(
                || {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    PathBuf::from(home).join(".tezos-signer")
                },
                |dirs| dirs.data_dir().to_path_buf(),
            )
        });

        Self {
            base_dir,
            secret_keys_dir: None,
        }
    }

    /// Create a key manager with split storage
    ///
    /// - `base_dir`: Directory for `public_keys` and `public_key_hashs`
    /// - `secret_keys_dir`: Separate directory for `secret_keys` (e.g., tmpfs for decrypted keys)
    pub fn new_with_secret_keys_path(
        base_dir: Option<PathBuf>,
        secret_keys_dir: Option<PathBuf>,
    ) -> Self {
        let base_dir = base_dir.unwrap_or_else(|| {
            ProjectDirs::from("org", "tezos", "signer").map_or_else(
                || {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    PathBuf::from(home).join(".tezos-signer")
                },
                |dirs| dirs.data_dir().to_path_buf(),
            )
        });

        Self {
            base_dir,
            secret_keys_dir,
        }
    }

    /// Get the base directory path
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn ensure_dirs(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.base_dir)?;
        if let Some(ref sk_dir) = self.secret_keys_dir {
            fs::create_dir_all(sk_dir)?;
        }
        Ok(())
    }

    // OCaml-compatible file paths
    fn public_key_hashs_file(&self) -> PathBuf {
        self.base_dir.join("public_key_hashs")
    }

    fn public_keys_file(&self) -> PathBuf {
        self.base_dir.join("public_keys")
    }

    fn secret_keys_file(&self) -> PathBuf {
        // Use separate directory if configured, otherwise use base_dir
        self.secret_keys_dir
            .as_ref()
            .unwrap_or(&self.base_dir)
            .join("secret_keys")
    }

    /// Load all keys from OCaml-compatible files
    pub fn load_keys(&self) -> HashMap<String, StoredKey> {
        let mut result = HashMap::new();

        // Load public_key_hashs
        let hash_path = self.public_key_hashs_file();
        let pubkey_path = self.public_keys_file();
        let secret_path = self.secret_keys_file();

        if !hash_path.exists() {
            return result;
        }

        // Read public key hashes
        let Ok(hash_content) = fs::read_to_string(&hash_path) else {
            return result;
        };

        let Ok(hash_entries): Result<Vec<OcamlKeyEntry<String>>, _> =
            serde_json::from_str(&hash_content)
        else {
            return result;
        };

        // Read public keys (optional)
        let pubkey_entries: Vec<OcamlKeyEntry<OcamlPublicKeyValue>> = if pubkey_path.exists() {
            fs::read_to_string(&pubkey_path)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Read secret keys (optional)
        let secret_entries: Vec<OcamlKeyEntry<String>> = if secret_path.exists() {
            fs::read_to_string(&secret_path)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Build result HashMap
        for hash_entry in hash_entries {
            let alias = hash_entry.name.clone();
            let public_key_hash = hash_entry.value.clone();

            // Find matching public key
            let public_key = pubkey_entries
                .iter()
                .find(|e| e.name == alias)
                .map(|e| e.value.key.clone())
                .unwrap_or_default();

            // Find matching secret key
            let secret_key = secret_entries
                .iter()
                .find(|e| e.name == alias)
                .and_then(|e| {
                    // Extract the actual key from "unencrypted:edsk..." or "encrypted:edesk..."
                    if let Some(unenc) = e.value.strip_prefix("unencrypted:") {
                        Some(unenc.to_string())
                    } else if let Some(_enc) = e.value.strip_prefix("encrypted:") {
                        // Skip encrypted keys for now
                        None
                    } else {
                        Some(e.value.clone())
                    }
                });

            result.insert(
                alias.clone(),
                StoredKey {
                    alias,
                    public_key_hash,
                    public_key,
                    secret_key,
                },
            );
        }

        result
    }

    /// Generate a new BLS key pair IN MEMORY ONLY
    ///
    /// Returns the generated key WITHOUT writing anything to disk.
    /// The caller is responsible for:
    /// 1. Encrypting the secret key before any disk writes
    /// 2. Calling `save_public_keys_only()` to persist public keys
    ///
    /// **SECURITY**: Secret keys must NEVER be written to disk unencrypted.
    pub fn gen_keys_in_memory(&self, name: &str, force: bool) -> Result<StoredKey, String> {
        let keys = self.load_keys();

        if keys.contains_key(name) && !force {
            return Err(format!(
                "Key '{name}' already exists. Use --force to overwrite."
            ));
        }

        let signer = UnencryptedSigner::generate(None)
            .map_err(|e| format!("Failed to generate keypair: {e}"))?;

        let pkh = signer.public_key_hash().to_b58check();
        let pk = signer.public_key().to_b58check();
        let sk = signer.secret_key().to_b58check();

        Ok(StoredKey {
            alias: name.to_string(),
            public_key_hash: pkh,
            public_key: pk,
            secret_key: Some(sk),
        })
    }

    /// Save ONLY public keys to disk (`public_key_hashs` and `public_keys` files)
    ///
    /// **SECURITY**: This method intentionally does NOT write `secret_keys`.
    /// Secret keys must be encrypted before writing to disk.
    pub fn save_public_keys_only(&self, keys: &[StoredKey]) -> Result<(), String> {
        self.ensure_dirs()
            .map_err(|e| format!("Failed to create directories: {e}"))?;

        // Build OCaml-format arrays for public keys only
        let mut hash_entries = Vec::new();
        let mut pubkey_entries = Vec::new();

        for key in keys {
            // Public key hash
            hash_entries.push(OcamlKeyEntry {
                name: key.alias.clone(),
                value: key.public_key_hash.clone(),
            });

            // Public key
            pubkey_entries.push(OcamlKeyEntry {
                name: key.alias.clone(),
                value: OcamlPublicKeyValue {
                    locator: format!("unencrypted:{}", key.public_key),
                    key: key.public_key.clone(),
                },
            });
        }

        // Write public_key_hashs
        let hash_content = serde_json::to_string_pretty(&hash_entries)
            .map_err(|e| format!("Failed to serialize public_key_hashs: {e}"))?;
        fs::write(self.public_key_hashs_file(), hash_content)
            .map_err(|e| format!("Failed to write public_key_hashs: {e}"))?;

        // Write public_keys
        let pubkey_content = serde_json::to_string_pretty(&pubkey_entries)
            .map_err(|e| format!("Failed to serialize public_keys: {e}"))?;
        fs::write(self.public_keys_file(), pubkey_content)
            .map_err(|e| format!("Failed to write public_keys: {e}"))?;

        // NOTE: secret_keys file is NOT written here - must be encrypted separately

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_manager_new_with_explicit_path() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));
        assert_eq!(manager.base_dir(), temp_dir.path());
    }

    #[test]
    fn test_key_manager_split_storage() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path().join("public");
        let secret_dir = temp_dir.path().join("secret");

        let manager =
            KeyManager::new_with_secret_keys_path(Some(base_dir.clone()), Some(secret_dir));

        assert_eq!(manager.base_dir(), base_dir);
    }

    #[test]
    fn test_load_keys_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        let keys = manager.load_keys();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_load_keys_ocaml_format() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        // Create OCaml-format public_key_hashs file
        let public_key_hash_json = r#"[{"name": "test_key", "value": "tz4test123"}]"#;
        fs::write(
            temp_dir.path().join("public_key_hashs"),
            public_key_hash_json,
        )
        .unwrap();

        // Create OCaml-format public_keys file
        let public_key_json = r#"[{"name": "test_key", "value": {"locator": "unencrypted:BLpk1test", "key": "BLpk1test"}}]"#;
        fs::write(temp_dir.path().join("public_keys"), public_key_json).unwrap();

        let keys = manager.load_keys();
        assert_eq!(keys.len(), 1);

        let key = keys.get("test_key").unwrap();
        assert_eq!(key.alias, "test_key");
        assert_eq!(key.public_key_hash, "tz4test123");
        assert_eq!(key.public_key, "BLpk1test");
        assert!(key.secret_key.is_none());
    }

    #[test]
    fn test_load_keys_with_secret_keys() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        // Create all three files
        let public_key_hash_json = r#"[{"name": "test_key", "value": "tz4test123"}]"#;
        fs::write(
            temp_dir.path().join("public_key_hashs"),
            public_key_hash_json,
        )
        .unwrap();

        let public_key_json = r#"[{"name": "test_key", "value": {"locator": "unencrypted:BLpk1test", "key": "BLpk1test"}}]"#;
        fs::write(temp_dir.path().join("public_keys"), public_key_json).unwrap();

        let sk_content = r#"[{"name": "test_key", "value": "unencrypted:BLsk1secret"}]"#;
        fs::write(temp_dir.path().join("secret_keys"), sk_content).unwrap();

        let keys = manager.load_keys();
        let key = keys.get("test_key").unwrap();
        assert_eq!(key.secret_key, Some("BLsk1secret".to_string()));
    }

    #[test]
    fn test_load_keys_skips_encrypted_secret() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        let pkh_content = r#"[{"name": "test_key", "value": "tz4test123"}]"#;
        fs::write(temp_dir.path().join("public_key_hashs"), pkh_content).unwrap();

        let sk_content = r#"[{"name": "test_key", "value": "encrypted:edesk1encrypted"}]"#;
        fs::write(temp_dir.path().join("secret_keys"), sk_content).unwrap();

        let keys = manager.load_keys();
        let key = keys.get("test_key").unwrap();
        // Encrypted keys should be skipped
        assert!(key.secret_key.is_none());
    }

    #[test]
    fn test_load_keys_corrupt_json_returns_empty() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        // Write invalid JSON
        fs::write(temp_dir.path().join("public_key_hashs"), "not valid json").unwrap();

        let keys = manager.load_keys();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_gen_keys_in_memory() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        let key = manager.gen_keys_in_memory("new_key", false).unwrap();

        assert_eq!(key.alias, "new_key");
        assert!(key.public_key_hash.starts_with("tz4"));
        assert!(key.public_key.starts_with("BLpk"));
        assert!(key.secret_key.is_some());
        assert!(key.secret_key.unwrap().starts_with("BLsk"));
    }

    #[test]
    fn test_gen_keys_rejects_existing_without_force() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        // Create existing key file
        let pkh_content = r#"[{"name": "existing", "value": "tz4test123"}]"#;
        fs::write(temp_dir.path().join("public_key_hashs"), pkh_content).unwrap();

        let result = manager.gen_keys_in_memory("existing", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_gen_keys_allows_force_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        // Create existing key file
        let pkh_content = r#"[{"name": "existing", "value": "tz4test123"}]"#;
        fs::write(temp_dir.path().join("public_key_hashs"), pkh_content).unwrap();

        let result = manager.gen_keys_in_memory("existing", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_save_public_keys_only_does_not_write_secrets() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        let key = StoredKey {
            alias: "test".to_string(),
            public_key_hash: "tz4test".to_string(),
            public_key: "BLpk1test".to_string(),
            secret_key: Some("BLsk1secret".to_string()),
        };

        manager.save_public_keys_only(&[key]).unwrap();

        // Public files should exist
        assert!(temp_dir.path().join("public_key_hashs").exists());
        assert!(temp_dir.path().join("public_keys").exists());

        // Secret keys file should NOT exist
        assert!(!temp_dir.path().join("secret_keys").exists());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        let original_key = StoredKey {
            alias: "roundtrip".to_string(),
            public_key_hash: "tz4roundtrip".to_string(),
            public_key: "BLpk1roundtrip".to_string(),
            secret_key: None,
        };

        manager
            .save_public_keys_only(std::slice::from_ref(&original_key))
            .unwrap();

        let loaded = manager.load_keys();
        let loaded_key = loaded.get("roundtrip").unwrap();

        assert_eq!(loaded_key.alias, original_key.alias);
        assert_eq!(loaded_key.public_key_hash, original_key.public_key_hash);
        assert_eq!(loaded_key.public_key, original_key.public_key);
    }
}
