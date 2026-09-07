//! Wallet management for loading and saving keys from disk in OCaml-compatible format.

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::signer::Unencrypted;

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
    pub secret_key: Option<Zeroizing<String>>,
}

/// The locator prefix of an unencrypted secret in a `secret_keys` entry.
pub const UNENCRYPTED_PREFIX: &str = "unencrypted:";

/// One `secret_keys` entry: the alias a store files a key under and the bare
/// base58 secret filed there.
pub struct SecretKeyEntry<'a> {
    /// The name the store files this key under.
    pub alias: &'a str,
    /// The base58 secret, without [`UNENCRYPTED_PREFIX`].
    pub secret: &'a str,
}

/// The `secret_keys` array for `entries`, as the OCaml client writes it, in a
/// buffer sized to the emit.
///
/// Sizing first keeps the plaintext in one heap block that is zeroed on drop: a
/// reallocation would copy it into a fresh block and leave the old one
/// un-zeroed. The size is the emit's own byte count rather than a per-entry
/// budget, an XMSS secret being kilobytes of base58 against a `BLsk`'s 54
/// characters, so no constant covers both. Counting runs the same emit into a
/// sink that keeps a length and none of the bytes.
#[must_use]
pub fn secret_keys_json(entries: &[SecretKeyEntry<'_>]) -> Zeroizing<String> {
    let mut counted = ByteCount::default();
    emit_secret_keys(&mut counted, entries);

    let mut json = Zeroizing::new(String::with_capacity(counted.0));
    emit_secret_keys(&mut *json, entries);
    json
}

const INFALLIBLE: &str = "writing to a String or a counter is infallible";

fn emit_secret_keys<W: core::fmt::Write>(out: &mut W, entries: &[SecretKeyEntry<'_>]) {
    out.write_char('[').expect(INFALLIBLE);
    for (position, entry) in entries.iter().enumerate() {
        if position > 0 {
            out.write_char(',').expect(INFALLIBLE);
        }
        out.write_str(r#"{"name":""#).expect(INFALLIBLE);
        write_escaped(out, entry.alias);
        out.write_str(r#"","value":""#).expect(INFALLIBLE);
        out.write_str(UNENCRYPTED_PREFIX).expect(INFALLIBLE);
        // Base58 alphabet contains no `"`, `\`, or control bytes — write raw.
        out.write_str(entry.secret).expect(INFALLIBLE);
        out.write_str(r#""}"#).expect(INFALLIBLE);
    }
    out.write_char(']').expect(INFALLIBLE);
}

/// A sink keeping how many bytes were written and none of the bytes, so
/// counting an emit that carries plaintext copies none of it.
#[derive(Default)]
struct ByteCount(usize);

impl core::fmt::Write for ByteCount {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

/// Escape a JSON string body: `"`, `\`, and ASCII control bytes as `\u00XX`.
/// No other escapes are needed because non-ASCII UTF-8 is valid inside a JSON
/// string.
fn write_escaped<W: core::fmt::Write>(out: &mut W, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.write_str("\\\""),
            '\\' => out.write_str("\\\\"),
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32),
            c => out.write_char(c),
        }
        .expect(INFALLIBLE);
    }
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

/// Where a wallet lives when the caller names no directory.
fn default_base_dir() -> PathBuf {
    ProjectDirs::from("org", "tezos", "signer").map_or_else(
        || {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".tezos-signer")
        },
        |dirs| dirs.data_dir().to_path_buf(),
    )
}

impl KeyManager {
    /// Create a new key manager with all files in the same directory
    #[must_use]
    pub fn new(base_dir: Option<PathBuf>) -> Self {
        Self::new_with_secret_keys_path(base_dir, None)
    }

    /// Create a key manager with split storage
    ///
    /// - `base_dir`: Directory for `public_keys` and `public_key_hashs`
    /// - `secret_keys_dir`: Separate directory for `secret_keys` (e.g., tmpfs for decrypted keys)
    #[must_use]
    pub fn new_with_secret_keys_path(
        base_dir: Option<PathBuf>,
        secret_keys_dir: Option<PathBuf>,
    ) -> Self {
        let base_dir = base_dir.unwrap_or_else(default_base_dir);

        Self {
            base_dir,
            secret_keys_dir,
        }
    }

    /// Get the base directory path
    #[must_use]
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
        self.secret_keys_dir
            .as_ref()
            .unwrap_or(&self.base_dir)
            .join("secret_keys")
    }

    /// Load every key the wallet files name.
    ///
    /// An absent address file is an empty wallet, which is what a card holds
    /// before setup runs.
    ///
    /// # Errors
    ///
    /// Returns an error if any wallet file that is present will not read or
    /// parse. Answering that with an empty map tells every caller the card
    /// holds no keys, which is what a card before setup looks like — and it
    /// sends an operator to re-flash a card whose keys are intact behind one
    /// unreadable file.
    pub fn load_keys(&self) -> Result<HashMap<String, StoredKey>, String> {
        let hash_entries: Vec<OcamlKeyEntry<String>> =
            read_wallet_file(&self.public_key_hashs_file())?;
        let pubkey_entries: Vec<OcamlKeyEntry<OcamlPublicKeyValue>> =
            read_wallet_file(&self.public_keys_file())?;
        let secret_entries: Vec<OcamlKeyEntry<String>> =
            read_wallet_file(&self.secret_keys_file())?;

        let mut result = HashMap::new();
        for hash_entry in hash_entries {
            let alias = hash_entry.name.clone();
            let public_key_hash = hash_entry.value.clone();

            let public_key = pubkey_entries
                .iter()
                .find(|e| e.name == alias)
                .map(|e| e.value.key.clone())
                .unwrap_or_default();

            let secret_key = secret_entries
                .iter()
                .find(|e| e.name == alias)
                .and_then(|e| {
                    // Extract the actual key from "unencrypted:edsk..." or "encrypted:edesk..."
                    if let Some(unenc) = e.value.strip_prefix(UNENCRYPTED_PREFIX) {
                        Some(Zeroizing::new(unenc.to_string()))
                    } else if let Some(_enc) = e.value.strip_prefix("encrypted:") {
                        // Skip encrypted keys for now
                        None
                    } else {
                        Some(Zeroizing::new(e.value.clone()))
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

        Ok(result)
    }

    /// Generate a new BLS key pair IN MEMORY ONLY
    ///
    /// Returns the generated key WITHOUT writing anything to disk.
    /// The caller is responsible for:
    /// 1. Encrypting the secret key before any disk writes
    /// 2. Calling `save_public_keys_only()` to persist public keys
    ///
    /// **SECURITY**: Secret keys must NEVER be written to disk unencrypted.
    ///
    /// # Errors
    ///
    /// Returns an error if a key with the given name already exists (and `force` is false)
    /// or if key generation fails.
    pub fn gen_keys_in_memory(&self, name: &str, force: bool) -> Result<StoredKey, String> {
        let keys = self.load_keys()?;

        if keys.contains_key(name) && !force {
            return Err(format!(
                "Key '{name}' already exists. Use --force to overwrite."
            ));
        }

        let signer =
            Unencrypted::generate(None).map_err(|e| format!("Failed to generate keypair: {e}"))?;

        let pkh = signer.public_key_hash().to_b58check();
        let pk = signer.public_key().to_b58check();
        let sk = Zeroizing::new(signer.secret_key().to_b58check());

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
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation, JSON serialization, or file I/O fails.
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
                    locator: format!("{UNENCRYPTED_PREFIX}{}", key.public_key),
                    key: key.public_key.clone(),
                },
            });
        }

        // Through a rename rather than in place: these files are read back by
        // a boot that may follow a power cut at any instant, and one caught
        // half-written reads as a card holding no keys at all — which no later
        // boot can repair while the keys partition is mounted read-only.
        let hash_content = serde_json::to_string_pretty(&hash_entries)
            .map_err(|e| format!("Failed to serialize public_key_hashs: {e}"))?;
        crate::durable::atomic_write(&self.public_key_hashs_file(), hash_content.as_bytes())
            .map_err(|e| format!("Failed to write public_key_hashs: {e}"))?;

        let pubkey_content = serde_json::to_string_pretty(&pubkey_entries)
            .map_err(|e| format!("Failed to serialize public_keys: {e}"))?;
        crate::durable::atomic_write(&self.public_keys_file(), pubkey_content.as_bytes())
            .map_err(|e| format!("Failed to write public_keys: {e}"))?;

        // NOTE: secret_keys file is NOT written here - must be encrypted separately

        Ok(())
    }
}

/// Read and parse one wallet file, an absent one holding no entries.
///
/// Absence comes from the read itself rather than from a check before it. A
/// file that arrives or vanishes between the two belongs to a different card
/// from the one that was observed, and the `NotFound` a stale check leads to
/// would surface as an unreadable wallet — which sends an operator to re-flash
/// a card whose keys are intact.
fn read_wallet_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>, String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Failed to read {}: {e}", path.display())),
    };
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries<'a>(pairs: &'a [(&'a str, &'a str)]) -> Vec<SecretKeyEntry<'a>> {
        pairs
            .iter()
            .map(|(alias, secret)| SecretKeyEntry { alias, secret })
            .collect()
    }

    /// The emit parses back as the entries it was given, each value carrying
    /// the locator prefix the OCaml client reads.
    #[test]
    fn secret_keys_json_round_trips_through_the_reader() {
        let json = secret_keys_json(&entries(&[
            ("consensus_tz4", "BLsk1"),
            ("companion_tz4", "BLsk2"),
        ]));

        let parsed: Vec<OcamlKeyEntry<String>> = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed
                .iter()
                .map(|e| (e.name.as_str(), e.value.as_str()))
                .collect::<Vec<_>>(),
            [
                ("consensus_tz4", "unencrypted:BLsk1"),
                ("companion_tz4", "unencrypted:BLsk2"),
            ]
        );
    }

    /// A reallocation mid-emit copies the plaintext into a fresh block and
    /// leaves the old one un-zeroed, so the buffer holds exactly what the emit
    /// writes, a secret of tens of thousands of characters included.
    #[test]
    fn secret_keys_json_never_reallocates() {
        let wide: String = std::iter::repeat_n('3', 230_000).collect();
        let json = secret_keys_json(&entries(&[
            ("consensus_tz4", "BLsk1"),
            ("consensus_tz6", &wide),
        ]));

        assert_eq!(json.capacity(), json.len());
    }

    /// Every byte JSON forbids raw in a string is escaped: a control byte
    /// written through produces a store no parser reads back.
    #[test]
    fn secret_keys_json_escapes_the_alias() {
        let json = secret_keys_json(&entries(&[("a\"b\\c\u{1}\u{1f}d", "BLsk1")]));

        let parsed: Vec<OcamlKeyEntry<String>> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0].name, "a\"b\\c\u{1}\u{1f}d");
    }

    #[test]
    fn secret_keys_json_of_nothing_is_an_empty_array() {
        assert_eq!(&*secret_keys_json(&[]), "[]");
    }
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
            KeyManager::new_with_secret_keys_path(Some(base_dir.clone()), Some(secret_dir.clone()));

        assert_eq!(manager.base_dir(), base_dir);
        assert_eq!(manager.secret_keys_file(), secret_dir.join("secret_keys"));
        assert_eq!(
            KeyManager::new(Some(base_dir.clone())).secret_keys_file(),
            base_dir.join("secret_keys"),
            "with no split, the secret keys sit beside the public ones"
        );
    }

    /// A secret filed under neither prefix is taken as the key itself, which is
    /// what an `octez-client` wallet written before the locator prefix existed
    /// carries. Reading it as absent would drop a key the card holds.
    #[test]
    fn a_secret_under_no_locator_prefix_is_the_key_itself() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));
        fs::write(
            temp_dir.path().join("public_key_hashs"),
            br#"[{"name":"bare","value":"tz4abc"}]"#,
        )
        .unwrap();
        fs::write(
            temp_dir.path().join("secret_keys"),
            br#"[{"name":"bare","value":"BLskBare"}]"#,
        )
        .unwrap();

        let keys = manager.load_keys().unwrap();

        assert_eq!(
            keys["bare"].secret_key.as_deref().map(String::as_str),
            Some("BLskBare")
        );
    }

    /// A wallet file that will not parse is a card whose keys are unreachable,
    /// not a card holding none. Reading it as an empty wallet is what a card
    /// before setup looks like, and the host's doctor sends the operator to
    /// re-flash a card whose keys are intact behind one unreadable file.
    #[test]
    fn a_wallet_file_that_will_not_parse_is_not_an_empty_wallet() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));
        let addresses = temp_dir.path().join("public_key_hashs");
        fs::write(
            &addresses,
            br#"[{"name":"consensus_tz4","value":"tz4abc"}]"#,
        )
        .unwrap();

        assert_eq!(manager.load_keys().unwrap().len(), 1);

        fs::write(&addresses, b"[{ this is not json").unwrap();
        let Err(e) = manager.load_keys() else {
            panic!("an unparseable address file must be reported")
        };
        assert!(
            e.contains("public_key_hashs"),
            "the error names the file: {e}"
        );

        fs::write(
            &addresses,
            br#"[{"name":"consensus_tz4","value":"tz4abc"}]"#,
        )
        .unwrap();
        fs::write(temp_dir.path().join("public_keys"), b"not json either").unwrap();
        let Err(e) = manager.load_keys() else {
            panic!("an unparseable public-key file must be reported")
        };
        assert!(e.contains("public_keys"), "the error names the file: {e}");
    }

    #[test]
    fn test_load_keys_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        let keys = manager.load_keys().unwrap();
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

        let keys = manager.load_keys().unwrap();
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

        let keys = manager.load_keys().unwrap();
        let key = keys.get("test_key").unwrap();
        assert_eq!(
            key.secret_key,
            Some(Zeroizing::new("BLsk1secret".to_string()))
        );
    }

    #[test]
    fn test_load_keys_skips_encrypted_secret() {
        let temp_dir = TempDir::new().unwrap();
        let manager = KeyManager::new(Some(temp_dir.path().to_path_buf()));

        let pkh_content = r#"[{"name": "test_key", "value": "tz4test123"}]"#;
        fs::write(temp_dir.path().join("public_key_hashs"), pkh_content).unwrap();

        let sk_content = r#"[{"name": "test_key", "value": "encrypted:edesk1encrypted"}]"#;
        fs::write(temp_dir.path().join("secret_keys"), sk_content).unwrap();

        let keys = manager.load_keys().unwrap();
        let key = keys.get("test_key").unwrap();
        // Encrypted keys should be skipped
        assert!(key.secret_key.is_none());
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
            secret_key: Some(Zeroizing::new("BLsk1secret".to_string())),
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

        let loaded = manager.load_keys().unwrap();
        let loaded_key = loaded.get("roundtrip").unwrap();

        assert_eq!(loaded_key.alias, original_key.alias);
        assert_eq!(loaded_key.public_key_hash, original_key.public_key_hash);
        assert_eq!(loaded_key.public_key, original_key.public_key);
    }
}
