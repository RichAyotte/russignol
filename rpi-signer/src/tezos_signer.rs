//! Tezos signer utilities
//!
//! Key generation is handled during first boot setup.
//! This module provides utilities for reading public keys.

use crate::constants::KEYS_DIR;
use russignol_signer_lib::wallet::{KeyManager as WalletKeyManager, StoredKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct TezosKey {
    pub name: String,
    pub value: String,
}

/// Order stored keys: consensus first, then companion.
fn order_keys(stored_keys: &HashMap<String, StoredKey>) -> Vec<TezosKey> {
    [stored_keys.get("consensus"), stored_keys.get("companion")]
        .into_iter()
        .flatten()
        .map(|k| TezosKey {
            name: k.alias.clone(),
            value: k.public_key_hash.clone(),
        })
        .collect()
}

/// Get public key info (readable without PIN)
///
/// Returns alias and public key hash from the unencrypted `public_key_hashs` file.
/// Secret keys are only available in memory after PIN decryption.
///
/// Keys are returned in deterministic order: consensus first, then companion.
/// The host utility expects `[0]` = consensus and `[1]` = companion.
pub fn get_keys() -> Vec<TezosKey> {
    // Only load public keys - secret keys are passed in memory, never read from disk
    let key_manager = WalletKeyManager::new(Some(PathBuf::from(KEYS_DIR)));
    let stored_keys = key_manager.load_keys();

    order_keys(&stored_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stored_key(alias: &str) -> StoredKey {
        StoredKey {
            alias: alias.to_string(),
            public_key_hash: format!("tz1{alias}hash"),
            public_key: String::new(),
            secret_key: None,
        }
    }

    #[test]
    fn test_keys_returned_in_correct_order() {
        let mut stored_keys = HashMap::new();
        stored_keys.insert("companion".to_string(), make_stored_key("companion"));
        stored_keys.insert("consensus".to_string(), make_stored_key("consensus"));

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].name, "consensus");
        assert_eq!(keys[1].name, "companion");
    }

    #[test]
    fn test_missing_consensus_key() {
        let mut stored_keys = HashMap::new();
        stored_keys.insert("companion".to_string(), make_stored_key("companion"));

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "companion");
    }

    #[test]
    fn test_empty_keys() {
        let stored_keys = HashMap::new();
        let keys = order_keys(&stored_keys);
        assert!(keys.is_empty());
    }
}
