//! Tezos signer utilities
//!
//! Key generation is handled during first boot setup.
//! This module provides utilities for reading public keys.

use crate::constants::KEYS_DIR;
use russignol_signer_lib::KeyRole;
use russignol_signer_lib::wallet::{KeyManager as WalletKeyManager, StoredKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Clone, Deserialize)]
pub struct TezosKey {
    pub name: String,
    pub value: String,
}

/// Process-lifetime public-key list. Keys are immutable after setup; empty
/// loads are not cached so a pre-keygen call cannot pin an empty result.
static PUBLIC_KEYS: OnceLock<Vec<TezosKey>> = OnceLock::new();

/// Order stored keys using [`KeyRole::ALL`].
///
/// Only role-aliased keys are returned; order is always consensus then companion
/// when both exist, independent of `HashMap` insertion order.
fn order_keys(stored_keys: &HashMap<String, StoredKey>) -> Vec<TezosKey> {
    KeyRole::ALL
        .into_iter()
        .filter_map(|role| stored_keys.get(role.device_alias()))
        .map(|k| TezosKey {
            name: k.alias.clone(),
            value: k.public_key_hash.clone(),
        })
        .collect()
}

fn load_keys_from_disk() -> Vec<TezosKey> {
    // Only load public keys - secret keys are passed in memory, never read from disk
    let key_manager = WalletKeyManager::new(Some(PathBuf::from(KEYS_DIR)));
    let stored_keys = key_manager.load_keys();
    order_keys(&stored_keys)
}

/// Get public key info (readable without PIN)
///
/// Returns alias and public key hash from the unencrypted `public_key_hashs` file.
/// Secret keys are only available in memory after PIN decryption.
///
/// Keys are returned in deterministic order: consensus first, then companion.
/// The host utility expects `[0]` = consensus and `[1]` = companion.
///
/// After a successful non-empty load, subsequent calls reuse the in-memory
/// list (no further disk I/O). Public material only.
pub fn get_keys() -> Vec<TezosKey> {
    if let Some(keys) = PUBLIC_KEYS.get() {
        return keys.clone();
    }
    let keys = load_keys_from_disk();
    if !keys.is_empty() {
        let _ = PUBLIC_KEYS.set(keys.clone());
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::KeyRole;

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
        let companion = KeyRole::Companion.device_alias();
        let consensus = KeyRole::Consensus.device_alias();
        stored_keys.insert(companion.to_string(), make_stored_key(companion));
        stored_keys.insert(consensus.to_string(), make_stored_key(consensus));

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].name, consensus);
        assert_eq!(keys[1].name, companion);
    }

    #[test]
    fn test_missing_consensus_key() {
        let mut stored_keys = HashMap::new();
        let companion = KeyRole::Companion.device_alias();
        stored_keys.insert(companion.to_string(), make_stored_key(companion));

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, companion);
    }

    #[test]
    fn test_empty_keys() {
        let stored_keys = HashMap::new();
        let keys = order_keys(&stored_keys);
        assert!(keys.is_empty());
    }

    #[test]
    fn order_keys_is_stable_for_cache_population() {
        let mut stored_keys = HashMap::new();
        let consensus = KeyRole::Consensus.device_alias();
        let companion = KeyRole::Companion.device_alias();
        stored_keys.insert(consensus.to_string(), make_stored_key(consensus));
        stored_keys.insert(companion.to_string(), make_stored_key(companion));
        let a = order_keys(&stored_keys);
        let b = order_keys(&stored_keys);
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0].name, b[0].name);
        assert_eq!(a[0].value, b[0].value);
        assert_eq!(a[1].name, b[1].name);
        assert_eq!(a[1].value, b[1].value);
    }
}
