//! Tezos signer utilities
//!
//! Key generation is handled during first boot setup.
//! This module provides utilities for reading public keys.

use crate::constants::KEYS_DIR;
use russignol_signer_lib::wallet::KeyManager as WalletKeyManager;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct TezosKey {
    pub name: String,
    pub value: String,
}

/// Get public key info (readable without PIN)
///
/// Returns alias and public key hash from the unencrypted `public_key_hashs` file.
/// Secret keys are only available in memory after PIN decryption.
pub fn get_keys() -> Vec<TezosKey> {
    // Only load public keys - secret keys are passed in memory, never read from disk
    let key_manager = WalletKeyManager::new(Some(PathBuf::from(KEYS_DIR)));
    let stored_keys = key_manager.load_keys();
    stored_keys
        .into_values()
        .map(|stored_key| TezosKey {
            name: stored_key.alias,
            value: stored_key.public_key_hash,
        })
        .collect()
}
