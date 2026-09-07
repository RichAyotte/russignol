//! Tezos signer utilities
//!
//! Key generation is handled during first boot setup.
//! This module provides utilities for reading public keys.

use crate::constants::KEYS_DIR;
use russignol_signer_lib::DeviceKey;
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

/// Order stored keys using [`DeviceKey::ALL`].
///
/// Only keys under a device alias are returned, in that array's order,
/// independent of `HashMap` insertion order. Walking the roles instead would
/// drop the tz6 consensus key, which shares the consensus role and answers to
/// an alias of its own.
///
/// A stored alias is resolved rather than matched against the canonical
/// spelling, so a card provisioned before the scheme suffix keeps every key,
/// and each is named by what it resolves to: one key drawn under two spellings
/// on one screen reads as two keys the device holds.
fn order_keys(stored_keys: &HashMap<String, StoredKey>) -> Vec<TezosKey> {
    let mut by_slot: [Option<&StoredKey>; DeviceKey::COUNT] = [None; DeviceKey::COUNT];
    for (alias, stored) in stored_keys {
        let Some(key) = DeviceKey::from_device_alias(alias) else {
            continue;
        };
        // Lowest address takes a slot two spellings both resolve to, as
        // `list_keys()` does: the host reads a key by its slot and the panel
        // draws the same slot, so a tie broken differently shows two keys.
        let slot = &mut by_slot[key.index()];
        let order = |held: &StoredKey| DeviceKey::slot_order(alias, &held.public_key_hash);
        if slot.is_none_or(|held| order(stored) < order(held)) {
            *slot = Some(stored);
        }
    }

    DeviceKey::ALL
        .into_iter()
        .filter_map(|key| {
            by_slot[key.index()].map(|stored| TezosKey {
                name: key.device_alias().to_string(),
                value: stored.public_key_hash.clone(),
            })
        })
        .collect()
}

/// The public keys a card names, or the fact that its wallet will not read.
///
/// The two are kept apart because a page drawing an unreadable wallet as no
/// keys says the card holds none, which is what a card before setup looks
/// like — and this card is one the signer may be serving signatures from.
#[derive(Clone)]
pub enum CardKeys {
    /// The keys the wallet files name, in device-key order.
    Listed(Vec<TezosKey>),
    /// The wallet files will not read, so what the card holds is unknown.
    Unreadable,
}

fn load_keys_from_disk() -> CardKeys {
    // Only load public keys - secret keys are passed in memory, never read from disk
    let key_manager = WalletKeyManager::new(Some(PathBuf::from(KEYS_DIR)));
    match key_manager.load_keys() {
        Ok(stored_keys) => CardKeys::Listed(order_keys(&stored_keys)),
        Err(e) => {
            log::error!("Wallet files will not read: {e}");
            CardKeys::Unreadable
        }
    }
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
pub fn get_keys() -> CardKeys {
    if let Some(keys) = PUBLIC_KEYS.get() {
        return CardKeys::Listed(keys.clone());
    }
    let keys = load_keys_from_disk();
    if let CardKeys::Listed(listed) = &keys
        && !listed.is_empty()
    {
        let _ = PUBLIC_KEYS.set(listed.clone());
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::{DeviceKey, KeyRole};

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
        let companion = DeviceKey::Bls(KeyRole::Companion).device_alias();
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        stored_keys.insert(companion.to_string(), make_stored_key(companion));
        stored_keys.insert(consensus.to_string(), make_stored_key(consensus));

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].name, consensus);
        assert_eq!(keys[1].name, companion);
    }

    /// A card provisioned before the scheme suffix carries the bare role words,
    /// spelled here as such a card spells them. Every page the device draws
    /// takes its keys from this list, so a key it drops is one nobody sees.
    #[test]
    fn a_pre_suffix_card_puts_every_key_in_its_own_slot() {
        let mut stored_keys = HashMap::new();
        for legacy in ["companion", "consensus"] {
            stored_keys.insert(legacy.to_string(), make_stored_key(legacy));
        }

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].value, make_stored_key("consensus").public_key_hash);
        assert_eq!(keys[1].value, make_stored_key("companion").public_key_hash);
    }

    /// A card carrying both spellings for one key resolves them to one slot,
    /// and which key lands there cannot come from `HashMap` order: the host
    /// reads a key by its slot and this list draws the same slot, so a tie
    /// broken two ways is two keys reported as one.
    #[test]
    fn a_slot_two_spellings_reach_is_not_decided_by_hash_order() {
        let canonical = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let slot_holder = |low_spelling: &str, high_spelling: &str| {
            let mut stored_keys = HashMap::new();
            for (spelling, pkh) in [(low_spelling, "tz4aaa"), (high_spelling, "tz4zzz")] {
                let mut key = make_stored_key(spelling);
                key.public_key_hash = pkh.to_string();
                stored_keys.insert(spelling.to_string(), key);
            }
            let keys = order_keys(&stored_keys);
            assert_eq!(keys.len(), 1);
            keys[0].value.clone()
        };

        // Either way round: the address decides the slot, not the spelling and
        // not which entry the map happened to yield first.
        assert_eq!(slot_holder("consensus", canonical), "tz4aaa");
        assert_eq!(slot_holder(canonical, "consensus"), "tz4aaa");
    }

    /// One key is drawn under one name. A card mid-migration would otherwise
    /// show the spelling on its disk beside the one every other surface
    /// resolves it under, reading as two keys where the device holds one.
    #[test]
    fn a_pre_suffix_key_is_named_by_what_it_resolves_to() {
        let mut stored_keys = HashMap::new();
        stored_keys.insert("consensus".to_string(), make_stored_key("consensus"));

        let keys = order_keys(&stored_keys);

        assert_eq!(keys[0].name, "consensus_tz4");
    }

    /// The signer serves and lists a key whose stored alias differs in case
    /// only, so a page that dropped it would leave that key signing with
    /// nothing on the display naming it.
    #[test]
    fn a_key_stored_under_a_different_casing_keeps_its_slot() {
        let stored = DeviceKey::Bls(KeyRole::Consensus)
            .device_alias()
            .to_uppercase();
        let mut stored_keys = HashMap::new();
        stored_keys.insert(stored.clone(), make_stored_key(&stored));

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "consensus_tz4");
        assert_eq!(keys[0].value, make_stored_key(&stored).public_key_hash);
    }

    /// A card provisioned with a tz6 key holds three, and dropping it here
    /// takes it off every page the device draws from this list.
    #[test]
    fn every_provisioned_key_is_ordered_not_only_the_roles() {
        let mut stored_keys = HashMap::new();
        for key in DeviceKey::ALL {
            let alias = key.device_alias();
            stored_keys.insert(alias.to_string(), make_stored_key(alias));
        }

        let keys = order_keys(&stored_keys);

        assert_eq!(keys.len(), DeviceKey::COUNT);
        for (slot, key) in DeviceKey::ALL.into_iter().enumerate() {
            assert_eq!(keys[slot].name, key.device_alias());
        }
    }

    #[test]
    fn test_missing_consensus_key() {
        let mut stored_keys = HashMap::new();
        let companion = DeviceKey::Bls(KeyRole::Companion).device_alias();
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
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let companion = DeviceKey::Bls(KeyRole::Companion).device_alias();
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
