//! Device key roles and the keys the device holds under them.

use crate::scheme::Scheme;

/// Baker signing role held on the device key-store.
///
/// [`Self::ALL`] is the global order. Walk that array for generation, listing,
/// migration, and host assumptions about `list_keys()` order. A role holds no
/// key-store alias: an alias names the scheme its key signs under, which a
/// role does not know, so [`DeviceKey::device_alias`] is the only source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// Consensus key
    Consensus,
    /// Companion key
    Companion,
}

impl KeyRole {
    /// Global order: consensus, then companion.
    pub const ALL: [Self; Self::COUNT] = [Self::Consensus, Self::Companion];

    /// Number of roles; equals the length of [`Self::ALL`].
    pub const COUNT: usize = 2;

    /// Index into role-parallel arrays; equals this role's position in [`Self::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Consensus => 0,
            Self::Companion => 1,
        }
    }

    /// Build a role-indexed array by evaluating `f` per role.
    ///
    /// The only way to construct one that names the role for every slot, so a
    /// change to [`Self::ALL`] cannot silently re-point existing entries the
    /// way a positional literal would.
    #[must_use]
    pub fn map_all<T>(mut f: impl FnMut(Self) -> T) -> [T; Self::COUNT] {
        std::array::from_fn(|i| f(Self::ALL[i]))
    }
}

/// A key the device provisions and holds: a role, and the scheme it signs
/// under.
///
/// Only the consensus role admits a second scheme. The protocol rejects every
/// scheme but tz4 as a companion key (`Update_companion_key_not_tz4`,
/// `src/proto_alpha/lib_protocol/apply.ml:1499-1509`), so [`KeyRole`] carries
/// no scheme dimension and the role-indexed arrays keyed on [`KeyRole::COUNT`]
/// are unaffected by a device holding three keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceKey {
    /// A BLS key in the named role.
    Bls(KeyRole),
    /// The XMSS consensus key.
    XmssConsensus,
}

impl DeviceKey {
    /// Number of keys the device holds; equals the length of [`Self::ALL`].
    pub const COUNT: usize = KeyRole::COUNT + 1;

    /// Global order: the BLS keys in [`KeyRole::ALL`] order, then the XMSS one.
    ///
    /// The host reads a listed key by its slot, so a key's position here is what
    /// names it: consensus at `[0]`, companion at `[1]`, the tz6 consensus key
    /// at `[2]`. Reordering this array re-points every one of those readers.
    pub const ALL: [Self; Self::COUNT] = Self::all();

    /// Index into device-key-parallel arrays; equals this key's position in
    /// [`Self::ALL`], which [`Self::all`] fills from here.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Bls(role) => role.index(),
            Self::XmssConsensus => KeyRole::COUNT,
        }
    }

    /// Places every key at its own [`Self::index`], the BLS ones straight out of
    /// [`KeyRole::ALL`], so the order has one definition and a role added there
    /// reaches this array without an entry being written for it.
    ///
    /// The fill value is a placeholder every slot is written over. Two keys
    /// claiming one index would leave a slot holding it, which is what
    /// `each_device_key_sits_at_the_slot_its_readers_expect` reads.
    const fn all() -> [Self; Self::COUNT] {
        let mut keys = [Self::XmssConsensus; Self::COUNT];
        let mut i = 0;
        while i < KeyRole::COUNT {
            let key = Self::Bls(KeyRole::ALL[i]);
            keys[key.index()] = key;
            i += 1;
        }
        keys[Self::XmssConsensus.index()] = Self::XmssConsensus;
        keys
    }

    /// The baker role this key signs in.
    #[must_use]
    pub const fn role(self) -> KeyRole {
        match self {
            Self::Bls(role) => role,
            Self::XmssConsensus => KeyRole::Consensus,
        }
    }

    /// The scheme this key signs under.
    #[must_use]
    pub const fn scheme(self) -> Scheme {
        match self {
            Self::Bls(_) => Scheme::Bls,
            Self::XmssConsensus => Scheme::Xmss,
        }
    }

    /// Canonical device key-store alias.
    ///
    /// The suffix is the scheme's registered public-key-hash prefix, so a key
    /// and the address printed beside it name the same scheme. Two keys of one
    /// role sit in the same store, and a suffix is what separates them there.
    #[must_use]
    pub const fn device_alias(self) -> &'static str {
        match self {
            Self::Bls(KeyRole::Consensus) => "consensus_tz4",
            Self::Bls(KeyRole::Companion) => "companion_tz4",
            Self::XmssConsensus => "consensus_tz6",
        }
    }

    /// The spelling a card provisioned before the suffix carries, if any.
    ///
    /// A backup keeps the wallet files verbatim and a restore writes them
    /// back, so a card written under the bare role words can appear at any
    /// time — these resolve forever rather than until the field has migrated.
    #[must_use]
    const fn legacy_device_alias(self) -> Option<&'static str> {
        match self {
            Self::Bls(KeyRole::Consensus) => Some("consensus"),
            Self::Bls(KeyRole::Companion) => Some("companion"),
            // No card was ever provisioned with a tz6 key under an earlier
            // spelling: the suffix predates the first one written.
            Self::XmssConsensus => None,
        }
    }

    /// Where a stored alias and the address filed under it sort among a card's
    /// keys.
    ///
    /// Device keys come first in [`Self::ALL`] order. Two spellings resolving
    /// to one key share a slot, and the lower address takes it — which is the
    /// key the signer serves there, so the device's own list, the pages it
    /// draws and the host's card report name the same one. An alias no device
    /// key claims sorts after them all, by its own name.
    #[must_use]
    pub fn slot_order(alias: &str, address: &str) -> (usize, String) {
        Self::from_device_alias(alias).map_or_else(
            || (Self::COUNT, alias.to_string()),
            |key| (key.index(), address.to_string()),
        )
    }

    /// Parse a stored device alias, canonical or pre-suffix. Whole match only;
    /// a substring resolves to nothing.
    ///
    /// This is where alias resolution is case-insensitive: a stored spelling
    /// names its key in any casing, and no caller normalizes for itself. The
    /// fold is ASCII because every spelling above is.
    #[must_use]
    pub fn from_device_alias(alias: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|key| {
            key.device_alias().eq_ignore_ascii_case(alias)
                || key
                    .legacy_device_alias()
                    .is_some_and(|legacy| legacy.eq_ignore_ascii_case(alias))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_order_and_index_agree() {
        assert_eq!(KeyRole::ALL.len(), KeyRole::COUNT);
        assert_eq!(KeyRole::ALL, [KeyRole::Consensus, KeyRole::Companion]);
        for (i, role) in KeyRole::ALL.into_iter().enumerate() {
            assert_eq!(role.index(), i);
            assert_eq!(KeyRole::ALL[role.index()], role);
        }
    }

    #[test]
    fn map_all_slots_land_at_their_role_index() {
        let roles = KeyRole::map_all(|role| role);
        assert_eq!(roles, KeyRole::ALL);
        for role in KeyRole::ALL {
            assert_eq!(roles[role.index()], role);
        }
    }

    /// Callers read a device key by its slot, so where each one sits is the
    /// contract: a BLS key at its own [`KeyRole::index`], the tz6 key last. Two
    /// keys claiming one index leaves the other slot holding `all`'s placeholder,
    /// which is the reading that fails here.
    #[test]
    fn each_device_key_sits_at_the_slot_its_readers_expect() {
        for key in DeviceKey::ALL {
            assert_eq!(DeviceKey::ALL[key.index()], key);
        }
        for role in KeyRole::ALL {
            assert_eq!(DeviceKey::Bls(role).index(), role.index());
        }
        assert_eq!(DeviceKey::XmssConsensus.index(), DeviceKey::COUNT - 1);
    }

    /// The three spellings a provisioned card carries.
    ///
    /// A card is written under one spelling and read under another, so these
    /// are a disk contract rather than an internal name: pinned here as
    /// literals, not derived from whatever the code beside them says.
    #[test]
    fn the_device_aliases_are_the_three_a_card_carries() {
        assert_eq!(
            DeviceKey::Bls(KeyRole::Consensus).device_alias(),
            "consensus_tz4"
        );
        assert_eq!(
            DeviceKey::Bls(KeyRole::Companion).device_alias(),
            "companion_tz4"
        );
        assert_eq!(DeviceKey::XmssConsensus.device_alias(), "consensus_tz6");
    }

    /// The suffix is the scheme's registered public-key-hash prefix, so the
    /// alias and the address printed beside it carry the same word. Held
    /// against what a key of that scheme renders as, the two cannot drift.
    #[test]
    fn every_alias_ends_in_the_word_its_key_renders_as() {
        for key in DeviceKey::ALL {
            let address = crate::PublicKeyHash::from_bytes(key.scheme(), &[0u8; 20])
                .expect("twenty bytes is a public key hash")
                .to_b58check();
            let (_, suffix) = key
                .device_alias()
                .rsplit_once('_')
                .expect("every alias carries a scheme suffix");
            assert!(
                address.starts_with(suffix),
                "{key:?} is aliased {suffix:?} and addressed {address}"
            );
        }
    }

    /// A card provisioned before the suffix existed carries the bare role
    /// words, and a backup taken from one can be restored onto a migrated card
    /// at any time. So those spellings resolve forever, not for a release.
    #[test]
    fn a_card_provisioned_before_the_suffix_resolves_every_key() {
        assert_eq!(
            DeviceKey::from_device_alias("consensus"),
            Some(DeviceKey::Bls(KeyRole::Consensus))
        );
        assert_eq!(
            DeviceKey::from_device_alias("companion"),
            Some(DeviceKey::Bls(KeyRole::Companion))
        );
    }

    /// The tz6 key is not the tz4 consensus key. Both sign in the consensus
    /// role, so a spelling resolving to either would attribute one key's
    /// signature to the other's slot wherever a caller reaches by name.
    #[test]
    fn the_two_consensus_keys_answer_to_different_spellings() {
        let tz4 = DeviceKey::Bls(KeyRole::Consensus);
        let tz6 = DeviceKey::XmssConsensus;

        assert_eq!(DeviceKey::from_device_alias(tz6.device_alias()), Some(tz6));
        assert_eq!(DeviceKey::from_device_alias(tz4.device_alias()), Some(tz4));
        assert_eq!(
            DeviceKey::from_device_alias(tz4.legacy_device_alias().expect("a tz4 card spelling")),
            Some(tz4)
        );
    }

    /// A stored spelling names one key whatever its casing.
    ///
    /// Six surfaces resolve the alias a card carries, and they have to agree:
    /// a key one of them drops is a key the others still serve and list, absent
    /// from every page the device draws and reported missing by the host's card
    /// doctor.
    #[test]
    fn a_stored_spelling_resolves_whatever_its_casing() {
        for key in DeviceKey::ALL {
            let spellings = [Some(key.device_alias()), key.legacy_device_alias()];
            for spelling in spellings.into_iter().flatten() {
                assert_eq!(
                    DeviceKey::from_device_alias(&spelling.to_uppercase()),
                    Some(key),
                    "{spelling} in upper case"
                );
                let mixed: String = spelling
                    .char_indices()
                    .map(|(i, c)| {
                        if i % 2 == 0 {
                            c.to_ascii_uppercase()
                        } else {
                            c
                        }
                    })
                    .collect();
                assert_eq!(
                    DeviceKey::from_device_alias(&mixed),
                    Some(key),
                    "{mixed} in mixed case"
                );
            }
        }
    }

    /// Every spelling the store resolves names one key.
    ///
    /// The host reads `list_keys()[0]` as consensus and `[1]` as companion, so
    /// two keys answering to one spelling puts one of them in the other's
    /// slot — which a card carrying both spellings would otherwise take
    /// silently.
    #[test]
    fn no_spelling_names_two_device_keys() {
        let mut spellings: Vec<&str> = DeviceKey::ALL
            .into_iter()
            .flat_map(|key| [Some(key.device_alias()), key.legacy_device_alias()])
            .flatten()
            .collect();
        spellings.sort_unstable();
        let distinct = spellings.len();
        spellings.dedup();
        assert_eq!(
            spellings.len(),
            distinct,
            "two device keys share a spelling"
        );
    }

    #[test]
    fn each_device_key_reports_its_role_and_scheme() {
        for role in KeyRole::ALL {
            assert_eq!(DeviceKey::Bls(role).role(), role);
            assert_eq!(DeviceKey::Bls(role).scheme(), Scheme::Bls);
        }
        assert_eq!(DeviceKey::XmssConsensus.role(), KeyRole::Consensus);
        assert_eq!(DeviceKey::XmssConsensus.scheme(), Scheme::Xmss);
    }

    #[test]
    fn device_key_alias_roundtrip() {
        for key in DeviceKey::ALL {
            assert_eq!(DeviceKey::from_device_alias(key.device_alias()), Some(key));
            if let Some(legacy) = key.legacy_device_alias() {
                assert_eq!(DeviceKey::from_device_alias(legacy), Some(key));
            }
        }
        assert_eq!(DeviceKey::from_device_alias(""), None);
        assert_eq!(DeviceKey::from_device_alias("baker_key"), None);
        assert_eq!(
            DeviceKey::from_device_alias(&format!(
                "my-{}-key",
                DeviceKey::XmssConsensus.device_alias()
            )),
            None
        );
    }
}
