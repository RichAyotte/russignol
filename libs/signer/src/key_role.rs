//! Device key roles: the single ordered model for consensus / companion.

/// Baker signing role held on the device key-store.
///
/// [`Self::ALL`] is the global order. Walk that array for generation, listing,
/// migration, and host assumptions about `list_keys()` order. Device key-store
/// aliases come only from [`Self::device_alias`].
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

    /// Canonical device key-store alias (`"consensus"` / `"companion"`).
    #[must_use]
    pub const fn device_alias(self) -> &'static str {
        match self {
            Self::Consensus => "consensus",
            Self::Companion => "companion",
        }
    }

    /// Parse a lowercased device alias. Exact match only; substring rejected.
    #[must_use]
    pub fn from_device_alias(alias: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|role| role.device_alias() == alias)
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

    #[test]
    fn device_alias_roundtrip() {
        for role in KeyRole::ALL {
            assert_eq!(KeyRole::from_device_alias(role.device_alias()), Some(role));
        }
        assert_eq!(
            KeyRole::from_device_alias(&format!("my-{}-key", KeyRole::Consensus.device_alias())),
            None
        );
        assert_eq!(KeyRole::from_device_alias("baker_key"), None);
        assert_eq!(KeyRole::from_device_alias(""), None);
        assert_eq!(
            KeyRole::from_device_alias("Consensus"),
            None,
            "caller must lowercase before lookup"
        );
    }
}
