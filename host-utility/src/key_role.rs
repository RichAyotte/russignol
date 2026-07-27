//! Host-side naming for [`KeyRole`] (octez-client baker aliases).

use russignol_signer_lib::KeyRole;

use crate::constants::{
    COMPANION_KEY_ALIAS, COMPANION_KEY_OLD_ALIAS, COMPANION_KEY_PENDING_ALIAS, CONSENSUS_KEY_ALIAS,
    CONSENSUS_KEY_OLD_ALIAS, CONSENSUS_KEY_PENDING_ALIAS,
};

/// Live baker aliases for every role, in [`KeyRole::ALL`] order.
pub fn baker_aliases() -> [&'static str; KeyRole::COUNT] {
    KeyRole::map_all(BakerKeyNames::baker_alias)
}

/// Baker-wallet names for a device [`KeyRole`].
pub trait BakerKeyNames {
    /// Live octez alias (`russignol-consensus` / `russignol-companion`).
    fn baker_alias(self) -> &'static str;
    /// Pending alias during rotation.
    fn baker_pending_alias(self) -> &'static str;
    /// Alias the outgoing key is renamed to during rotation.
    fn baker_old_alias(self) -> &'static str;
    /// Human label for status / restore UI.
    fn display_name(self) -> &'static str;
    /// Human label for a pending rotation alias.
    fn pending_display_name(self) -> &'static str;
    /// Delegate RPC object key (`consensus_key` / `companion_key`).
    fn rpc_delegate_key_field(self) -> &'static str;
    /// Subcommand word in `octez-client set <kind> key for <baker> to <alias>`.
    /// Spelled like the device alias today, but it is octez-client's vocabulary
    /// and changes with the CLI, not with the device key-store.
    fn cli_key_kind(self) -> &'static str;
}

impl BakerKeyNames for KeyRole {
    fn baker_alias(self) -> &'static str {
        match self {
            Self::Consensus => CONSENSUS_KEY_ALIAS,
            Self::Companion => COMPANION_KEY_ALIAS,
        }
    }

    fn baker_pending_alias(self) -> &'static str {
        match self {
            Self::Consensus => CONSENSUS_KEY_PENDING_ALIAS,
            Self::Companion => COMPANION_KEY_PENDING_ALIAS,
        }
    }

    fn baker_old_alias(self) -> &'static str {
        match self {
            Self::Consensus => CONSENSUS_KEY_OLD_ALIAS,
            Self::Companion => COMPANION_KEY_OLD_ALIAS,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Consensus => "Consensus key",
            Self::Companion => "Companion key",
        }
    }

    fn pending_display_name(self) -> &'static str {
        match self {
            Self::Consensus => "Pending consensus key",
            Self::Companion => "Pending companion key",
        }
    }

    fn rpc_delegate_key_field(self) -> &'static str {
        match self {
            Self::Consensus => "consensus_key",
            Self::Companion => "companion_key",
        }
    }

    fn cli_key_kind(self) -> &'static str {
        match self {
            Self::Consensus => "consensus",
            Self::Companion => "companion",
        }
    }
}
