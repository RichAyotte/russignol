//! Migrate keys from a Nomadic Labs `tezos-rpi-bls-signer` source card.
//!
//! The source stores its two BLS keys as a stock Octez `secret_keys` wallet
//! file (`unencrypted:BLsk…`) inside an eCryptfs directory unlocked by the
//! device PIN. That plaintext shape is identical to what Russignol holds after
//! decryption, so migration is: decrypt the source, relabel the key names to
//! Russignol's `consensus`/`companion` roles, re-encrypt under a new PIN, and
//! reuse the existing card-writing pipeline via [`SourceBackup`].

use anyhow::{Context, Result, anyhow, bail};
use inquire::{Password, PasswordDisplayMode, Select};
use russignol_signer_lib::KeyManager;
use russignol_signer_lib::server::KEY_ROLES;
use russignol_signer_lib::signer::Unencrypted;
use russignol_signer_lib::wallet::StoredKey;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

use crate::config::RussignolConfig;
use crate::restore_keys::{AbortRead, CardSource, SourceBackup};
use crate::{blockchain, progress, restore_keys, utils};

/// Relative path of the signer directory on the source card's rootfs.
const SOURCE_SIGNER_DIR: &str = "home/pi/.tezos-signer-encrypted";

/// On-disk filename for Russignol's v2 encrypted secret-keys blob.
const SECRET_KEYS_ENC_V2_FILENAME: &str = "secret_keys.enc.v2";

/// Octez wallet prefix on an unencrypted secret-key value.
const UNENCRYPTED_PREFIX: &str = "unencrypted:";

/// Explicit override of which source keys fill Russignol's two roles.
///
/// A `None` field is resolved downstream (see [`resolve_role_mapping`]): by the
/// chain-registered consensus key when available, otherwise positionally (first
/// source key → consensus, second → companion).
#[derive(Debug, Default)]
pub struct RoleMapping {
    /// Source alias to use as the consensus key.
    pub consensus: Option<String>,
    /// Source alias to use as the companion key.
    pub companion: Option<String>,
}

/// A source key assigned to a Russignol role.
struct RoleAssignment {
    /// Russignol role: `consensus` or `companion`.
    role: &'static str,
    /// Original alias on the source card (e.g. `key1`).
    source_name: String,
    /// `unencrypted:BLsk…` value, carried through verbatim.
    secret_value: Zeroizing<String>,
}

/// Public material derived from a source secret key.
struct DerivedPub {
    /// Source alias on the card (e.g. `key1`).
    source_name: String,
    /// tz4 address.
    pkh: String,
    /// BLS public key, base58.
    pk: String,
}

/// Build a [`SourceBackup`] from a Nomadic source card's decrypted files.
///
/// `source_secret_keys` is the plaintext Octez `secret_keys` JSON; when
/// `source_public_key_hashs` is present it cross-checks the derived `tz4`
/// addresses against it. `chain_consensus`, when set, is the delegate's active
/// consensus key as reported by the node, used to label the matching source key
/// as consensus. The produced secret-keys blob is encrypted under `new_pin` (the
/// new Russignol PIN), independent of the source PIN.
pub fn build_migrated_backup(
    source_secret_keys: &[u8],
    source_public_key_hashs: Option<&[u8]>,
    new_pin: &[u8],
    mapping: &RoleMapping,
    chain_consensus: Option<&str>,
) -> Result<SourceBackup> {
    let entries = parse_octez_secret_keys(source_secret_keys)?;
    // Derive public material once from the secret keys themselves rather than
    // trusting the source's stored pubkey files; role resolution, the
    // cross-check, and the written public files all reuse it.
    let derived = derive_source_pubs(&entries)?;
    let resolved = resolve_role_mapping(&derived, mapping, chain_consensus);
    let assignments = assign_roles(&entries, &resolved)?;
    let source_pkh = source_public_key_hashs.map(parse_pkh_map).transpose()?;

    let mut stored = Vec::with_capacity(assignments.len());
    for a in &assignments {
        let public = derived
            .iter()
            .find(|d| d.source_name == a.source_name)
            .expect("assignment source_name is one of the derived entries");

        if let Some(map) = &source_pkh
            && let Some(expected) = map.get(&a.source_name)
            && *expected != public.pkh
        {
            bail!(
                "derived address {} for '{}' does not match source public_key_hashs ({expected}); source key material may be inconsistent",
                public.pkh,
                a.source_name
            );
        }

        stored.push(StoredKey {
            alias: a.role.to_string(),
            public_key_hash: public.pkh.clone(),
            public_key: public.pk.clone(),
            secret_key: None,
        });
    }

    let secret_keys_json = relabeled_secret_keys_json(&assignments);
    let blob = russignol_crypto::encrypt(new_pin, secret_keys_json.as_str())
        .map_err(|e| anyhow::anyhow!("failed to encrypt secret keys: {e}"))?;

    // Reuse the OCaml-format writer so the public files match Russignol's own.
    let tmp = tempfile::tempdir().context("failed to create temp dir for public keys")?;
    let manager = KeyManager::new(Some(tmp.path().to_path_buf()));
    manager
        .save_public_keys_only(&stored)
        .map_err(|e| anyhow::anyhow!("failed to write public keys: {e}"))?;
    let public_keys =
        fs::read(tmp.path().join("public_keys")).context("failed to read generated public_keys")?;
    let public_key_hashs = fs::read(tmp.path().join("public_key_hashs"))
        .context("failed to read generated public_key_hashs")?;

    Ok(SourceBackup {
        pin_blobs: vec![(SECRET_KEYS_ENC_V2_FILENAME.to_string(), blob)],
        public_keys,
        public_key_hashs,
        source_card_id: None,
        source_chain_id: None,
        source_chain_name: None,
    })
}

/// Parse an `unencrypted:BLsk…` wallet value into a signer.
fn parse_unencrypted_bls(value: &str) -> Result<Unencrypted> {
    let blsk = value
        .strip_prefix(UNENCRYPTED_PREFIX)
        .context("value is not an unencrypted secret key")?;
    Ok(Unencrypted::from_b58check(blsk)?)
}

/// Derive tz4 + public key for every source entry — the single derivation site
/// consumed by role resolution, the tamper cross-check, and the public files.
fn derive_source_pubs(entries: &[(String, Zeroizing<String>)]) -> Result<Vec<DerivedPub>> {
    entries
        .iter()
        .map(|(name, value)| {
            let signer = parse_unencrypted_bls(value)
                .with_context(|| format!("invalid BLS secret key for '{name}'"))?;
            Ok(DerivedPub {
                source_name: name.clone(),
                pkh: signer.public_key_hash().to_b58check(),
                pk: signer.public_key().to_b58check(),
            })
        })
        .collect()
}

/// Serialize role assignments as Octez `secret_keys` JSON into a single
/// pre-sized buffer.
///
/// Pre-sizing so `push_str` never reallocates keeps the plaintext in one heap
/// block that is zeroed on drop; a reallocation would copy it into a new block
/// and leave the old one un-zeroed. Role names are fixed literals and BLS
/// base58 values contain no JSON metacharacters, so no escaping is required.
fn relabeled_secret_keys_json(assignments: &[RoleAssignment]) -> Zeroizing<String> {
    let cap = 2 + assignments.len().saturating_mul(192);
    let mut json = Zeroizing::new(String::with_capacity(cap));
    json.push('[');
    for (i, a) in assignments.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push_str(r#"{"name":""#);
        json.push_str(a.role);
        json.push_str(r#"","value":""#);
        json.push_str(&a.secret_value);
        json.push_str(r#""}"#);
    }
    json.push(']');
    json
}

/// Parse an Octez `secret_keys` JSON array into `(alias, value)` pairs,
/// requiring each value to be an unencrypted BLS secret key.
fn parse_octez_secret_keys(json: &[u8]) -> Result<Vec<(String, Zeroizing<String>)>> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(json).context("source secret_keys is not valid JSON")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in &entries {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .context("source secret_keys entry missing 'name'")?;
        let value = entry
            .get("value")
            .and_then(|v| v.as_str())
            .context("source secret_keys entry missing 'value'")?;
        let blsk = value
            .strip_prefix(UNENCRYPTED_PREFIX)
            .with_context(|| format!("key '{name}' is not an unencrypted secret key"))?;
        if !blsk.starts_with("BLsk") {
            bail!("key '{name}' is not a BLS secret key (expected BLsk…)");
        }
        out.push((name.to_string(), Zeroizing::new(value.to_string())));
    }
    Ok(out)
}

/// Resolve which source key fills each role, in precedence order: explicit
/// overrides, then the chain-registered consensus key, then unresolved (left for
/// positional assignment).
///
/// Overrides may name a source alias or a tz4 address. Chain detection applies
/// only when no override is given and exactly one source key matches the
/// delegate's active consensus key, so a wrong delegate can never mislabel.
fn resolve_role_mapping(
    derived: &[DerivedPub],
    explicit: &RoleMapping,
    chain_consensus: Option<&str>,
) -> RoleMapping {
    // Map an override (alias or tz4) to a source alias; keep it verbatim when it
    // matches nothing so `assign_roles` reports a clear "no key named" error.
    let normalize = |key: &String| source_alias_for(derived, key).unwrap_or_else(|| key.clone());
    let consensus = explicit.consensus.as_ref().map(&normalize);
    let companion = explicit.companion.as_ref().map(&normalize);

    if consensus.is_none()
        && companion.is_none()
        && let Some(target) = chain_consensus
    {
        let mut matches = derived.iter().filter(|d| d.pkh == target);
        if let (Some(only), None) = (matches.next(), matches.next()) {
            return RoleMapping {
                consensus: Some(only.source_name.clone()),
                companion: None,
            };
        }
    }
    RoleMapping {
        consensus,
        companion,
    }
}

/// Resolve a user-supplied key reference (a source alias or a tz4 address) to
/// the matching source alias, if any.
fn source_alias_for(derived: &[DerivedPub], key: &str) -> Option<String> {
    derived
        .iter()
        .find(|d| d.source_name == key || d.pkh == key)
        .map(|d| d.source_name.clone())
}

/// Assign source keys to the consensus/companion roles in canonical order.
fn assign_roles(
    entries: &[(String, Zeroizing<String>)],
    mapping: &RoleMapping,
) -> Result<Vec<RoleAssignment>> {
    let (consensus_name, companion_name) = match (&mapping.consensus, &mapping.companion) {
        // No overrides: require exactly two keys and map positionally.
        (None, None) => {
            if entries.len() != 2 {
                bail!(
                    "expected exactly 2 keys on the source card, found {} (use --consensus-key/--companion-key to disambiguate)",
                    entries.len()
                );
            }
            (entries[0].0.clone(), entries[1].0.clone())
        }
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        // One role given: the other defaults to the remaining key.
        (Some(c), None) => (c.clone(), remaining_source_key(entries, c)?),
        (None, Some(k)) => (remaining_source_key(entries, k)?, k.clone()),
    };
    if consensus_name == companion_name {
        bail!("consensus and companion cannot both be source key '{consensus_name}'");
    }

    let find = |name: &str| -> Result<Zeroizing<String>> {
        entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .with_context(|| format!("source card has no key named '{name}'"))
    };

    Ok(vec![
        RoleAssignment {
            role: KEY_ROLES[0],
            secret_value: find(&consensus_name)?,
            source_name: consensus_name,
        },
        RoleAssignment {
            role: KEY_ROLES[1],
            secret_value: find(&companion_name)?,
            source_name: companion_name,
        },
    ])
}

/// The first source key whose alias differs from `taken` — the remaining key
/// when only one role was specified explicitly.
fn remaining_source_key(entries: &[(String, Zeroizing<String>)], taken: &str) -> Result<String> {
    entries
        .iter()
        .map(|(n, _)| n)
        .find(|n| n.as_str() != taken)
        .cloned()
        .context("only one key resolves; assign roles with --consensus-key/--companion-key")
}

/// Map source alias → `tz4` address from an Octez `public_key_hashs` file.
fn parse_pkh_map(json: &[u8]) -> Result<HashMap<String, String>> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(json).context("source public_key_hashs is not valid JSON")?;
    let mut map = HashMap::new();
    for entry in &entries {
        if let (Some(name), Some(value)) = (
            entry.get("name").and_then(|v| v.as_str()),
            entry.get("value").and_then(|v| v.as_str()),
        ) {
            map.insert(name.to_string(), value.to_string());
        }
    }
    Ok(map)
}

/// Prompt for the baker delegate whose active on-chain consensus key labels the
/// roles, picking from the wallet's known addresses. Returns the chosen delegate
/// address, or `None` to fall back to positional assignment (the user skipped,
/// or the wallet has no listable addresses).
///
/// Selection is a local wallet read; only the caller's follow-up consensus-key
/// fetch touches the node — one RPC instead of probing every wallet address.
fn prompt_delegate(config: &RussignolConfig) -> Result<Option<String>> {
    const SKIP: &str = "Assign roles by source-card key order (no on-chain lookup)";

    let addresses = match blockchain::list_known_addresses(config) {
        Ok(addresses) if !addresses.is_empty() => addresses,
        _ => {
            utils::info("No known baker addresses; assigning roles by source-card key order.");
            return Ok(None);
        }
    };

    let mut options = Vec::with_capacity(addresses.len() + 1);
    options.push(SKIP.to_string());
    options.extend(
        addresses
            .iter()
            .map(|(alias, address)| format!("{alias} ({address})")),
    );

    // Cancelling (Esc/Ctrl-C) aborts the migration, like the PIN prompts; the
    // SKIP option is the way to opt out of on-chain labeling and keep going.
    let choice = Select::new(
        "Select your baker delegate to label keys by on-chain role:",
        options,
    )
    .with_help_message("type to filter, ↑↓ to navigate, Enter to select")
    .with_render_config(utils::create_orange_theme())
    .prompt()
    .context("failed to select delegate")?;

    if choice == SKIP {
        return Ok(None);
    }
    Ok(addresses
        .into_iter()
        .find(|(alias, address)| format!("{alias} ({address})") == choice)
        .map(|(_, address)| address))
}

/// Resolve the on-chain consensus key used to label roles: prompt for the
/// delegate, then a single RPC for its active consensus key. `Ok(None)`
/// (positional fallback) when the user picks SKIP or the lookup fails; an error
/// only when the user cancels the prompt.
fn resolve_delegate_consensus(config: &RussignolConfig) -> Result<Option<String>> {
    let Some(delegate) = prompt_delegate(config)? else {
        return Ok(None);
    };
    let spinner = progress::create_spinner("Fetching the delegate's on-chain consensus key...");
    let consensus = blockchain::get_active_consensus_key(&delegate, config);
    spinner.finish_and_clear();
    Ok(match consensus {
        Ok(pkh) => Some(pkh),
        Err(e) => {
            utils::warning(&format!(
                "Could not read the delegate's consensus key ({e:#}); \
                 assigning roles by source-card key order."
            ));
            None
        }
    })
}

/// Kernel eCryptfs mount options for a `mount -i` (helper-bypassing) mount:
/// AES with a 16-byte key, matching how `tezos-rpi-bls-signer` encrypts the
/// signer directory. Plaintext filenames are the default (no `ecryptfs_fnek_sig`),
/// and `ecryptfs_unlink_sigs` drops the key from the keyring on unmount.
///
/// The passphrase-derived key is added to the keyring separately (see
/// [`mount_ecryptfs`]) and referenced by `ecryptfs_sig` at mount time, so the
/// PIN never appears in these options or the `mount` arguments (`ps`/`/proc`).
fn ecryptfs_options() -> String {
    "ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_unlink_sigs".to_string()
}

/// Check tools required for migration beyond the restore toolchain.
///
/// `ecryptfs-add-passphrase` decrypts the source signer dir; `blkid` identifies
/// the physical card for the single-reader swap guard (a missing `blkid` would
/// silently disable that guard, so it is required, not optional).
pub fn check_migrate_tools() -> Result<()> {
    restore_keys::check_restore_tools()?;
    let missing: Vec<&str> = ["ecryptfs-add-passphrase", "blkid"]
        .into_iter()
        .filter(|tool| utils::resolve_tool(tool).is_none())
        .collect();
    if !missing.is_empty() {
        bail!(
            "Required tools not found: {}.\n  Install with:\n    \
             sudo apt install ecryptfs-utils util-linux  (Debian/Ubuntu)",
            missing.join(", ")
        );
    }
    Ok(())
}

/// Why reading a Nomadic source card failed, which decides how the caller
/// recovers: re-prompt the PIN, prompt for a different card, or abort.
enum NomadicReadError {
    /// The source PIN did not decrypt the card; prompting again may succeed.
    WrongPin(anyhow::Error),
    /// Not a readable Nomadic source card (no rootfs or signer dir); a different
    /// card may work.
    WrongCard(anyhow::Error),
    /// An environment/mount failure (e.g. missing eCryptfs kernel module) or bad
    /// key content that neither a new PIN nor a different card fixes; abort.
    Fatal(anyhow::Error),
}

/// New-PIN length limits, mirroring the on-device keypad
/// (`rpi-signer/src/pages/pin.rs`) so the user can type the same PIN there.
const MIN_DEVICE_PIN_LEN: usize = 5;
const MAX_DEVICE_PIN_LEN: usize = 10;

/// A migration source: a Nomadic Labs `tezos-rpi-bls-signer` card whose keys
/// are decrypted under the source PIN and re-encrypted under a new russignol PIN.
pub(crate) struct MigrateSource {
    /// Source card PIN — an eCryptfs passphrase, used as the literal string.
    source_pin: Zeroizing<String>,
    /// New russignol PIN, encoded as the device stores it (see [`encode_device_pin`]).
    new_pin: Zeroizing<Vec<u8>>,
    mapping: RoleMapping,
    /// The delegate's active on-chain consensus key (tz4), captured up front to
    /// label the matching source key as consensus. `None` => positional fallback.
    chain_consensus: Option<String>,
}

impl MigrateSource {
    /// Build a migration source: verify the migration toolchain, prompt for the
    /// source and new PINs, and capture the role mapping from the optional
    /// `--consensus-key`/`--companion-key` aliases.
    pub(crate) fn prompt(
        consensus_key: Option<String>,
        companion_key: Option<String>,
        config: Option<RussignolConfig>,
    ) -> Result<Self> {
        check_migrate_tools()?;
        // Migration needs root only to mount the source's eCryptfs directory and
        // read the signer's `pi`-owned files; cache sudo credentials up front and
        // escalate just those steps, rather than running the whole flash as root.
        utils::info("Migration needs sudo to mount and decrypt the source card.");
        utils::ensure_sudo()?;
        let source_pin = prompt_pin("Source card PIN:", false)?;
        let new_pin = prompt_new_device_pin()?;
        let mapping = RoleMapping {
            consensus: consensus_key,
            companion: companion_key,
        };
        // On-chain role labeling only changes the outcome when neither role was
        // pinned explicitly (see `resolve_role_mapping`); skip the delegate
        // prompt and its RPC otherwise.
        let chain_consensus = match config {
            Some(c) if mapping.consensus.is_none() && mapping.companion.is_none() => {
                resolve_delegate_consensus(&c)?
            }
            _ => None,
        };
        Ok(Self {
            source_pin,
            new_pin,
            mapping,
            chain_consensus,
        })
    }
}

/// Prompt (with confirmation) for the new russignol PIN and return it encoded
/// the way the device stores it, re-prompting until it is a valid digit PIN.
fn prompt_new_device_pin() -> Result<Zeroizing<Vec<u8>>> {
    loop {
        let entry = prompt_pin(
            &format!("New russignol PIN ({MIN_DEVICE_PIN_LEN}-{MAX_DEVICE_PIN_LEN} digits):"),
            true,
        )?;
        match encode_device_pin(&entry) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => utils::warning(&format!("{e}")),
        }
    }
}

/// Encode a numeric PIN the way the russignol device does: each digit as its
/// raw value (`'1'` -> `1u8`), matching the touchscreen keypad in
/// `rpi-signer/src/pages/pin.rs`. The migrated keys are encrypted under these
/// bytes, so the PIN the user types on the device decrypts them — encrypting
/// under the ASCII digits instead yields a different scrypt key and "invalid PIN".
fn encode_device_pin(pin: &str) -> Result<Zeroizing<Vec<u8>>> {
    if !pin.bytes().all(|b| b.is_ascii_digit()) {
        bail!("PIN must contain only digits 0-9");
    }
    if !(MIN_DEVICE_PIN_LEN..=MAX_DEVICE_PIN_LEN).contains(&pin.len()) {
        bail!("PIN must be {MIN_DEVICE_PIN_LEN}-{MAX_DEVICE_PIN_LEN} digits");
    }
    Ok(Zeroizing::new(pin.bytes().map(|b| b - b'0').collect()))
}

impl CardSource for MigrateSource {
    fn read(&self, device: &Path) -> Result<SourceBackup> {
        let mut source_pin = self.source_pin.clone();
        loop {
            let spinner = progress::create_spinner("Reading source card...");
            let result = read_nomadic_source(
                device,
                source_pin.as_bytes(),
                self.new_pin.as_slice(),
                &self.mapping,
                self.chain_consensus.as_deref(),
            );
            spinner.finish_and_clear();
            match result {
                Ok(backup) => return Ok(backup),
                Err(NomadicReadError::WrongPin(e)) => {
                    utils::warning(&format!(
                        "Could not decrypt the source card: {e:#}\n  \
                         Re-enter the source PIN."
                    ));
                    source_pin = prompt_pin("Source card PIN:", false)?;
                }
                // A different card may be the right source, so let the caller
                // prompt for a swap.
                Err(NomadicReadError::WrongCard(e)) => return Err(e),
                // Neither a new PIN nor a different card helps; abort the flash.
                Err(NomadicReadError::Fatal(e)) => return Err(AbortRead(e).into()),
            }
        }
    }

    fn identity(&self, device: &Path) -> Option<String> {
        utils::source_disk_ptuuid(device)
    }

    fn noun(&self) -> &'static str {
        "migrate"
    }
}

/// Prompt for a PIN, optionally requiring confirmation entry.
fn prompt_pin(message: &str, confirm: bool) -> Result<Zeroizing<String>> {
    let mut prompt = Password::new(message)
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_render_config(utils::create_orange_theme());
    if !confirm {
        prompt = prompt.without_confirmation();
    }
    Ok(Zeroizing::new(
        prompt.prompt().context("failed to read PIN")?,
    ))
}

/// Mount the source rootfs read-only, decrypt the signer dir, and build the
/// migrated backup. The source card is never written to.
fn read_nomadic_source(
    source_device: &Path,
    source_pin: &[u8],
    new_pin: &[u8],
    mapping: &RoleMapping,
    chain_consensus: Option<&str>,
) -> Result<SourceBackup, NomadicReadError> {
    let p2 = utils::get_partition_path(source_device, 2);
    if !p2.exists() {
        return Err(NomadicReadError::WrongCard(anyhow!(
            "source rootfs partition not found: {}",
            p2.display()
        )));
    }
    let rootfs = utils::mount_partition(&p2, "ext4", true)
        .context("failed to mount source rootfs (partition 2)")
        .map_err(NomadicReadError::WrongCard)?;

    let result = (|| {
        let enc_dir = rootfs.join(SOURCE_SIGNER_DIR);
        if !enc_dir.is_dir() {
            return Err(NomadicReadError::WrongCard(anyhow!(
                "signer directory not found at {} (is this a tezos-rpi-bls-signer card?)",
                enc_dir.display()
            )));
        }
        decrypt_and_build(&enc_dir, source_pin, new_pin, mapping, chain_consensus)
    })();

    match result {
        Ok(backup) => {
            utils::unmount_partition(&rootfs, &p2).map_err(NomadicReadError::Fatal)?;
            Ok(backup)
        }
        Err(e) => {
            let _ = utils::unmount_partition(&rootfs, &p2);
            Err(e)
        }
    }
}

/// Copy the encrypted signer dir into a temp lower dir, eCryptfs-mount it, and
/// build the backup from the decrypted `secret_keys`.
fn decrypt_and_build(
    enc_dir: &Path,
    source_pin: &[u8],
    new_pin: &[u8],
    mapping: &RoleMapping,
    chain_consensus: Option<&str>,
) -> Result<SourceBackup, NomadicReadError> {
    let work = tempfile::tempdir()
        .context("failed to create work dir")
        .map_err(NomadicReadError::Fatal)?;
    let lower = work.path().join("lower");
    let plain = work.path().join("plain");
    fs::create_dir(&lower)
        .context("failed to create lower dir")
        .map_err(NomadicReadError::Fatal)?;
    fs::create_dir(&plain)
        .context("failed to create plain dir")
        .map_err(NomadicReadError::Fatal)?;
    copy_files(enc_dir, &lower).map_err(NomadicReadError::Fatal)?;

    mount_ecryptfs(&lower, &plain, source_pin).map_err(NomadicReadError::Fatal)?;

    let result = (|| {
        // eCryptfs accepts any passphrase at mount time, so a wrong source PIN
        // surfaces here as an unreadable or non-JSON payload — treat both as a
        // PIN error so the caller can re-prompt.
        let secret_keys = Zeroizing::new(
            fs::read(plain.join("secret_keys"))
                .context("decrypted secret_keys unreadable (wrong source PIN?)")
                .map_err(NomadicReadError::WrongPin)?,
        );
        if serde_json::from_slice::<serde_json::Value>(secret_keys.as_slice()).is_err() {
            return Err(NomadicReadError::WrongPin(anyhow!(
                "decrypted secret_keys is not valid JSON (wrong source PIN?)"
            )));
        }
        let pkh = fs::read(plain.join("public_key_hashs")).ok();
        // The PIN is correct past this point; a build failure is a genuine
        // content problem, not something re-prompting can fix.
        build_migrated_backup(
            secret_keys.as_slice(),
            pkh.as_deref(),
            new_pin,
            mapping,
            chain_consensus,
        )
        .map_err(NomadicReadError::Fatal)
    })();

    // The decrypted eCryptfs view exposes plaintext key material. If it will
    // not unmount, fail closed: disarm the TempDir so its recursive delete does
    // not run through a live mount, and tell the operator to clear it by hand.
    if let Err(e) = umount(&plain) {
        let plain_display = plain.display().to_string();
        let _ = work.keep();
        return Err(NomadicReadError::Fatal(anyhow!(
            "Failed to unmount decrypted key material at {plain_display}: {e:#}. \
             Plaintext keys may remain mounted — unmount it and remove the directory manually."
        )));
    }
    result
}

/// Copy the regular files of `src` into `dst` (the signer dir is flat).
///
/// The source files are owned by the signer's `pi` user and unreadable by the
/// invoking user, so their contents are read via sudo; the copies in `dst` are
/// written as the invoking user, which makes the decrypted eCryptfs files
/// user-owned too — so the later read and temp-dir cleanup need no privilege.
fn copy_files(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let bytes = sudo_read_file(&entry.path())?;
            fs::write(dst.join(entry.file_name()), &bytes)
                .with_context(|| format!("failed to copy {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Read a file via sudo (the source signer files are owned by `pi`).
fn sudo_read_file(path: &Path) -> Result<Vec<u8>> {
    let output = Command::new("sudo")
        .arg("cat")
        .arg(path)
        .output()
        .with_context(|| format!("failed to run sudo cat {}", path.display()))?;
    if !output.status.success() {
        bail!(
            "could not read {}: {}",
            path.display(),
            command_failure_detail(&output)
        );
    }
    Ok(output.stdout)
}

/// One privileged shell that adds the passphrase to the kernel keyring and
/// mounts by the resulting signature with `mount -i`.
///
/// The stock `mount.ecryptfs` helper's passphrase-key setup fails on some
/// ecryptfs-utils/kernel combinations (an internal error while "evaluating mount
/// options"), so `ecryptfs-add-passphrase -` inserts the key (printing
/// `... sig [<hex>] ...`) and `mount -i` bypasses the helper, letting the kernel
/// find the key by `ecryptfs_sig`. Both run in one shell so the inserted key is
/// in the keyring the mount searches. lower/plain/options arrive as positional
/// args ($1/$2/$3), never interpolated, so paths can't inject into the script.
///
/// The trailing `-` is load-bearing: without it the tool reads the passphrase
/// via `getpass()` from `/dev/tty` and ignores the PIN piped to stdin, silently
/// prompting on the terminal (hidden behind the reader spinner) and hanging.
const ECRYPTFS_MOUNT_SCRIPT: &str = r#"set -eu
sig=$(ecryptfs-add-passphrase - | sed -n 's/.*\[\([0-9a-f]*\)\].*/\1/p')
[ -n "$sig" ] || { echo 'ecryptfs-add-passphrase returned no signature' >&2; exit 1; }
exec mount -i -t ecryptfs "$1" "$2" -o "ecryptfs_sig=$sig,$3"
"#;

fn mount_ecryptfs(lower: &Path, plain: &Path, pin: &[u8]) -> Result<()> {
    // `mount -t ecryptfs` does not reliably auto-load the module; load it
    // best-effort. A genuine "module unavailable" still surfaces from the mount.
    let _ = Command::new("sudo").args(["modprobe", "ecryptfs"]).output();

    let mut child = Command::new("sudo")
        .arg("bash")
        .arg("-c")
        .arg(ECRYPTFS_MOUNT_SCRIPT)
        .arg("russignol-ecryptfs")
        .arg(lower)
        .arg(plain)
        .arg(ecryptfs_options())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run the eCryptfs mount")?;

    // `ecryptfs-add-passphrase` reads the passphrase from stdin until EOF, so
    // write the PIN (no trailing newline) and drop the pipe. sudo forwards stdin
    // to the script because credentials are pre-cached (see `MigrateSource::prompt`),
    // so sudo never consumes it for its own password prompt.
    child
        .stdin
        .take()
        .context("failed to open mount stdin")?
        .write_all(pin)
        .context("failed to send passphrase")?;

    let output = child
        .wait_with_output()
        .context("failed to run the eCryptfs mount")?;
    if !output.status.success() {
        bail!(
            "failed to mount the source's encrypted signer directory (eCryptfs): {}\n  \
             Ensure the eCryptfs kernel module is available (try: sudo modprobe ecryptfs).",
            command_failure_detail(&output)
        );
    }
    Ok(())
}

/// Combine a failed command's stderr and stdout into a single detail string,
/// falling back to the exit status when both streams are empty.
fn command_failure_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = [stderr.trim(), stdout.trim()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    if detail.is_empty() {
        format!("{}", output.status)
    } else {
        detail
    }
}

fn umount(mount_point: &Path) -> Result<()> {
    let output = Command::new("sudo")
        .arg("umount")
        .arg(mount_point)
        .output()
        .context("failed to run sudo umount")?;
    if !output.status.success() {
        bail!("umount failed: {}", command_failure_detail(&output));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_pin_encodes_digits_as_raw_values() {
        // Must match the device keypad, which pushes each digit's numeric value.
        assert_eq!(
            encode_device_pin("50412").unwrap().as_slice(),
            &[5, 0, 4, 1, 2]
        );
        assert!(encode_device_pin("1234").is_err()); // too short
        assert!(encode_device_pin("12345678901").is_err()); // too long
        assert!(encode_device_pin("12a45").is_err()); // non-digit
        assert!(encode_device_pin("").is_err());
    }

    #[test]
    fn ecryptfs_options_never_carry_the_passphrase() {
        let opts = ecryptfs_options();
        // The key reaches the mount via ecryptfs_sig (added to the keyring from
        // stdin), never as a passphrase option.
        assert!(
            !opts.contains("passphrase") && !opts.contains("passwd"),
            "the PIN must be fed via the keyring, not inlined as a mount option: {opts}"
        );
        assert!(opts.contains("ecryptfs_cipher=aes"));
        assert!(opts.contains("ecryptfs_key_bytes=16"));
    }

    #[test]
    fn mount_script_reads_passphrase_from_stdin_not_the_tty() {
        // Without the trailing `-`, ecryptfs-add-passphrase prompts via
        // getpass() on /dev/tty and ignores the PIN we pipe, hanging behind the
        // spinner when a controlling terminal is present.
        assert!(
            ECRYPTFS_MOUNT_SCRIPT.contains("ecryptfs-add-passphrase -"),
            "mount script must pass `-` so the passphrase is read from stdin: {ECRYPTFS_MOUNT_SCRIPT}"
        );
    }

    /// Extract the error from a result whose `Ok` type isn't `Debug`.
    fn expect_err(result: Result<SourceBackup>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    /// Derive a `(BLsk, tz4)` pair deterministically from a 32-byte seed.
    fn key_from_seed(seed: u8) -> (String, String) {
        let signer = Unencrypted::generate(Some(&[seed; 32])).unwrap();
        (
            signer.secret_key().to_b58check(),
            signer.public_key_hash().to_b58check(),
        )
    }

    /// Build an Octez `secret_keys` JSON from `(alias, BLsk)` pairs.
    fn secret_keys_json(keys: &[(&str, &str)]) -> Vec<u8> {
        let arr: Vec<serde_json::Value> = keys
            .iter()
            .map(|(name, blsk)| {
                serde_json::json!({"name": name, "value": format!("unencrypted:{blsk}")})
            })
            .collect();
        serde_json::to_vec(&arr).unwrap()
    }

    /// Build an Octez `public_key_hashs` JSON from `(alias, tz4)` pairs.
    fn pkh_json(keys: &[(&str, &str)]) -> Vec<u8> {
        let arr: Vec<serde_json::Value> = keys
            .iter()
            .map(|(name, tz4)| serde_json::json!({"name": name, "value": tz4}))
            .collect();
        serde_json::to_vec(&arr).unwrap()
    }

    #[test]
    fn maps_two_keys_positionally_to_consensus_companion() {
        let (sk1, tz1) = key_from_seed(1);
        let (sk2, tz2) = key_from_seed(2);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);

        let backup =
            build_migrated_backup(&src, None, b"12345678", &RoleMapping::default(), None).unwrap();

        assert_eq!(backup.pin_blobs.len(), 1);
        assert_eq!(backup.pin_blobs[0].0, SECRET_KEYS_ENC_V2_FILENAME);

        let plaintext = russignol_crypto::decrypt(b"12345678", &backup.pin_blobs[0].1).unwrap();
        assert!(plaintext.contains(r#""name":"consensus""#));
        assert!(plaintext.contains(r#""name":"companion""#));
        assert!(plaintext.contains(&format!("unencrypted:{sk1}")));
        assert!(plaintext.contains(&format!("unencrypted:{sk2}")));

        let pkh = String::from_utf8(backup.public_key_hashs.clone()).unwrap();
        assert!(pkh.contains(&tz1));
        assert!(pkh.contains(&tz2));
        assert!(pkh.contains("consensus"));
        assert!(pkh.contains("companion"));
    }

    #[test]
    fn overrides_select_roles_by_source_name() {
        let (sk1, tz1) = key_from_seed(3);
        let (sk2, tz2) = key_from_seed(4);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);
        let mapping = RoleMapping {
            consensus: Some("key2".to_string()),
            companion: Some("key1".to_string()),
        };

        let backup = build_migrated_backup(&src, None, b"0000", &mapping, None).unwrap();
        let plaintext = russignol_crypto::decrypt(b"0000", &backup.pin_blobs[0].1).unwrap();

        // consensus comes first; key2 was designated consensus.
        let consensus_pos = plaintext.find("consensus").unwrap();
        let sk2_pos = plaintext.find(&sk2 as &str).unwrap();
        let sk1_pos = plaintext.find(&sk1 as &str).unwrap();
        assert!(consensus_pos < sk2_pos);
        assert!(sk2_pos < sk1_pos);
        let _ = (tz1, tz2);
    }

    #[test]
    fn cross_check_rejects_tampered_source_pkh() {
        let (sk1, _tz1) = key_from_seed(5);
        let (sk2, tz2) = key_from_seed(6);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);
        // key1's recorded tz4 is wrong (reuses key2's address).
        let bad_pkh = pkh_json(&[("key1", &tz2), ("key2", &tz2)]);

        let err = expect_err(build_migrated_backup(
            &src,
            Some(&bad_pkh),
            b"1234",
            &RoleMapping::default(),
            None,
        ));
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn cross_check_passes_with_matching_source_pkh() {
        let (sk1, tz1) = key_from_seed(7);
        let (sk2, tz2) = key_from_seed(8);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);
        let good_pkh = pkh_json(&[("key1", &tz1), ("key2", &tz2)]);

        build_migrated_backup(
            &src,
            Some(&good_pkh),
            b"1234",
            &RoleMapping::default(),
            None,
        )
        .unwrap();
    }

    #[test]
    fn rejects_non_bls_secret_key() {
        let src = secret_keys_json(&[("key1", "edsk000notbls"), ("key2", "edsk111notbls")]);
        let err = expect_err(build_migrated_backup(
            &src,
            None,
            b"1234",
            &RoleMapping::default(),
            None,
        ));
        assert!(err.to_string().contains("BLS"));
    }

    #[test]
    fn rejects_wrong_key_count_without_overrides() {
        let (sk1, _tz1) = key_from_seed(9);
        let src = secret_keys_json(&[("key1", &sk1)]);
        let err = expect_err(build_migrated_backup(
            &src,
            None,
            b"1234",
            &RoleMapping::default(),
            None,
        ));
        assert!(err.to_string().contains("expected exactly 2 keys"));
    }

    /// The tz4 the built backup labels as `consensus`, read from the generated
    /// `public_key_hashs`.
    fn consensus_tz4(backup: &SourceBackup) -> String {
        let arr: Vec<serde_json::Value> = serde_json::from_slice(&backup.public_key_hashs).unwrap();
        arr.iter()
            .find(|e| e.get("name").and_then(|v| v.as_str()) == Some("consensus"))
            .and_then(|e| e.get("value").and_then(|v| v.as_str()))
            .unwrap()
            .to_string()
    }

    #[test]
    fn chain_detection_labels_matching_source_key_as_consensus() {
        let (sk1, _tz1) = key_from_seed(10);
        let (sk2, tz2) = key_from_seed(11);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);

        // The chain reports key2's tz4 as the registered consensus key,
        // overriding the positional key1->consensus default.
        let backup =
            build_migrated_backup(&src, None, b"1234", &RoleMapping::default(), Some(&tz2))
                .unwrap();
        assert_eq!(consensus_tz4(&backup), tz2);
    }

    #[test]
    fn chain_detection_without_match_falls_back_to_positional() {
        let (sk1, tz1) = key_from_seed(12);
        let (sk2, _tz2) = key_from_seed(13);
        let (_sk3, unrelated_tz) = key_from_seed(14);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);

        // No source key matches the chain's consensus key, so positional applies.
        let backup = build_migrated_backup(
            &src,
            None,
            b"1234",
            &RoleMapping::default(),
            Some(&unrelated_tz),
        )
        .unwrap();
        assert_eq!(consensus_tz4(&backup), tz1);
    }

    #[test]
    fn explicit_override_takes_precedence_over_chain_detection() {
        let (sk1, tz1) = key_from_seed(15);
        let (sk2, tz2) = key_from_seed(16);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);
        let mapping = RoleMapping {
            consensus: Some("key1".to_string()),
            companion: None,
        };

        // The chain would pick key2, but the explicit override wins.
        let backup = build_migrated_backup(&src, None, b"1234", &mapping, Some(&tz2)).unwrap();
        assert_eq!(consensus_tz4(&backup), tz1);
    }

    #[test]
    fn override_by_tz4_selects_matching_key() {
        let (sk1, _tz1) = key_from_seed(17);
        let (sk2, tz2) = key_from_seed(18);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);
        // Users know their tz4 addresses, not the source's key1/key2 aliases.
        let mapping = RoleMapping {
            consensus: Some(tz2.clone()),
            companion: None,
        };

        let backup = build_migrated_backup(&src, None, b"1234", &mapping, None).unwrap();
        assert_eq!(consensus_tz4(&backup), tz2);
    }

    #[test]
    fn companion_only_override_defaults_consensus_to_remaining_key() {
        let (sk1, _tz1) = key_from_seed(19);
        let (sk2, tz2) = key_from_seed(20);
        let src = secret_keys_json(&[("key1", &sk1), ("key2", &sk2)]);
        // Only companion given, naming the first source key; consensus must
        // default to the other key rather than colliding.
        let mapping = RoleMapping {
            consensus: None,
            companion: Some("key1".to_string()),
        };

        let backup = build_migrated_backup(&src, None, b"1234", &mapping, None).unwrap();
        assert_eq!(consensus_tz4(&backup), tz2);
    }
}
