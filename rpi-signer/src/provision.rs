//! Adding or replacing one device key after first boot.
//!
//! First boot generates the card's BLS keys in one pass
//! (`generate_and_encrypt_keys`). This module is the other entry: one key of
//! one scheme, generated onto a card whose other keys stay exactly as they
//! are — the annual XMSS epoch rotation, and a scheme parameter change that
//! invalidates every key already generated.

use crate::secret::Secret;
use russignol_signer_lib::durable::atomic_write;
use russignol_signer_lib::signer::Unencrypted;
use russignol_signer_lib::wallet::{self, SecretKeyEntry};
use russignol_signer_lib::{DeviceKey, KeyManager, KeyRole, StoredKey, xmss};
use std::borrow::Cow;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// One entry of the secret-key store, paired with the public material its
/// secret derives.
///
/// The secret is borrowed rather than re-encoded, so an entry a provisioning
/// run does not touch reaches the new store as the bytes it was read as and no
/// key the operator did not name can be rewritten.
pub struct Entry<'a> {
    /// The name the store files this key under.
    pub alias: Cow<'a, str>,
    /// The base58 secret, without the store's `unencrypted:` prefix.
    pub secret: &'a str,
    /// The base58 public key this entry's secret derives.
    pub public_key: String,
    /// The base58 address this entry's secret derives.
    pub public_key_hash: String,
}

impl<'a> Entry<'a> {
    /// Pair an alias and its secret with the public material `signer` derives.
    ///
    /// `signer` is what `secret` loads to, so the public material and the
    /// secret filed beside it are one key's by construction.
    fn new(alias: Cow<'a, str>, secret: &'a str, signer: &Unencrypted) -> Self {
        Self {
            alias,
            secret,
            public_key: signer.public_key().to_b58check(),
            public_key_hash: signer.public_key_hash().to_b58check(),
        }
    }

    /// This entry's public half, as the wallet files hold it.
    fn to_stored_key(&self) -> StoredKey {
        StoredKey {
            alias: self.alias.to_string(),
            public_key_hash: self.public_key_hash.clone(),
            public_key: self.public_key.clone(),
            secret_key: None,
        }
    }

    /// The device key this entry's alias names, if any.
    fn device_key(&self) -> Option<DeviceKey> {
        DeviceKey::from_device_alias(&self.alias)
    }
}

/// Freshly generated material for one device key, held until it is filed.
///
/// The secret is owned here so the store built from it borrows rather than
/// copies, and it is zeroized when this value drops.
pub struct Generated {
    key: DeviceKey,
    signer: Unencrypted,
    secret: Zeroizing<String>,
}

/// What one provisioning run generates.
///
/// The span rides on the arm that spends epochs, so a BLS key cannot be asked
/// for over a span its scheme never spends.
pub enum Provisioning {
    /// A BLS key in one role.
    Bls(KeyRole),
    /// The XMSS consensus key, over the span of one-time keys it will hold.
    ///
    /// The span is the caller's because it is baked into the key: the card is
    /// rotated when the span runs out, and a span wide enough to deploy costs
    /// tens of minutes to walk.
    Xmss(std::ops::RangeInclusive<xmss::Epoch>),
}

impl Provisioning {
    /// The device key this run fills.
    #[must_use]
    pub const fn device_key(&self) -> DeviceKey {
        match self {
            Self::Bls(role) => DeviceKey::Bls(*role),
            Self::Xmss(_) => DeviceKey::XmssConsensus,
        }
    }
}

impl Generated {
    /// # Errors
    ///
    /// Returns an error if generation fails or an XMSS span is empty.
    pub fn new(what: Provisioning) -> Result<Self, String> {
        let key = what.device_key();
        let signer = match what {
            Provisioning::Bls(_) => Unencrypted::generate(None),
            Provisioning::Xmss(epochs) => Unencrypted::generate_xmss(epochs),
        }
        .map_err(|e| format!("Failed to generate the {} key: {e}", key.device_alias()))?;
        let secret = Zeroizing::new(signer.secret_key().to_b58check());
        Ok(Self {
            key,
            signer,
            secret,
        })
    }

    /// This key as the store files it.
    #[must_use]
    pub fn entry(&self) -> Entry<'_> {
        Entry::new(
            Cow::Borrowed(self.key.device_alias()),
            &self.secret,
            &self.signer,
        )
    }
}

/// Read a decrypted secret-key store into its entries.
///
/// # Errors
///
/// Returns an error if the store does not parse or any secret does not load. A
/// key that fails to load aborts rather than being dropped, since dropping it
/// writes the card back without a key it arrived holding.
pub fn read_store(store: &str) -> Result<Vec<Entry<'_>>, String> {
    crate::signer_server::parse_store(store)?
        .into_iter()
        .map(|entry| {
            let (secret, signer) = crate::signer_server::load_entry(&entry)?;
            Ok(Entry::new(entry.name, secret, &signer))
        })
        .collect()
}

/// `entries` with `generated`'s slot taken by it, in device-key order.
///
/// Every entry resolving to that device key is replaced, so a card carrying a
/// pre-suffix spelling beside the canonical one comes out holding one key in
/// the slot rather than two. An entry no device key claims keeps its place
/// after the ones that do: a key the operator put there is not one this run
/// was asked to remove.
#[must_use]
pub fn with_key_provisioned<'a>(
    entries: Vec<Entry<'a>>,
    generated: &'a Generated,
) -> Vec<Entry<'a>> {
    let mut kept: Vec<(Option<DeviceKey>, Entry<'a>)> = entries
        .into_iter()
        .map(|entry| (entry.device_key(), entry))
        .filter(|(key, _)| *key != Some(generated.key))
        .collect();
    kept.push((Some(generated.key), generated.entry()));
    kept.sort_by_key(|(key, _)| key.map_or(DeviceKey::COUNT, DeviceKey::index));
    kept.into_iter().map(|(_, entry)| entry).collect()
}

/// The `secret_keys` array for `entries`, through the one emitter the host's
/// migration writes its stores with, so a card written by either reads back
/// under the other.
#[must_use]
pub fn build_secret_keys_json(entries: &[Entry<'_>]) -> Secret<String> {
    let entries: Vec<SecretKeyEntry<'_>> = entries
        .iter()
        .map(|entry| SecretKeyEntry {
            alias: &entry.alias,
            secret: entry.secret,
        })
        .collect();
    Secret::from_zeroizing(wallet::secret_keys_json(&entries))
}

/// Write `entries` as the card's key store, encrypted under `pin` into
/// `blob`, and hand back the plaintext that was written.
///
/// The wallet files land in the directory holding `blob`, which is what makes
/// the two halves of a store one path's business.
///
/// The encrypted blob lands before the public files. A run interrupted between
/// them leaves a card whose signer holds every key and whose public files do
/// not name the newest one yet; the other order leaves a public file naming a
/// key no secret backs, which is a key the host would carry onto a second card
/// and a key the device would show but never sign with.
///
/// # Errors
///
/// Returns an error if encryption fails or any file will not be written.
pub fn write_store(
    blob: &Path,
    pin: &[u8],
    entries: &[Entry<'_>],
) -> Result<Secret<String>, String> {
    let keys_dir = blob
        .parent()
        .ok_or_else(|| format!("The key store path names no directory: {}", blob.display()))?;
    let plaintext = build_secret_keys_json(entries);

    let encrypted = russignol_crypto::encrypt(pin, plaintext.as_str())
        .map_err(|e| format!("Failed to encrypt the key store: {e}"))?;
    atomic_write(blob, &encrypted).map_err(|e| format!("Failed to write the key store: {e}"))?;

    let public: Vec<StoredKey> = entries.iter().map(Entry::to_stored_key).collect();
    KeyManager::new(Some(keys_dir.to_path_buf())).save_public_keys_only(&public)?;

    Ok(plaintext)
}

/// Provision `what` onto the card whose store is `blob`, over the store
/// `current` holds, and hand back the store that replaces it.
///
/// # Errors
///
/// Returns an error if generation fails, if `current` does not read, or if the
/// new store will not be written.
pub fn provision_key(
    blob: &Path,
    pin: &[u8],
    current: &str,
    what: Provisioning,
) -> Result<Secret<String>, String> {
    let generated = Generated::new(what)?;
    let entries = with_key_provisioned(read_store(current)?, &generated);
    write_store(blob, pin, &entries)
}

/// The two files one provisioning boot works on.
///
/// Built here rather than handed in: both are paths, and a pair a caller fills
/// in can be filled in crossed, which reads the request out of the key store
/// and deletes the store on the way out.
pub struct Paths {
    request: PathBuf,
    store: PathBuf,
}

impl Paths {
    /// Where the device keeps them: the request on the data partition, which
    /// is the only one an unprivileged signer can write, and the store on the
    /// keys partition.
    #[must_use]
    pub fn device() -> Self {
        Self {
            request: PathBuf::from(crate::constants::PROVISION_REQUEST_FILE),
            store: PathBuf::from(russignol_crypto::SECRET_KEYS_ENC_V2_PATH),
        }
    }

    /// The same two file names under a directory standing in for each
    /// partition, so a test can hold one of them read-only.
    #[cfg(test)]
    pub fn under(data: &Path, keys: &Path) -> Self {
        Self {
            request: data.join(device_file_name(crate::constants::PROVISION_REQUEST_FILE)),
            store: keys.join(device_file_name(russignol_crypto::SECRET_KEYS_ENC_V2_PATH)),
        }
    }

    /// The staged request naming the key to provision.
    #[must_use]
    pub fn request(&self) -> &Path {
        &self.request
    }

    /// The encrypted key store the run rewrites.
    #[must_use]
    pub fn store(&self) -> &Path {
        &self.store
    }
}

#[cfg(test)]
fn device_file_name(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("a device path names a file")
}

/// The device key a staged request names, or `None` where none is staged.
///
/// A request naming a key this device does not provision is an error rather
/// than a skip. The init script has already kept the keys partition writable
/// for it, so a boot that reads it as nothing staged repeats that on every
/// boot after.
///
/// # Errors
///
/// Returns an error if the request will not read, or names no device key.
pub fn staged_request(path: &Path) -> io::Result<Option<DeviceKey>> {
    let alias = match fs::read_to_string(path) {
        Ok(alias) => alias,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    DeviceKey::from_device_alias(alias.trim())
        .map(Some)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("staged provisioning request names no device key: {alias:?}"),
            )
        })
}

/// How long generating `key` takes on the device.
///
/// The XMSS figure is the 41 minutes measured at the deployed span; a BLS key
/// is generated in milliseconds, and the estimate is there so the progress bar
/// and the operator's confirmation read one number rather than two.
#[must_use]
pub const fn estimate(key: DeviceKey) -> std::time::Duration {
    match key {
        DeviceKey::Bls(_) => std::time::Duration::from_secs(1),
        DeviceKey::XmssConsensus => std::time::Duration::from_mins(41),
    }
}

/// That estimate as the operator reads it.
#[must_use]
pub fn estimate_in_words(key: DeviceKey) -> String {
    let minutes = estimate(key).as_secs() / 60;
    if minutes == 0 {
        "under a minute".to_string()
    } else {
        format!("about {minutes} minutes")
    }
}

/// Ask the next boot to provision `key`.
///
/// Through a rename, because a request caught half-written by a power cut is
/// one no later boot resolves: its presence keeps the keys partition writable
/// and its content names no key, so every boot after it stops on the same
/// unreadable request.
///
/// # Errors
///
/// Returns an error if the request cannot be written.
pub fn stage_request(path: &Path, key: DeviceKey) -> io::Result<()> {
    atomic_write(path, key.device_alias().as_bytes())
}

/// Clear a staged request, whether or not one is staged.
///
/// # Errors
///
/// Returns an error if a staged request will not be removed. A request left
/// behind is a device that reboots into a writable keys partition every time.
pub fn clear_request(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::wallet::OcamlKeyEntry;

    const SAMPLE_SK: &str = "BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x";

    /// A span generation can walk inside a test run: it builds every in-range
    /// leaf, and the deployed span costs tens of minutes.
    const TEST_EPOCHS: std::ops::RangeInclusive<xmss::Epoch> = 0..=15;

    /// Wide enough that its secret runs to thousands of base58 characters
    /// beside a `BLsk`'s 54, which is the spread the store's buffer is sized
    /// against.
    const WIDE_EPOCHS: std::ops::RangeInclusive<xmss::Epoch> = 0..=4095;

    fn generated(what: Provisioning) -> Generated {
        Generated::new(what).expect("a non-empty span")
    }

    fn bls_secret(seed: u8) -> String {
        Unencrypted::generate(Some(&[seed; 32]))
            .unwrap()
            .secret_key()
            .to_b58check()
    }

    /// Entries as the store holds them, each carrying the public material its
    /// own secret derives.
    fn entries<'a>(pairs: &'a [(&'a str, String)]) -> Vec<Entry<'a>> {
        pairs
            .iter()
            .map(|(alias, secret)| {
                let signer = Unencrypted::from_b58check(secret).expect("a loadable secret");
                Entry::new(Cow::Borrowed(alias), secret, &signer)
            })
            .collect()
    }

    /// A store as the device writes one, through the emitter that writes it: a
    /// hand-rolled fixture is a second copy of the format, and a reader tested
    /// against it stays green while the card it has to read moves.
    fn store(pairs: &[(&str, String)]) -> Secret<String> {
        build_secret_keys_json(&entries(pairs))
    }

    fn filed(entries: &[Entry<'_>]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|e| (e.alias.to_string(), e.secret.to_string()))
            .collect()
    }

    /// Adding a scheme to a provisioned card leaves the keys already on it as
    /// the same bytes: a run that re-derived them would rewrite the keys the
    /// baker's delegate is registered against.
    #[test]
    fn adding_a_key_leaves_every_other_entry_as_the_bytes_it_arrived_as() {
        let (consensus, companion) = (bls_secret(1), bls_secret(2));
        let json = store(&[
            ("consensus_tz4", consensus.clone()),
            ("companion_tz4", companion.clone()),
        ]);
        let tz6 = generated(Provisioning::Xmss(TEST_EPOCHS));

        let provisioned = with_key_provisioned(read_store(&json).unwrap(), &tz6);

        assert_eq!(
            filed(&provisioned),
            vec![
                ("consensus_tz4".to_string(), consensus),
                ("companion_tz4".to_string(), companion),
                (
                    "consensus_tz6".to_string(),
                    tz6.signer.secret_key().to_b58check()
                ),
            ]
        );
    }

    /// One key answers to one slot after a run. A card mid-migration carries
    /// both spellings of a role, and leaving the replaced one beside the new
    /// key puts the key the run just retired back in reach of `list_keys()`.
    #[test]
    fn provisioning_replaces_every_spelling_of_the_key_it_names() {
        let json = store(&[
            ("consensus", bls_secret(1)),
            ("consensus_tz4", bls_secret(2)),
            ("companion_tz4", bls_secret(3)),
        ]);
        let replacement = generated(Provisioning::Bls(KeyRole::Consensus));

        let provisioned = with_key_provisioned(read_store(&json).unwrap(), &replacement);

        assert_eq!(
            filed(&provisioned),
            vec![
                (
                    "consensus_tz4".to_string(),
                    replacement.signer.secret_key().to_b58check()
                ),
                ("companion_tz4".to_string(), bls_secret(3)),
            ]
        );
    }

    /// An alias no device key claims is a key the card holds and this run was
    /// not asked about, so it survives rather than being dropped on the way
    /// through.
    #[test]
    fn an_alias_no_device_key_claims_survives_the_run() {
        let alice = bls_secret(4);
        let json = store(&[("alice", alice.clone()), ("consensus_tz4", bls_secret(1))]);
        let tz6 = generated(Provisioning::Xmss(TEST_EPOCHS));

        let provisioned = with_key_provisioned(read_store(&json).unwrap(), &tz6);

        assert_eq!(
            filed(&provisioned)
                .into_iter()
                .map(|(alias, _)| alias)
                .collect::<Vec<_>>(),
            vec!["consensus_tz4", "consensus_tz6", "alice"]
        );
        assert_eq!(filed(&provisioned)[2].1, alice);
    }

    /// The public material filed beside a secret is derived from that secret,
    /// so no entry can carry one key's address over another key's secret.
    #[test]
    fn each_entry_carries_the_address_its_own_secret_derives() {
        let json = store(&[("consensus_tz4", SAMPLE_SK.to_string())]);
        let tz6 = generated(Provisioning::Xmss(TEST_EPOCHS));

        let provisioned = with_key_provisioned(read_store(&json).unwrap(), &tz6);

        for entry in &provisioned {
            let signer = Unencrypted::from_b58check(entry.secret).expect("a loadable secret");
            assert_eq!(
                entry.public_key_hash,
                signer.public_key_hash().to_b58check()
            );
            assert_eq!(entry.public_key, signer.public_key().to_b58check());
        }
        assert!(provisioned[1].public_key_hash.starts_with("tz6"));
    }

    /// A key that will not load aborts the read. Skipping it would write the
    /// card back without a key it arrived holding, which no later step can
    /// recover.
    #[test]
    fn a_secret_that_will_not_load_stops_the_read() {
        let json = format!(
            r#"[{{"name":"consensus_tz4","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"companion_tz4","value":"unencrypted:BLskNope"}}]"#
        );

        let Err(e) = read_store(&json) else {
            panic!("an unloadable secret must abort the read")
        };
        assert!(
            e.contains("companion_tz4"),
            "the error names the entry: {e}"
        );
    }

    #[test]
    fn emit_round_trip() {
        let pairs = [
            ("consensus_tz4", bls_secret(1)),
            ("companion_tz4", bls_secret(2)),
        ];
        let secret = build_secret_keys_json(&entries(&pairs));

        let parsed: Vec<OcamlKeyEntry<String>> =
            serde_json::from_str(&secret).expect("emitter must produce valid JSON");
        assert_eq!(parsed.len(), 2);
        for (entry, (alias, sk)) in parsed.iter().zip(pairs.iter()) {
            assert_eq!(&entry.name, alias);
            assert_eq!(entry.value, format!("unencrypted:{sk}"));
        }
    }

    /// A card holding both schemes writes one entry of 54 base58 characters
    /// beside one of thousands, the XMSS width growing with the key's epoch
    /// span. That spread is what a buffer sized per entry must absorb without
    /// growing.
    #[test]
    fn emit_no_realloc_for_a_tz6_secret() {
        let tz6 = generated(Provisioning::Xmss(WIDE_EPOCHS));
        let pairs = [
            ("consensus_tz4", bls_secret(1)),
            ("consensus_tz6", tz6.signer.secret_key().to_b58check()),
        ];
        let built = entries(&pairs);
        assert!(
            built[1].secret.len() > 20 * built[0].secret.len(),
            "the two entries are the same order of width"
        );

        let secret = build_secret_keys_json(&built);

        assert_eq!(
            secret.capacity(),
            secret.len(),
            "the buffer was not sized to what it emitted",
        );
    }

    /// The card reads back as the entries it was written from. The blob is the
    /// only copy of a secret the device keeps, so a write the reader cannot
    /// undo is a card that unlocks to nothing.
    #[test]
    fn a_written_store_reloads_as_the_entries_it_was_given() {
        let dir = tempfile::TempDir::new().unwrap();
        let pairs = [
            ("consensus_tz4", bls_secret(1)),
            ("companion_tz4", bls_secret(2)),
        ];

        let written = write_store(
            &dir.path().join("secret_keys.enc.v2"),
            b"12345678",
            &entries(&pairs),
        )
        .unwrap();

        let blob = std::fs::read(dir.path().join("secret_keys.enc.v2")).unwrap();
        let plaintext = russignol_crypto::decrypt(b"12345678", &blob).unwrap();
        assert_eq!(plaintext.as_str(), written.as_str());
        assert_eq!(
            filed(&read_store(&plaintext).unwrap()),
            pairs
                .iter()
                .map(|(alias, sk)| ((*alias).to_string(), sk.clone()))
                .collect::<Vec<_>>()
        );
    }

    /// The wallet files name every key in the blob, at the address that key's
    /// own secret derives. The device draws its pre-unlock pages from these
    /// files, so a key missing here is one the operator cannot see.
    #[test]
    fn the_wallet_files_name_every_key_the_blob_holds() {
        let dir = tempfile::TempDir::new().unwrap();
        let pairs = [
            ("consensus_tz4", bls_secret(1)),
            ("companion_tz4", bls_secret(2)),
        ];
        let built = entries(&pairs);

        write_store(&dir.path().join("secret_keys.enc.v2"), b"12345678", &built).unwrap();

        let loaded = KeyManager::new(Some(dir.path().to_path_buf()))
            .load_keys()
            .unwrap();
        assert_eq!(loaded.len(), built.len());
        for entry in &built {
            let stored = loaded
                .get(entry.alias.as_ref())
                .unwrap_or_else(|| panic!("{} is absent from the wallet files", entry.alias));
            assert_eq!(stored.public_key_hash, entry.public_key_hash);
            assert_eq!(stored.public_key, entry.public_key);
        }
    }

    /// The blob lands before the wallet files, so a run stopped between them
    /// leaves a card that still unlocks and still signs. The other order leaves
    /// a wallet naming a key no secret backs.
    #[test]
    fn a_wallet_write_that_cannot_land_leaves_the_blob_readable() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("public_key_hashs")).unwrap();
        let pairs = [("consensus_tz4", bls_secret(1))];

        let failed = write_store(
            &dir.path().join("secret_keys.enc.v2"),
            b"12345678",
            &entries(&pairs),
        );

        assert!(failed.is_err(), "the wallet write must report its failure");
        let blob = std::fs::read(dir.path().join("secret_keys.enc.v2")).unwrap();
        let plaintext = russignol_crypto::decrypt(b"12345678", &blob).unwrap();
        assert_eq!(
            filed(&read_store(&plaintext).unwrap()),
            vec![("consensus_tz4".to_string(), bls_secret(1))]
        );
    }
    const PIN: &[u8] = b"12345678";

    /// The epoch store a card's keys get at unlock, over `watermarks`.
    fn unlock_store(
        watermarks: &Path,
        plaintext: &str,
    ) -> std::sync::Arc<std::sync::RwLock<russignol_signer_lib::HighWatermark>> {
        let (key_manager, params) = crate::signer_server::load_secret_keys(plaintext).unwrap();
        let config = crate::signer_server::SignerConfig {
            watermark_dir: watermarks.to_string_lossy().into_owned(),
            ..Default::default()
        };
        crate::signer_server::create_high_watermark(
            &config,
            &key_manager.list_keys(),
            params,
            russignol_signer_lib::ChainId::from_bytes(&[5u8; 32]),
        )
        .expect("a store over a writable directory")
        .expect("watermark checking is on")
    }

    /// Every file under `root`, so a run can be held to having changed none.
    fn snapshot(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        let mut files = std::collections::BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    pending.push(entry.path());
                } else {
                    files.insert(entry.path(), std::fs::read(entry.path()).unwrap());
                }
            }
        }
        files
    }

    /// A card provisioned with a second scheme keeps the watermark and epoch
    /// records of the keys already on it. Those records live on the data
    /// partition and a provisioning run writes only the keys partition, so a
    /// run that touched them would be rewinding a mark that guards against
    /// double-signing.
    #[test]
    fn adding_a_key_leaves_every_record_on_the_data_partition_alone() {
        let (keys, data) = (
            tempfile::TempDir::new().unwrap(),
            tempfile::TempDir::new().unwrap(),
        );
        let blob = keys.path().join("secret_keys.enc.v2");
        let pairs = [("consensus_tz4", bls_secret(1))];
        let built = entries(&pairs);
        let tz4_pkh =
            russignol_signer_lib::PublicKeyHash::from_b58check(&built[0].public_key_hash).unwrap();
        let before = write_store(&blob, PIN, &built).unwrap();
        {
            let store = unlock_store(data.path(), &before);
            store
                .write()
                .unwrap()
                .seed_floor(
                    russignol_signer_lib::ChainId::from_bytes(&[5u8; 32]),
                    &tz4_pkh,
                    100,
                )
                .unwrap();
        }
        let records = snapshot(data.path());
        assert!(!records.is_empty(), "the unlock wrote no records to hold");

        provision_key(&blob, PIN, &before, Provisioning::Xmss(TEST_EPOCHS)).unwrap();

        assert_eq!(snapshot(data.path()), records);
    }

    /// Replacing a key of one scheme cannot rewind another's epoch counter.
    /// Each counter is filed under its own key's address, and handing back an
    /// epoch a tz6 key has already signed at discloses that key.
    #[test]
    fn replacing_a_bls_key_leaves_a_tz6_counter_where_it_stood() {
        let (keys, data) = (
            tempfile::TempDir::new().unwrap(),
            tempfile::TempDir::new().unwrap(),
        );
        let blob = keys.path().join("secret_keys.enc.v2");
        let tz6 = generated(Provisioning::Xmss(TEST_EPOCHS));
        let tz6_pkh = *tz6.signer.public_key_hash();
        let pairs = [
            ("consensus_tz4", bls_secret(1)),
            ("consensus_tz6", tz6.signer.secret_key().to_b58check()),
        ];
        let before = write_store(&blob, PIN, &entries(&pairs)).unwrap();
        {
            let store = unlock_store(data.path(), &before);
            let mut wm = store.write().unwrap();
            for _ in 0..3 {
                wm.claim_epoch(&tz6_pkh).unwrap();
            }
        }
        let reached = unlock_store(data.path(), &before)
            .read()
            .unwrap()
            .epoch_resume_point(&tz6_pkh)
            .unwrap();
        assert!(reached >= 3, "the claims did not persist: {reached}");

        let after =
            provision_key(&blob, PIN, &before, Provisioning::Bls(KeyRole::Consensus)).unwrap();

        let store = unlock_store(data.path(), &after);
        let wm = store.read().unwrap();
        assert_eq!(wm.epoch_resume_point(&tz6_pkh), Some(reached));
        assert_eq!(wm.next_epoch(&tz6_pkh), Some(reached));
    }

    /// A replaced XMSS key starts at its own first epoch, and the record of the
    /// key it replaced is left where it stood. The counter is filed under the
    /// key's address, so a replacement is never handed an epoch that the key it
    /// replaced spent under the same key material.
    #[test]
    fn a_replaced_tz6_key_starts_at_its_own_first_epoch() {
        let (keys, data) = (
            tempfile::TempDir::new().unwrap(),
            tempfile::TempDir::new().unwrap(),
        );
        let blob = keys.path().join("secret_keys.enc.v2");
        let retired = generated(Provisioning::Xmss(TEST_EPOCHS));
        let retired_pkh = *retired.signer.public_key_hash();
        let pairs = [("consensus_tz6", retired.signer.secret_key().to_b58check())];
        let before = write_store(&blob, PIN, &entries(&pairs)).unwrap();
        {
            let store = unlock_store(data.path(), &before);
            let mut wm = store.write().unwrap();
            for _ in 0..3 {
                wm.claim_epoch(&retired_pkh).unwrap();
            }
        }
        let retired_record = snapshot(&data.path().join(retired_pkh.to_b58check()));

        let after = provision_key(&blob, PIN, &before, Provisioning::Xmss(TEST_EPOCHS)).unwrap();

        let replacement = read_store(&after).unwrap();
        let replacement_pkh =
            russignol_signer_lib::PublicKeyHash::from_b58check(&replacement[0].public_key_hash)
                .unwrap();
        assert_ne!(replacement_pkh, retired_pkh, "the run reused key material");

        let store = unlock_store(data.path(), &after);
        let mut wm = store.write().unwrap();
        assert_eq!(
            u64::from(wm.claim_epoch(&replacement_pkh).unwrap()),
            u64::from(*TEST_EPOCHS.start()),
            "the replacement did not start at its own first epoch"
        );
        assert_eq!(
            snapshot(&data.path().join(retired_pkh.to_b58check())),
            retired_record,
            "the retired key's record moved"
        );
    }

    /// A staged request names the key the next boot provisions, and it is
    /// written where a signer that has dropped its privileges can still write:
    /// nothing past unlock can write the keys partition at all.
    #[test]
    fn a_staged_request_names_the_key_it_was_staged_for() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("provision-request");

        assert_eq!(staged_request(&path).unwrap(), None);
        // The alias as it lands on disk, spelled here rather than read back
        // off either side of the file: one boot writes it and the next reads
        // it, so a spelling that moves on one side has to turn a test red.
        std::fs::write(&path, "consensus_tz6").unwrap();
        assert_eq!(
            staged_request(&path).unwrap(),
            Some(DeviceKey::XmssConsensus)
        );

        stage_request(&path, DeviceKey::XmssConsensus).expect("a writable directory");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "consensus_tz6");

        clear_request(&path).unwrap();
        assert_eq!(staged_request(&path).unwrap(), None);
        clear_request(&path).expect("clearing what is not there is not a failure");
    }

    /// The operator's flow and the boot that carries it out agree on every key
    /// the device provisions: a request one writes and the other does not read
    /// is a boot that stops on it, with the keys partition left writable.
    #[test]
    fn every_key_staged_is_a_key_the_next_boot_reads_back() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("provision-request");

        for key in DeviceKey::ALL {
            stage_request(&path, key).expect("a writable data partition");
            assert_eq!(staged_request(&path).unwrap(), Some(key));
        }
    }

    /// A request naming no key of this device stops the boot rather than
    /// reading as nothing staged. The init script has already kept the keys
    /// partition writable for it, and a boot that shrugs repeats that on every
    /// boot after.
    #[test]
    fn a_request_naming_no_device_key_is_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("provision-request");
        std::fs::write(&path, "consensus_tz9").unwrap();

        let Err(e) = staged_request(&path) else {
            panic!("a request naming no device key must stop the boot")
        };
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }
}
