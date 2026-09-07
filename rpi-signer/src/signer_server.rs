use crate::cpu_freq::CpuBoost;
use log::{error, info};
use russignol_signer_lib::{
    ChainId, HighWatermark, MagicByte, RequestHandler, ServerKeyManager, SigningActivity,
    high_watermark::MarkParams, server, signer,
};
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Borrowing view over a secret-keys JSON entry.
///
/// `value: &str` makes `serde_json` slice each secret out of the input
/// buffer rather than allocate a fresh owned `String` per entry; an owned
/// `String` would drop without zeroizing and leave plaintext in the heap.
/// The input itself is a `Secret<String>` and zeroizes on drop, so the
/// borrowed slice inherits that lifetime. Base58 secrets contain no `"`,
/// `\`, or control bytes, so the borrow always succeeds.
#[derive(Deserialize)]
pub struct BorrowedKeyEntry<'a> {
    /// The name the store files this key under.
    #[serde(borrow)]
    pub name: Cow<'a, str>,
    /// The stored value, `unencrypted:` prefix included.
    pub value: &'a str,
}

/// Configuration for the integrated signer
pub struct SignerConfig {
    /// Directory for watermarks (on /data partition)
    pub watermark_dir: String,
    pub address: String,
    pub port: u16,
    pub magic_bytes: &'static [u8],
    pub check_high_watermark: bool,
    /// Consecutive failed starts to ride out before the failure is reported.
    ///
    /// One attempt is the fewest a start can be made in, so the count is
    /// non-zero rather than a number that could ask for none.
    ///
    /// The listener binds a link-local address on the USB gadget interface,
    /// which the init script's gadget supervisor brings up in the background,
    /// so an early failure is a race rather than a fault. A failure that
    /// survives every attempt is one nothing is going to clear, and retrying
    /// it silently forever is a device that never signs and never says so.
    pub start_attempts: NonZeroU32,
    /// How long to wait between those attempts.
    pub retry_delay: Duration,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            watermark_dir: "/data/watermarks".to_string(),
            address: "169.254.1.1".to_string(),
            port: 7732,
            magic_bytes: MagicByte::all(),
            check_high_watermark: true,
            start_attempts: NonZeroU32::new(12).expect("twelve is not zero"),
            retry_delay: Duration::from_secs(5),
        }
    }
}

/// Read a decrypted secret-key store, borrowing each secret out of the input.
///
/// # Errors
///
/// Returns an error if the JSON does not parse or holds no key.
pub fn parse_store(store: &str) -> Result<Vec<BorrowedKeyEntry<'_>>, String> {
    let entries: Vec<BorrowedKeyEntry<'_>> = serde_json::from_str(store)
        .map_err(|e| format!("Failed to parse secret_keys JSON: {e}"))?;
    if entries.is_empty() {
        return Err("No keys found in secret_keys".to_string());
    }
    Ok(entries)
}

/// The bare base58 secret one store entry carries, and the signer it loads to.
///
/// # Errors
///
/// Returns an error naming the entry where its value does not load.
pub fn load_entry<'a>(
    entry: &BorrowedKeyEntry<'a>,
) -> Result<(&'a str, signer::Unencrypted), String> {
    let secret = entry
        .value
        .strip_prefix(russignol_signer_lib::wallet::UNENCRYPTED_PREFIX)
        .unwrap_or(entry.value);
    let signer = signer::Unencrypted::from_b58check(secret)
        .map_err(|e| format!("Failed to load key '{}': {e}", entry.name))?;
    Ok((secret, signer))
}

/// Parse secret keys JSON and create a `KeyManager`.
///
/// Keys are passed in memory after PIN decryption — never written to disk.
fn parse_secret_keys(secret_keys_json: &str) -> Result<ServerKeyManager, String> {
    let entries = parse_store(secret_keys_json)?;

    info!("Loading {} key(s)...", entries.len());

    let mut key_manager = ServerKeyManager::new();
    for entry in entries {
        // Abort rather than skip: a signer missing one of its keys boots
        // normally but silently stops signing for that pkh.
        let (_, signer) = load_entry(&entry).inspect_err(|e| error!("  ✗ {e}"))?;
        let pkh = *signer.public_key_hash();
        let alias = entry.name.into_owned();
        info!("  ✓ Loaded key: {alias} ({})", pkh.to_b58check());
        key_manager.add_signer(signer, alias);
    }

    Ok(key_manager)
}

/// Read what the mark store needs from every key an already-loaded manager
/// holds: the MAC key authenticating its records, and the epochs it may sign at.
#[must_use]
pub fn mark_params_from_manager(
    key_manager: &ServerKeyManager,
) -> HashMap<PublicKeyHash, MarkParams> {
    key_manager
        .iter_signers()
        .map(|(pkh, signer)| (*pkh, MarkParams::from(signer.secret_key())))
        .collect()
}

/// Parse secret-key JSON once into a key manager and its mark parameters.
///
/// # Errors
///
/// Returns an error if the JSON cannot be parsed or a key fails to load.
pub fn load_secret_keys(
    secret_keys_json: &str,
) -> Result<(ServerKeyManager, HashMap<PublicKeyHash, MarkParams>), String> {
    let key_manager = parse_secret_keys(secret_keys_json)?;
    let mark_params = mark_params_from_manager(&key_manager);
    Ok((key_manager, mark_params))
}

use russignol_signer_lib::PublicKeyHash;

/// Type alias for watermark error callback
pub type WatermarkErrorCallback =
    Arc<dyn Fn(PublicKeyHash, ChainId, &russignol_signer_lib::WatermarkError) + Send + Sync>;

/// Type alias for large level gap callback
pub type LargeGapCallback = Arc<dyn Fn(PublicKeyHash, ChainId, u32, u32) + Send + Sync>;

/// Type alias for missing watermark callback (pkh, `chain_id`, `requested_level`)
pub type MissingWatermarkCallback = Arc<dyn Fn(PublicKeyHash, ChainId, u32) + Send + Sync>;

/// Type alias for unknown-key callback (the requested pkh the signer does not hold)
pub type UnknownKeyCallback = Arc<dyn Fn(PublicKeyHash) + Send + Sync>;

/// Callbacks for the integrated signer
#[derive(Default)]
pub struct SignerCallbacks {
    /// Called when a watermark error occurs
    pub watermark_error: Option<WatermarkErrorCallback>,
    /// Called after each successful signing operation
    pub signing: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Called when a large level gap is detected (pkh, `chain_id`, `current_level`, `new_level`)
    pub large_gap: Option<LargeGapCallback>,
    /// Called when a signing request hits a key with no initialized watermark
    pub missing_watermark: Option<MissingWatermarkCallback>,
    /// Called when a signing request names a key the signer does not hold
    pub unknown_key: Option<UnknownKeyCallback>,
    /// Called when a client TCP connection opens (e.g., CPU frequency boost).
    /// Must not block — see `RequestHandler::with_pre_sign_callback`.
    pub pre_sign: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Called when a client TCP connection closes (e.g., CPU frequency restore).
    /// Must not block — see `RequestHandler::with_post_sign_callback`.
    pub post_sign: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// Create high watermark tracker based on config
///
/// Watermarks are stored on the data partition (/data/watermarks) which is
/// separate from keys to allow write operations without affecting the
/// read-only keys partition.
pub fn create_high_watermark(
    config: &SignerConfig,
    pkhs: &[PublicKeyHash],
    mark_params: HashMap<PublicKeyHash, MarkParams>,
    chain_id: ChainId,
) -> Result<Option<Arc<RwLock<HighWatermark>>>, String> {
    if config.check_high_watermark {
        let hwm_dir = PathBuf::from(&config.watermark_dir);
        fs::create_dir_all(&hwm_dir)
            .map_err(|e| format!("Failed to create watermark directory: {e}"))?;

        let mut hwm = HighWatermark::new(&hwm_dir, pkhs, mark_params, chain_id)
            .map_err(|e| format!("Failed to create high watermark: {e}"))?;

        // A key that spends epochs refuses to sign until its record exists, and
        // nothing between here and the first signing request establishes one.
        // Seeding at 0 raises each key to its own range start and never lowers
        // a record an earlier unlock or a restore already established.
        for pkh in pkhs {
            if !hwm.spends_epochs(pkh) {
                continue;
            }
            hwm.seed_epoch_floor(pkh, 0).map_err(|e| {
                format!(
                    "Failed to establish the epoch floor for {}: {e}",
                    pkh.to_b58check()
                )
            })?;
        }

        info!(
            "✓ High watermark protection enabled ({})",
            config.watermark_dir
        );
        Ok(Some(Arc::new(RwLock::new(hwm))))
    } else {
        info!("⚠ High watermark protection DISABLED");
        Ok(None)
    }
}

/// Every loaded key whose first signature would otherwise build its own
/// bottom subtree, paired with the epoch that build covers.
///
/// The cache does not survive serialization, so a key read off the card starts
/// empty and its first signature pays a build on the signing path. The epoch is
/// the one the store will hand out, because that is what the signature spends.
fn keys_to_warm(
    key_manager: &ServerKeyManager,
    watermark: &RwLock<HighWatermark>,
) -> Vec<(
    PublicKeyHash,
    russignol_signer_lib::SecretKey,
    russignol_signer_lib::xmss::Epoch,
)> {
    // Taken back from a poisoned lock: an empty list is what a card with
    // nothing to warm returns, so reading a poisoned lock as one puts the
    // subtree build back on the first signature of every loaded key.
    let wm = watermark
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    key_manager
        .iter_signers()
        .filter_map(|(pkh, signer)| {
            let next = wm.next_epoch(pkh)?;
            let next = russignol_signer_lib::xmss::Epoch::try_from(next).ok()?;
            Some((*pkh, signer.secret_key().clone(), next))
        })
        .collect()
}

/// Build each loaded key's next bottom subtree off the signing path.
///
/// Spawned rather than awaited: the listener comes up without waiting for a
/// build, and a signature arriving mid-build takes no lock the build holds —
/// upstream builds outside its cache lock.
fn warm_loaded_keys(
    key_manager: &ServerKeyManager,
    watermark: &RwLock<HighWatermark>,
    cpu_boost: Option<CpuBoost>,
) {
    let pending = keys_to_warm(key_manager, watermark);
    if pending.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let _held = cpu_boost.as_ref().map(CpuBoost::hold);
        for (pkh, secret, epoch) in pending {
            match secret.warm(epoch) {
                Ok(Some(warmed)) => info!("Warmed {} for epoch {warmed}", pkh.to_b58check()),
                Ok(None) => {}
                Err(e) => error!("Failed to warm {} at epoch {epoch}: {e}", pkh.to_b58check()),
            }
        }
    });
}

/// Start the integrated signer server with an already-parsed key manager.
///
/// Keys are loaded once at unlock ([`load_secret_keys`]) and handed here in
/// memory — never re-parsed from JSON and never written to disk.
pub fn start_integrated_signer(
    config: &SignerConfig,
    key_manager: ServerKeyManager,
    signing_activity: &Arc<Mutex<SigningActivity>>,
    watermark: Option<&Arc<RwLock<HighWatermark>>>,
    callbacks: &SignerCallbacks,
    blocks_per_cycle: Option<u32>,
    cpu_boost: Option<CpuBoost>,
) -> Result<(), String> {
    if let Some(wm) = watermark {
        warm_loaded_keys(&key_manager, wm, cpu_boost);
    }
    let key_manager = Arc::new(RwLock::new(key_manager));

    // Parsed once: the address does not change between attempts, and a
    // malformed one is a failure no amount of retrying reaches.
    let addr_str = format!("{}:{}", config.address, config.port);
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("Failed to parse address '{addr_str}': {e}"))?;

    let attempts = config.start_attempts.get();
    let mut attempt = 1;
    loop {
        match run_signer_once(
            addr,
            config,
            key_manager.clone(),
            watermark.cloned(),
            signing_activity.clone(),
            callbacks,
            blocks_per_cycle,
        ) {
            Ok(()) => {
                info!("Signer stopped normally");
                return Ok(());
            }
            Err(e) if attempt >= attempts => {
                error!("Signer error: {e}. Out of attempts.");
                return Err(e);
            }
            Err(e) => {
                error!(
                    "Signer error: {e}. Attempt {attempt} of {attempts}; retrying in {:?}.",
                    config.retry_delay
                );
                attempt += 1;
                std::thread::sleep(config.retry_delay);
            }
        }
    }
}

fn run_signer_once(
    addr: SocketAddr,
    config: &SignerConfig,
    key_manager: Arc<RwLock<ServerKeyManager>>,
    watermark: Option<Arc<RwLock<HighWatermark>>>,
    signing_activity: Arc<Mutex<SigningActivity>>,
    callbacks: &SignerCallbacks,
    blocks_per_cycle: Option<u32>,
) -> Result<(), String> {
    info!("Starting signer...");

    let mut handler = RequestHandler::new(
        key_manager,
        watermark,
        Some(config.magic_bytes),
        true, // allow_list_known_keys
        true, // allow_prove_possession
    )
    .with_signing_activity(signing_activity);

    if let Some(ref callback) = callbacks.watermark_error {
        handler = handler.with_watermark_error_callback(callback.clone());
    }

    if let Some(ref callback) = callbacks.signing {
        handler = handler.with_signing_notify(callback.clone());
    }

    if let (Some(callback), Some(bpc)) = (&callbacks.large_gap, blocks_per_cycle) {
        handler = handler.with_large_gap_callback(callback.clone(), bpc);
    }

    if let Some(ref callback) = callbacks.missing_watermark {
        handler = handler.with_watermark_missing_callback(callback.clone());
    }

    if let Some(ref callback) = callbacks.unknown_key {
        handler = handler.with_unknown_key_callback(callback.clone());
    }

    if let Some(ref callback) = callbacks.pre_sign {
        handler = handler.with_pre_sign_callback(callback.clone());
    }
    if let Some(ref callback) = callbacks.post_sign {
        handler = handler.with_post_sign_callback(callback.clone());
    }

    // Without a timeout a USB disconnect leaves the thread serving that
    // connection parked on a socket nothing closes.
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(30)));

    info!("🚀 Signer server listening on {addr}");
    info!("📡 Waiting for connections...");

    server
        .run()
        .map_err(|e| format!("Server error on {addr}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::wallet::OcamlKeyEntry;
    use russignol_signer_lib::{DeviceKey, KeyRole, Scheme, xmss};

    const SAMPLE_SK: &str = "BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x";

    fn parse(input: &str) -> Result<Vec<BorrowedKeyEntry<'_>>, String> {
        parse_store(input)
    }

    #[test]
    fn parse_secret_keys_loads_all_valid_keys() {
        let other_sk = signer::Unencrypted::generate(Some(&[7u8; 32]))
            .unwrap()
            .secret_key()
            .to_b58check();
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let companion = DeviceKey::Bls(KeyRole::Companion).device_alias();
        let input = format!(
            r#"[{{"name":"{consensus}","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"{companion}","value":"unencrypted:{other_sk}"}}]"#
        );
        let key_manager = parse_secret_keys(&input).expect("valid keys load");
        assert_eq!(key_manager.list_keys().len(), 2);
    }

    /// The MAC key unlock installs is keyed by the loaded key's own address and
    /// derived from that key's secret; a map keyed or derived any other way
    /// authenticates marks the signing path cannot reproduce.
    #[test]
    fn load_secret_keys_keys_each_mac_by_its_own_secret() {
        let (xmss_sk, _) = xmss::SecretKey::generate([7u8; 32], 0, 15).expect("range is valid");
        let tz6 = russignol_signer_lib::SecretKey::Xmss(std::sync::Arc::new(xmss_sk)).to_b58check();
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let input = format!(
            r#"[{{"name":"{consensus}","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"pq_consensus","value":"unencrypted:{tz6}"}}]"#
        );
        let (_, from_load) = load_secret_keys(&input).expect("load");

        assert_eq!(from_load.len(), 2);
        for secret in [SAMPLE_SK, tz6.as_str()] {
            let signer = signer::Unencrypted::from_b58check(secret).expect("loadable key");
            let params = from_load
                .get(signer.public_key_hash())
                .expect("keyed by the loaded key's own address");
            assert_eq!(params.mac_key, signer.secret_key().watermark_mac_key());
            assert_eq!(params.epochs, signer.secret_key().epoch_range());
        }
    }

    /// One card holds keys of both schemes, and a single unreadable entry
    /// aborts the whole load — so a tz6 entry the loader could not parse would
    /// take the tz4 keys down with it and stop the device signing at all.
    #[test]
    fn parse_secret_keys_loads_a_mixed_tz4_and_tz6_blob() {
        let (xmss_sk, _) = xmss::SecretKey::generate([7u8; 32], 0, 15).expect("range is valid");
        let tz6 = russignol_signer_lib::SecretKey::Xmss(std::sync::Arc::new(xmss_sk)).to_b58check();
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let input = format!(
            r#"[{{"name":"{consensus}","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"pq_consensus","value":"unencrypted:{tz6}"}}]"#
        );

        let key_manager = parse_secret_keys(&input).expect("both schemes load");
        let mut schemes: Vec<Scheme> = key_manager
            .list_keys()
            .iter()
            .map(russignol_signer_lib::PublicKeyHash::scheme)
            .collect();
        schemes.sort_by_key(|s| format!("{s}"));

        assert_eq!(schemes, vec![Scheme::Bls, Scheme::Xmss]);
        assert_eq!(mark_params_from_manager(&key_manager).len(), 2);
    }

    /// Only a key that caches per epoch is worth warming, and the epoch is the
    /// one the store will hand out — warming any other builds a subtree the
    /// first signature does not use and leaves the one it does use cold.
    #[test]
    fn only_an_epoch_spending_key_is_warmed_and_at_the_epoch_it_will_spend() {
        use russignol_signer_lib::test_utils::new_mixed_watermark;

        let dir = tempfile::TempDir::new().unwrap();
        let (xmss_sk, _) = xmss::SecretKey::generate([21u8; 32], 4, 19).expect("range is valid");
        let tz6 = signer::Unencrypted::new(russignol_signer_lib::SecretKey::Xmss(
            std::sync::Arc::new(xmss_sk),
        ));
        let tz4 = signer::Unencrypted::generate(Some(&[22u8; 32])).unwrap();
        let tz6_pkh = *tz6.public_key_hash();

        let mut key_manager = ServerKeyManager::new();
        let keys: Vec<_> = [&tz6, &tz4]
            .into_iter()
            .map(|s| (*s.public_key_hash(), s.secret_key().epoch_range()))
            .collect();
        key_manager.add_signer(
            tz6.clone(),
            DeviceKey::XmssConsensus.device_alias().to_string(),
        );
        key_manager.add_signer(
            tz4,
            DeviceKey::Bls(KeyRole::Consensus)
                .device_alias()
                .to_string(),
        );

        let mut hwm = new_mixed_watermark(dir.path(), &keys).unwrap();
        hwm.seed_epoch_floor(&tz6_pkh, 0).unwrap();
        let floor = hwm.next_epoch(&tz6_pkh).unwrap();
        let watermark = RwLock::new(hwm);

        let warming = keys_to_warm(&key_manager, &watermark);

        assert_eq!(warming.len(), 1, "only the tz6 key spends epochs");
        assert_eq!(warming[0].0, tz6_pkh);
        assert_eq!(u64::from(warming[0].2), floor);
    }

    /// A signer that cannot come up is reported rather than retried forever.
    /// The listener binds a link-local address on an interface the init script
    /// brings up in the background, so an early failure is a race — but one
    /// that survives every attempt is a device that never signs, and the
    /// display error is all the operator gets before the baker stops attesting.
    #[test]
    fn a_signer_that_never_starts_reports_instead_of_retrying_forever() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = SignerConfig {
            watermark_dir: dir.path().to_string_lossy().into_owned(),
            // Parseable and unbindable: the failure recurs on every
            // attempt, which is what exhausts them.
            address: "203.0.113.1".to_string(),
            start_attempts: NonZeroU32::new(3).expect("three is not zero"),
            retry_delay: Duration::ZERO,
            ..Default::default()
        };
        let signer = signer::Unencrypted::generate(Some(&[19u8; 32])).unwrap();
        let mut key_manager = ServerKeyManager::new();
        key_manager.add_signer(
            signer,
            DeviceKey::Bls(KeyRole::Consensus)
                .device_alias()
                .to_string(),
        );

        let outcome = start_integrated_signer(
            &config,
            key_manager,
            &Arc::new(Mutex::new(SigningActivity::default())),
            None,
            &SignerCallbacks::default(),
            None,
            None,
        );

        let Err(e) = outcome else {
            panic!("a signer that cannot bind must report")
        };
        assert!(
            e.contains("203.0.113.1"),
            "the error names the address: {e}"
        );
    }

    /// A poisoned lock and a card with nothing to warm are one answer here, and
    /// the second costs the first signature of every loaded key the subtree
    /// build this list exists to take off the signing path. The guard is taken
    /// back from the poison rather than read as an empty list.
    #[test]
    fn a_poisoned_watermark_lock_still_reports_what_to_warm() {
        use russignol_signer_lib::test_utils::new_mixed_watermark;

        let dir = tempfile::TempDir::new().unwrap();
        let (xmss_sk, _) = xmss::SecretKey::generate([31u8; 32], 4, 19).expect("range is valid");
        let tz6 = signer::Unencrypted::new(russignol_signer_lib::SecretKey::Xmss(
            std::sync::Arc::new(xmss_sk),
        ));
        let tz6_pkh = *tz6.public_key_hash();
        let range = tz6.secret_key().epoch_range();
        let mut key_manager = ServerKeyManager::new();
        key_manager.add_signer(tz6, DeviceKey::XmssConsensus.device_alias().to_string());

        let mut hwm = new_mixed_watermark(dir.path(), &[(tz6_pkh, range)]).unwrap();
        hwm.seed_epoch_floor(&tz6_pkh, 0).unwrap();
        let watermark = Arc::new(RwLock::new(hwm));

        let poisoner = Arc::clone(&watermark);
        std::thread::spawn(move || {
            let _held = poisoner.write().unwrap();
            panic!("poisoning the watermark lock");
        })
        .join()
        .expect_err("the spawned thread panics while holding the lock");
        assert!(watermark.is_poisoned(), "the lock is poisoned");

        let warming = keys_to_warm(&key_manager, &watermark);

        assert_eq!(warming.len(), 1, "the tz6 key is still worth warming");
        assert_eq!(warming[0].0, tz6_pkh);
    }

    /// A key that spends epochs cannot sign until its record exists — a claim
    /// before one is `EpochNotInitialized` — and nothing between unlock and the
    /// first signing request establishes it. The store the unlock builds is
    /// therefore where the floor is established, at the key's own first epoch.
    #[test]
    fn the_unlock_store_establishes_a_floor_for_every_key_that_spends_epochs() {
        let dir = tempfile::TempDir::new().unwrap();
        let (xmss_sk, _) = xmss::SecretKey::generate([23u8; 32], 4, 19).expect("range is valid");
        let tz6 = signer::Unencrypted::new(russignol_signer_lib::SecretKey::Xmss(
            std::sync::Arc::new(xmss_sk),
        ));
        let tz4 = signer::Unencrypted::generate(Some(&[24u8; 32])).unwrap();
        let (tz6_pkh, tz4_pkh) = (*tz6.public_key_hash(), *tz4.public_key_hash());

        let mut key_manager = ServerKeyManager::new();
        key_manager.add_signer(tz6, DeviceKey::XmssConsensus.device_alias().to_string());
        key_manager.add_signer(
            tz4,
            DeviceKey::Bls(KeyRole::Consensus)
                .device_alias()
                .to_string(),
        );
        let config = SignerConfig {
            watermark_dir: dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        };

        let hwm = create_high_watermark(
            &config,
            &key_manager.list_keys(),
            mark_params_from_manager(&key_manager),
            ChainId::from_bytes(&[3u8; 32]),
        )
        .expect("a store over a writable directory")
        .expect("watermark checking is on");
        let mut wm = hwm.write().unwrap();

        assert_eq!(
            u64::from(wm.claim_epoch(&tz6_pkh).expect("a floor is established")),
            4,
            "the first claim hands out the key's own first epoch"
        );
        assert!(
            matches!(
                wm.claim_epoch(&tz4_pkh),
                Err(russignol_signer_lib::WatermarkError::NoEpochCounter { .. })
            ),
            "a key whose scheme spends no epochs gains no counter"
        );
    }

    /// The loader aborts rather than skipping, so an entry naming a scheme it
    /// does not hold stops the load instead of leaving a key silently absent.
    #[test]
    fn parse_secret_keys_aborts_on_an_entry_of_an_unknown_scheme() {
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let input = format!(
            r#"[{{"name":"{consensus}","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"other","value":"unencrypted:edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh"}}]"#
        );

        assert!(parse_secret_keys(&input).is_err());
    }

    /// A key that fails to parse must abort startup: silently dropping it
    /// boots a signer that can no longer sign for that pkh, and the baker
    /// stops attesting with nothing on the display.
    #[test]
    fn parse_secret_keys_rejects_any_unloadable_key() {
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let companion = DeviceKey::Bls(KeyRole::Companion).device_alias();
        let input = format!(
            r#"[{{"name":"{consensus}","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"{companion}","value":"unencrypted:BLsk3NotAValidKey"}}]"#
        );
        let Err(err) = parse_secret_keys(&input) else {
            panic!("unloadable key must abort")
        };
        assert!(
            err.contains(companion),
            "error must name the failing alias: {err}"
        );
    }

    #[test]
    fn parse_compact() {
        let input = format!(
            r#"[{{"name":"alice","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"bob","value":"unencrypted:{SAMPLE_SK}"}}]"#,
        );
        let entries = parse(&input).expect("compact parses");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name.as_ref(), "alice");
        assert_eq!(entries[0].value, format!("unencrypted:{SAMPLE_SK}"));
        assert_eq!(entries[1].name.as_ref(), "bob");
        assert_eq!(entries[1].value, format!("unencrypted:{SAMPLE_SK}"));
    }

    /// Backwards-compat: existing v2 (and v1) blobs in the field hold
    /// plaintext produced by `serde_json::to_string_pretty`. The reader
    /// must continue to accept that whitespace-rich form unchanged.
    #[test]
    fn parse_pretty_legacy() {
        let consensus = DeviceKey::Bls(KeyRole::Consensus).device_alias();
        let companion = DeviceKey::Bls(KeyRole::Companion).device_alias();
        let legacy = vec![
            OcamlKeyEntry {
                name: consensus.to_string(),
                value: format!("unencrypted:{SAMPLE_SK}"),
            },
            OcamlKeyEntry {
                name: companion.to_string(),
                value: format!("unencrypted:{SAMPLE_SK}"),
            },
        ];
        let pretty = serde_json::to_string_pretty(&legacy).expect("legacy emitter");

        let entries = parse(&pretty).expect("pretty-legacy parses");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name.as_ref(), consensus);
        assert_eq!(entries[0].value, format!("unencrypted:{SAMPLE_SK}"));
        assert_eq!(entries[1].name.as_ref(), companion);
        assert_eq!(entries[1].value, format!("unencrypted:{SAMPLE_SK}"));
    }

    #[test]
    fn parse_with_escapes_in_alias() {
        let input = r#"[{"name":"a\"b\\c","value":"unencrypted:abc"}]"#;
        let entries = parse(input).expect("escaped alias parses");
        assert_eq!(entries[0].name.as_ref(), "a\"b\\c");
        assert_eq!(entries[0].value, "unencrypted:abc");
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse(r#"{"name":"k","value":"v"}"#).is_err()); // not an array
        assert!(parse(r#"[{"name":"k","value":"v"}"#).is_err()); // unterminated array
        assert!(parse(r#"[{"name":"k","value":"v"}]xx"#).is_err()); // trailing garbage
        assert!(parse("").is_err()); // empty
    }

    /// A borrowed `value` is what keeps a secret out of a heap block nothing
    /// clears: an owned `String` per entry drops without zeroizing. The
    /// declaration does not settle that on its own, since `serde_json` copies
    /// wherever an escape forces it to, so the slice is read against the input's
    /// own address range.
    #[test]
    fn parse_borrows_value_from_input() {
        let input: String = format!(r#"[{{"name":"k","value":"unencrypted:{SAMPLE_SK}"}}]"#);
        let entries = parse(&input).expect("parses");
        let value: &str = entries[0].value;
        let input_start = input.as_ptr() as usize;
        let input_end = input_start + input.len();
        let value_start = value.as_ptr() as usize;
        assert!(
            (input_start..input_end).contains(&value_start),
            "value slice does not point into the input buffer (parser allocated)",
        );
    }
}
