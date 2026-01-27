use log::{error, info};
use russignol_signer_lib::{
    ChainId, HighWatermark, RequestHandler, ServerKeyManager, SignerServer, SigningActivity,
    UnencryptedSigner,
};
use serde::Deserialize;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct OcamlKeyEntry<T> {
    name: String,
    value: T,
}

/// Configuration for the integrated signer
pub struct SignerConfig {
    /// Directory for watermarks (on /data partition)
    pub watermark_dir: String,
    pub address: String,
    pub port: u16,
    pub magic_bytes: Vec<u8>,
    pub check_high_watermark: bool,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            watermark_dir: "/data/watermarks".to_string(),
            address: "169.254.1.1".to_string(),
            port: 7732,
            magic_bytes: vec![0x11, 0x12, 0x13],
            check_high_watermark: true,
        }
    }
}

/// Parse secret keys JSON and create a `KeyManager`
///
/// Keys are passed directly in memory after PIN decryption - never written to disk.
fn parse_secret_keys(secret_keys_json: &str) -> Result<ServerKeyManager, String> {
    let mut key_manager = ServerKeyManager::new();

    let sk_entries: Vec<OcamlKeyEntry<String>> = serde_json::from_str(secret_keys_json)
        .map_err(|e| format!("Failed to parse secret_keys JSON: {e}"))?;

    if sk_entries.is_empty() {
        return Err("No keys found in secret_keys".to_string());
    }

    info!("Loading {} key(s)...", sk_entries.len());

    for entry in sk_entries {
        let sk_b58 = if let Some(unenc) = entry.value.strip_prefix("unencrypted:") {
            unenc
        } else {
            &entry.value
        };

        match UnencryptedSigner::from_b58check(sk_b58) {
            Ok(signer) => {
                let pkh = *signer.public_key_hash();
                key_manager.add_signer(pkh, signer, entry.name.clone());
                info!("  ✓ Loaded key: {} ({})", entry.name, pkh.to_b58check());
            }
            Err(e) => {
                error!("  ✗ Failed to load key '{}': {}", entry.name, e);
            }
        }
    }

    Ok(key_manager)
}

use russignol_signer_lib::bls::PublicKeyHash;

/// Type alias for watermark error callback
pub type WatermarkErrorCallback =
    Arc<dyn Fn(PublicKeyHash, ChainId, &russignol_signer_lib::WatermarkError) + Send + Sync>;

/// Type alias for large level gap callback
pub type LargeGapCallback = Arc<dyn Fn(PublicKeyHash, ChainId, u32, u32) + Send + Sync>;

/// Callbacks for the integrated signer
#[derive(Default)]
pub struct SignerCallbacks {
    /// Called when a watermark error occurs
    pub watermark_error: Option<WatermarkErrorCallback>,
    /// Called after each successful signing operation
    pub signing: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Called when a large level gap is detected (pkh, `chain_id`, `current_level`, `new_level`)
    pub large_gap: Option<LargeGapCallback>,
}

/// Create high watermark tracker based on config
///
/// Watermarks are stored on the data partition (/data/watermarks) which is
/// separate from keys to allow write operations without affecting the
/// read-only keys partition.
pub fn create_high_watermark(
    config: &SignerConfig,
) -> Result<Option<Arc<RwLock<HighWatermark>>>, String> {
    if config.check_high_watermark {
        let hwm_dir = PathBuf::from(&config.watermark_dir);
        fs::create_dir_all(&hwm_dir)
            .map_err(|e| format!("Failed to create watermark directory: {e}"))?;

        let hwm = HighWatermark::new(&hwm_dir)
            .map_err(|e| format!("Failed to create high watermark: {e}"))?;

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

/// Start the integrated signer server
///
/// `secret_keys_json` contains the decrypted secret keys - passed in memory, never written to disk.
pub fn start_integrated_signer(
    config: &SignerConfig,
    secret_keys_json: &str,
    signing_activity: &Arc<Mutex<SigningActivity>>,
    watermark: Option<&Arc<RwLock<HighWatermark>>>,
    callbacks: &SignerCallbacks,
    blocks_per_cycle: Option<u32>,
) -> Result<(), String> {
    loop {
        match run_signer_once(
            config,
            secret_keys_json,
            watermark.cloned(),
            signing_activity.clone(),
            callbacks,
            blocks_per_cycle,
        ) {
            Ok(()) => {
                info!("Signer stopped normally");
                break Ok(());
            }
            Err(e) => {
                error!("Signer error: {e}. Restarting in 5 seconds...");
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

fn run_signer_once(
    config: &SignerConfig,
    secret_keys_json: &str,
    watermark: Option<Arc<RwLock<HighWatermark>>>,
    signing_activity: Arc<Mutex<SigningActivity>>,
    callbacks: &SignerCallbacks,
    blocks_per_cycle: Option<u32>,
) -> Result<(), String> {
    info!("Starting signer...");

    // Parse keys directly from memory - never touches disk
    let key_manager = parse_secret_keys(secret_keys_json)?;

    // Create chain ID (mainnet)
    let _chain_id = ChainId::from_bytes(&[
        0x7a, 0x06, 0xa7, 0x70, // NetXdQprcVkpaWU (mainnet)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    // Create request handler
    let mut handler = RequestHandler::new(
        Arc::new(RwLock::new(key_manager)),
        watermark,
        Some(config.magic_bytes.clone()),
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

    // Wire up large level gap detection if blocks_per_cycle is configured
    if let (Some(callback), Some(bpc)) = (&callbacks.large_gap, blocks_per_cycle) {
        handler = handler.with_large_gap_callback(callback.clone(), bpc);
    }

    // Resolve address
    let addr_str = format!("{}:{}", config.address, config.port);
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("Failed to parse address '{addr_str}': {e}"))?;

    // Create server with 30-second connection timeout to prevent stale threads
    // on USB disconnect events
    let server = SignerServer::new(addr, Arc::new(handler), Some(Duration::from_secs(30)));

    info!("🚀 Signer server listening on {addr}");
    info!("📡 Waiting for connections...");

    server.run().map_err(|e| format!("Server error: {e}"))
}
