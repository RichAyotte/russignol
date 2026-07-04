use log::{error, info};
use russignol_signer_lib::{
    ChainId, HighWatermark, RequestHandler, ServerKeyManager, SigningActivity, server, signer,
};
use serde::Deserialize;
use std::borrow::Cow;
use std::fs;
use std::net::SocketAddr;
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
struct BorrowedKeyEntry<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    value: &'a str,
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

/// Parse secret keys JSON and create a `KeyManager`.
///
/// Keys are passed in memory after PIN decryption — never written to disk.
fn parse_secret_keys(secret_keys_json: &str) -> Result<ServerKeyManager, String> {
    let entries: Vec<BorrowedKeyEntry<'_>> = serde_json::from_str(secret_keys_json)
        .map_err(|e| format!("Failed to parse secret_keys JSON: {e}"))?;

    if entries.is_empty() {
        return Err("No keys found in secret_keys".to_string());
    }

    info!("Loading {} key(s)...", entries.len());

    let mut key_manager = ServerKeyManager::new();
    for entry in entries {
        let sk_b58 = entry
            .value
            .strip_prefix("unencrypted:")
            .unwrap_or(entry.value);
        let alias = entry.name;

        match signer::Unencrypted::from_b58check(sk_b58) {
            Ok(signer) => {
                let pkh = *signer.public_key_hash();
                let alias_owned = alias.into_owned();
                info!("  ✓ Loaded key: {alias_owned} ({})", pkh.to_b58check());
                key_manager.add_signer(pkh, signer, alias_owned);
            }
            // Abort rather than skip: a signer missing one of its keys boots
            // normally but silently stops signing for that pkh.
            Err(e) => {
                error!("  ✗ Failed to load key '{alias}': {e}");
                return Err(format!("Failed to load key '{alias}': {e}"));
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

/// Type alias for missing watermark callback (pkh, `chain_id`, `requested_level`)
pub type MissingWatermarkCallback = Arc<dyn Fn(PublicKeyHash, ChainId, u32) + Send + Sync>;

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
    /// Called before each signing operation (e.g., CPU frequency boost)
    pub pre_sign: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Called after each signing operation (e.g., CPU frequency restore)
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
) -> Result<Option<Arc<RwLock<HighWatermark>>>, String> {
    if config.check_high_watermark {
        let hwm_dir = PathBuf::from(&config.watermark_dir);
        fs::create_dir_all(&hwm_dir)
            .map_err(|e| format!("Failed to create watermark directory: {e}"))?;

        let hwm = HighWatermark::new(&hwm_dir, pkhs)
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
    // Parse keys directly from memory - never touches disk. Parsed outside
    // the retry loop: a key failure is deterministic, so retrying can never
    // fix it — it must surface to the caller instead.
    let key_manager = Arc::new(RwLock::new(parse_secret_keys(secret_keys_json)?));

    loop {
        match run_signer_once(
            config,
            key_manager.clone(),
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
    key_manager: Arc<RwLock<ServerKeyManager>>,
    watermark: Option<Arc<RwLock<HighWatermark>>>,
    signing_activity: Arc<Mutex<SigningActivity>>,
    callbacks: &SignerCallbacks,
    blocks_per_cycle: Option<u32>,
) -> Result<(), String> {
    info!("Starting signer...");

    // Create request handler
    let mut handler = RequestHandler::new(
        key_manager,
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

    if let Some(ref callback) = callbacks.missing_watermark {
        handler = handler.with_watermark_missing_callback(callback.clone());
    }

    if let Some(ref callback) = callbacks.pre_sign {
        handler = handler.with_pre_sign_callback(callback.clone());
    }
    if let Some(ref callback) = callbacks.post_sign {
        handler = handler.with_post_sign_callback(callback.clone());
    }

    // Resolve address
    let addr_str = format!("{}:{}", config.address, config.port);
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("Failed to parse address '{addr_str}': {e}"))?;

    // Create server with 30-second connection timeout to prevent stale threads
    // on USB disconnect events
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(30)));

    info!("🚀 Signer server listening on {addr}");
    info!("📡 Waiting for connections...");

    server.run().map_err(|e| format!("Server error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::wallet::OcamlKeyEntry;

    const SAMPLE_SK: &str = "BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x";

    fn parse(input: &str) -> Result<Vec<BorrowedKeyEntry<'_>>, serde_json::Error> {
        serde_json::from_str(input)
    }

    #[test]
    fn parse_secret_keys_loads_all_valid_keys() {
        let other_sk = signer::Unencrypted::generate(Some(&[7u8; 32]))
            .unwrap()
            .secret_key()
            .to_b58check();
        let input = format!(
            r#"[{{"name":"consensus","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"companion","value":"unencrypted:{other_sk}"}}]"#
        );
        let key_manager = parse_secret_keys(&input).expect("valid keys load");
        assert_eq!(key_manager.list_keys().len(), 2);
    }

    /// A key that fails to parse must abort startup: silently dropping it
    /// boots a signer that can no longer sign for that pkh, and the baker
    /// stops attesting with nothing on the display.
    #[test]
    fn parse_secret_keys_rejects_any_unloadable_key() {
        let input = format!(
            r#"[{{"name":"consensus","value":"unencrypted:{SAMPLE_SK}"}},{{"name":"companion","value":"unencrypted:BLsk3NotAValidKey"}}]"#
        );
        let Err(err) = parse_secret_keys(&input) else {
            panic!("unloadable key must abort")
        };
        assert!(
            err.contains("companion"),
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
        let legacy = vec![
            OcamlKeyEntry {
                name: "consensus".to_string(),
                value: format!("unencrypted:{SAMPLE_SK}"),
            },
            OcamlKeyEntry {
                name: "companion".to_string(),
                value: format!("unencrypted:{SAMPLE_SK}"),
            },
        ];
        let pretty = serde_json::to_string_pretty(&legacy).expect("legacy emitter");

        let entries = parse(&pretty).expect("pretty-legacy parses");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name.as_ref(), "consensus");
        assert_eq!(entries[0].value, format!("unencrypted:{SAMPLE_SK}"));
        assert_eq!(entries[1].name.as_ref(), "companion");
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

    /// Load-bearing for the leak fix: `value: &'a str` forces `serde_json`
    /// to slice into the input rather than allocate a fresh `String` per
    /// entry. If a future refactor changes `value`'s type to one that
    /// owns its bytes, this test catches it via a pointer-range check.
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
