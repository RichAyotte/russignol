//! TCP server implementation for russignol-signer
//!
//! This module implements the TCP server that accepts connections from octez-client
//! and handles signing requests using the binary protocol.
//!
//! Corresponds to: `src/bin_signer/socket_daemon.ml`

use crate::bls::{PublicKey, PublicKeyHash};
use crate::high_watermark::{ChainId, HighWatermark};
use crate::magic_bytes;
use crate::protocol::encoding::{decode_request, encode_response};
use crate::protocol::{SignerRequest, SignerResponse};
use crate::signer::{Handler, Unencrypted};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::Duration;

// Concurrency tracking for performance profiling
#[cfg(feature = "perf-trace")]
static ACTIVE_REQUEST_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// RAII guard for connection counting
/// Automatically increments counter on creation and decrements on drop
struct ConnectionGuard {
    counter: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl ConnectionGuard {
    fn new(counter: Option<Arc<std::sync::atomic::AtomicUsize>>) -> Self {
        if let Some(ref c) = counter {
            let count = c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!("Connection established - count: {} -> {}", count, count + 1);
        }
        Self { counter }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(ref c) = self.counter {
            let count = c.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!("Connection closed - count: {} -> {}", count, count - 1);
        }
    }
}

/// RAII guard for request concurrency tracking
/// Automatically increments counter on creation and decrements on drop
#[cfg(feature = "perf-trace")]
struct RequestGuard {
    addr: SocketAddr,
}

#[cfg(feature = "perf-trace")]
impl RequestGuard {
    fn new(addr: SocketAddr) -> Self {
        let prev_count = ACTIVE_REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        log::info!(
            "[CONCURRENCY] Request started (from {addr}), {} active (was {})",
            prev_count + 1,
            prev_count
        );
        Self { addr }
    }
}

#[cfg(feature = "perf-trace")]
impl Drop for RequestGuard {
    fn drop(&mut self) {
        let prev_count = ACTIVE_REQUEST_COUNT.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        log::info!(
            "[CONCURRENCY] Request completed (from {}), {} still active (was {})",
            self.addr,
            prev_count - 1,
            prev_count
        );
    }
}

/// Server error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(#[from] crate::protocol::Error),

    /// Signer error
    #[error("Signer error: {0}")]
    Signer(#[from] crate::signer::Error),

    /// Watermark error
    #[error("Watermark error: {0}")]
    Watermark(#[from] crate::high_watermark::WatermarkError),

    /// Magic byte error
    #[error("Magic byte error: {0}")]
    MagicByte(#[from] crate::magic_bytes::MagicByteError),

    /// Timeout error
    #[error("Connection timeout")]
    Timeout,

    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Authentication required
    #[error("Authentication required")]
    AuthRequired,

    /// Operation not authorized
    #[error("Operation not authorized: {0}")]
    NotAuthorized(String),

    /// Message too large
    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),

    /// Internal server error (lock poisoned)
    #[error("Internal server error: {0}")]
    Internal(String),
}

/// Result type for server operations
pub type Result<T> = std::result::Result<T, Error>;

// Implement From for PoisonError to enable ? operator on lock operations
impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        Error::Internal(format!("Lock poisoned: {e}"))
    }
}

/// Key manager for storing and retrieving signers
pub struct KeyManager {
    /// Map of public key hash to signer
    signers: HashMap<PublicKeyHash, Unencrypted>,
    /// Map of public key hash to key name
    key_names: HashMap<PublicKeyHash, String>,
}

impl KeyManager {
    /// Create new empty key manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            signers: HashMap::new(),
            key_names: HashMap::new(),
        }
    }

    /// Add a signer with its name
    pub fn add_signer(&mut self, pkh: PublicKeyHash, signer: Unencrypted, name: String) {
        self.signers.insert(pkh, signer);
        self.key_names.insert(pkh, name);
    }

    /// Get a signer by public key hash
    ///
    /// # Errors
    ///
    /// Returns an error if no signer is registered for the given public key hash.
    pub fn get_signer(&self, pkh: &PublicKeyHash) -> Result<&Unencrypted> {
        self.signers
            .get(pkh)
            .ok_or_else(|| Error::KeyNotFound(pkh.to_b58check()))
    }

    /// Get the name of a key by public key hash
    #[must_use]
    pub fn get_key_name(&self, pkh: &PublicKeyHash) -> Option<&str> {
        self.key_names.get(pkh).map(String::as_str)
    }

    /// List all known public key hashes in deterministic global role order.
    ///
    /// Roles from [`crate::key_role::KeyRole::ALL`] come first (consensus, then
    /// companion), matched case-insensitively so stored casing cannot reshuffle
    /// the prefix. Any non-role keys follow. Both groups break ties by base58
    /// pkh, so `HashMap` iteration order cannot reach the result even when two
    /// stored keys carry the same alias.
    ///
    /// The host utility expects `[0]` = consensus and `[1]` = companion when
    /// both roles are present.
    #[must_use]
    pub fn list_keys(&self) -> Vec<PublicKeyHash> {
        use crate::key_role::KeyRole;

        let mut keys = Vec::with_capacity(self.signers.len());
        let mut seen = std::collections::HashSet::with_capacity(KeyRole::COUNT);
        for role in KeyRole::ALL {
            let alias = role.device_alias();
            if let Some(pkh) = self
                .key_names
                .iter()
                .filter(|(_, name)| name.eq_ignore_ascii_case(alias))
                .map(|(pkh, _)| *pkh)
                .min_by_key(PublicKeyHash::to_b58check)
            {
                keys.push(pkh);
                seen.insert(pkh);
            }
        }
        let mut extras: Vec<PublicKeyHash> = self
            .signers
            .keys()
            .filter(|pkh| !seen.contains(*pkh))
            .copied()
            .collect();
        extras.sort_by_cached_key(PublicKeyHash::to_b58check);
        keys.extend(extras);
        keys
    }

    /// Iterate loaded signers (pkh, signer) for one-pass MAC-key derivation after parse.
    pub fn iter_signers(&self) -> impl Iterator<Item = (&PublicKeyHash, &Unencrypted)> {
        self.signers.iter()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for watermark error callback (passes structured error reference for better handling)
type WatermarkErrorCallback =
    Arc<dyn Fn(PublicKeyHash, ChainId, &crate::high_watermark::WatermarkError) + Send + Sync>;

/// Type alias for large level gap callback (pkh, `chain_id`, `current_level`, `requested_level`)
type LargeGapCallback = Arc<dyn Fn(PublicKeyHash, ChainId, u32, u32) + Send + Sync>;

/// Type alias for missing watermark callback (pkh, `chain_id`, `requested_level`)
type MissingWatermarkCallback = Arc<dyn Fn(PublicKeyHash, ChainId, u32) + Send + Sync>;

/// Type alias for unknown-key callback (the requested pkh the signer does not hold)
type UnknownKeyCallback = Arc<dyn Fn(PublicKeyHash) + Send + Sync>;

/// Type alias for signing notification callback (called after each successful signature)
type SigningNotifyCallback = Arc<dyn Fn() + Send + Sync>;

/// Number of cycles threshold for large level gap detection. A signing request
/// whose level exceeds the current watermark by more than this many cycles is
/// refused at signing time and raises a touchscreen alert, so it is also the
/// point past which a card's floor is "meaningfully" behind the chain.
pub const LARGE_GAP_CYCLES: u32 = 4;

/// Request handler for processing signer requests
///
/// Corresponds to: src/bin_signer/handler.ml:275-309
pub struct RequestHandler {
    /// Key manager
    keys: Arc<RwLock<KeyManager>>,
    /// High watermark tracker (if enabled)
    watermark: Option<Arc<RwLock<HighWatermark>>>,
    /// Provisioned chain id, cached at construction (immutable on `HighWatermark`).
    /// Lets Sign reject foreign-chain ops without taking the watermark lock.
    provisioned_chain_id: Option<ChainId>,
    /// Allowed magic bytes (static slice — no per-request clone)
    allowed_magic_bytes: Option<&'static [u8]>,
    /// Allow listing known keys
    allow_list_known_keys: bool,
    /// Allow proof of possession
    allow_prove_possession: bool,
    /// Signing activity tracker (if enabled)
    signing_activity: Option<Arc<std::sync::Mutex<crate::signing_activity::SigningActivity>>>,
    /// Callback for watermark errors
    watermark_error_callback: Option<WatermarkErrorCallback>,
    /// Callback to notify when a signature is completed (for UI refresh)
    signing_notify_callback: Option<SigningNotifyCallback>,
    /// Callback for large level gap detection
    large_gap_callback: Option<LargeGapCallback>,
    /// Callback for missing (uninitialized) watermark detection
    missing_watermark_callback: Option<MissingWatermarkCallback>,
    /// Callback for signing requests naming a key the signer does not hold
    unknown_key_callback: Option<UnknownKeyCallback>,
    /// Blocks per cycle (chain-specific, used for gap threshold calculation)
    blocks_per_cycle: Option<u32>,
    /// Callback invoked when a TCP connection opens (e.g., CPU frequency boost)
    pre_sign_callback: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Callback invoked when a TCP connection closes (e.g., CPU frequency restore)
    post_sign_callback: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Latches the two activity-recording failures below. Both are permanent
    /// once hit, and the sign path runs ~3x every 6s, so an unlatched error
    /// would churn the size-capped device log until real history is evicted.
    unknown_alias_reported: std::sync::atomic::AtomicBool,
    activity_poison_reported: std::sync::atomic::AtomicBool,
}

impl RequestHandler {
    /// Create new request handler
    pub fn new(
        keys: Arc<RwLock<KeyManager>>,
        watermark: Option<Arc<RwLock<HighWatermark>>>,
        allowed_magic_bytes: Option<&'static [u8]>,
        allow_list_known_keys: bool,
        allow_prove_possession: bool,
    ) -> Self {
        let provisioned_chain_id = watermark.as_ref().map(|arc| match arc.read() {
            Ok(wm) => wm.chain_id(),
            Err(poisoned) => poisoned.into_inner().chain_id(),
        });
        Self {
            keys,
            watermark,
            provisioned_chain_id,
            allowed_magic_bytes,
            allow_list_known_keys,
            allow_prove_possession,
            signing_activity: None,
            watermark_error_callback: None,
            signing_notify_callback: None,
            large_gap_callback: None,
            missing_watermark_callback: None,
            unknown_key_callback: None,
            blocks_per_cycle: None,
            pre_sign_callback: None,
            post_sign_callback: None,
            unknown_alias_reported: std::sync::atomic::AtomicBool::new(false),
            activity_poison_reported: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Set signing activity tracker
    #[must_use]
    pub fn with_signing_activity(
        mut self,
        signing_activity: Arc<std::sync::Mutex<crate::signing_activity::SigningActivity>>,
    ) -> Self {
        self.signing_activity = Some(signing_activity);
        self
    }

    /// Set watermark error callback (receives structured error reference for better handling)
    #[must_use]
    pub fn with_watermark_error_callback(mut self, callback: WatermarkErrorCallback) -> Self {
        self.watermark_error_callback = Some(callback);
        self
    }

    /// Set signing notification callback (called after each successful signature)
    #[must_use]
    pub fn with_signing_notify(mut self, callback: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.signing_notify_callback = Some(callback);
        self
    }

    /// Set large level gap detection callback and threshold
    ///
    /// When a signing request arrives with a level gap exceeding 4 cycles,
    /// the callback is invoked to notify the UI for user confirmation.
    #[must_use]
    pub fn with_large_gap_callback(
        mut self,
        callback: Arc<dyn Fn(PublicKeyHash, ChainId, u32, u32) + Send + Sync>,
        blocks_per_cycle: u32,
    ) -> Self {
        self.large_gap_callback = Some(callback);
        self.blocks_per_cycle = Some(blocks_per_cycle);
        self
    }

    /// Set missing watermark detection callback.
    ///
    /// When a signing request arrives for a key with no initialized watermark,
    /// the callback is invoked so the UI can offer on-device recovery. Signing
    /// still fails with `NotInitialized`; the callback only supplies the
    /// requested level the confirmation needs.
    #[must_use]
    pub fn with_watermark_missing_callback(
        mut self,
        callback: Arc<dyn Fn(PublicKeyHash, ChainId, u32) + Send + Sync>,
    ) -> Self {
        self.missing_watermark_callback = Some(callback);
        self
    }

    /// Set unknown-key detection callback.
    ///
    /// When a signing request names a key the signer does not hold, the
    /// callback is invoked so the UI can alert the operator that the baker
    /// is signing for the wrong keys. Signing still fails with `KeyNotFound`;
    /// the callback only supplies the requested pkh.
    #[must_use]
    pub fn with_unknown_key_callback(mut self, callback: UnknownKeyCallback) -> Self {
        self.unknown_key_callback = Some(callback);
        self
    }

    /// Set pre-connection callback (called when a client TCP connection opens).
    ///
    /// Must not block: octez opens a new connection per sign, so stalls here
    /// add directly to inter-sign latency (pre→att forge gap).
    #[must_use]
    pub fn with_pre_sign_callback(mut self, callback: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.pre_sign_callback = Some(callback);
        self
    }

    /// Set post-connection callback (called when a client TCP connection closes).
    ///
    /// Must not block: the next connection's pre-callback may already be running
    /// on another thread and must not wait on work started here.
    #[must_use]
    pub fn with_post_sign_callback(mut self, callback: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.post_sign_callback = Some(callback);
        self
    }

    /// Notify that a client connection has opened (e.g., boost CPU frequency).
    pub fn notify_request_received(&self) {
        if let Some(ref callback) = self.pre_sign_callback {
            callback();
        }
    }

    /// Notify that a client connection has closed (e.g., restore CPU frequency).
    pub fn notify_request_complete(&self) {
        if let Some(ref callback) = self.post_sign_callback {
            callback();
        }
    }

    /// Resolve a pkh to its signer (and alias), firing the unknown-key callback
    /// when the signer does not hold the key.
    ///
    /// Every pkh-bearing request path must resolve through here so a baker
    /// misconfigured with an unheld key is surfaced no matter which request
    /// type arrives first — public-key and proof-of-possession lookups at
    /// baker startup, not just Sign.
    ///
    /// Returns one clone of the signer so the keys lock can be dropped before
    /// watermark I/O or BLS work. Call sites must not resolve the same pkh twice.
    ///
    /// The keys lock is released before any UI callback so a callback cannot
    /// deadlock against another keys reader/writer.
    fn resolve_signer(&self, pkh: &PublicKeyHash) -> Result<(Unencrypted, String)> {
        let result = {
            let keys = self.keys.read()?;
            match keys.get_signer(pkh) {
                Ok(signer) => {
                    let name = keys.get_key_name(pkh).unwrap_or("").to_lowercase();
                    Ok((signer.clone(), name))
                }
                Err(e) => Err(e),
            }
        };
        if matches!(result, Err(Error::KeyNotFound(_)))
            && let Some(ref callback) = self.unknown_key_callback
        {
            callback(*pkh);
        }
        result
    }

    /// Resolve a pkh to its signer only (drops the alias).
    fn get_signer_or_alert(&self, pkh: &PublicKeyHash) -> Result<Unencrypted> {
        self.resolve_signer(pkh).map(|(signer, _)| signer)
    }

    /// Handle a signer request
    ///
    /// # Errors
    ///
    /// Returns an error if the requested key is not found, signing fails, or a watermark
    /// violation is detected.
    pub fn handle_request(&self, req: SignerRequest) -> Result<(SignerResponse, Option<ChainId>)> {
        match req {
            SignerRequest::Sign {
                pkh,
                data,
                signature: _,
            } => self.handle_sign(pkh, &data),
            SignerRequest::PublicKey { pkh } => {
                self.handle_public_key(pkh).map(|resp| (resp, None))
            }
            SignerRequest::AuthorizedKeys => Ok((Self::handle_authorized_keys(), None)),
            SignerRequest::DeterministicNonce {
                pkh,
                data,
                signature: _,
            } => self
                .handle_deterministic_nonce(pkh.0, &data)
                .map(|resp| (resp, None)),
            SignerRequest::DeterministicNonceHash {
                pkh,
                data,
                signature: _,
            } => self
                .handle_deterministic_nonce_hash(pkh.0, &data)
                .map(|resp| (resp, None)),
            SignerRequest::SupportsDeterministicNonces { pkh } => self
                .handle_supports_deterministic_nonces(pkh)
                .map(|resp| (resp, None)),
            SignerRequest::KnownKeys => self.handle_known_keys().map(|resp| (resp, None)),
            SignerRequest::BlsProveRequest { pkh, override_pk } => self
                .handle_bls_prove(pkh, override_pk.as_ref())
                .map(|resp| (resp, None)),
        }
    }

    /// Handle sign request
    #[expect(
        clippy::too_many_lines,
        reason = "signing flow with watermark validation"
    )]
    fn handle_sign(
        &self,
        pkh_and_version: (PublicKeyHash, u8),
        data: &[u8],
    ) -> Result<(SignerResponse, Option<ChainId>)> {
        let (pkh, version) = pkh_and_version;
        log::debug!(
            "Signature request for key: {} (version {})",
            pkh.to_b58check(),
            version
        );

        #[cfg(feature = "perf-trace")]
        let request_start = std::time::Instant::now();

        // 1. Check magic byte
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        if let Some(allowed) = self.allowed_magic_bytes {
            magic_bytes::check_magic_byte(data, Some(allowed))?;
        }

        #[cfg(feature = "perf-trace")]
        log::info!("[PERF] Magic byte check: {:?}", t.elapsed());

        // A key the signer does not hold can never be signed, and the watermark
        // checks below would otherwise offer recovery for it. Reject it here so
        // the missing-watermark dialog is reserved for keys we can actually sign.
        // Single resolve: one keys-map read and one Unencrypted clone for the
        // whole request (BLS sign runs after the keys lock is dropped).
        let (signer, key_name) = self.resolve_signer(&pkh)?;

        // 2. Check high watermark
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        // Parse tenderbake fields once for prechecks, activity, and check_and_update.
        // BLS-only: attestation/preattestation layout always uses is_bls=true.
        let parsed = Self::parse_sign_payload(data);
        let operation_chain_id = parsed.chain_id;

        // The device signs only for its provisioned chain. Reject a foreign-chain
        // operation before any watermark logic so it cannot raise a gap/missing/level
        // dialog. A wrong chain is never operator-recoverable, so this takes the
        // silent watermark-error path (no recovery dialog), like RoundTooLow.
        // provisioned_chain_id is cached at construction — no watermark lock here.
        if let Some(op_chain) = operation_chain_id
            && let Some(provisioned) = self.provisioned_chain_id
            && op_chain != provisioned
        {
            let err = crate::high_watermark::WatermarkError::ChainMismatch {
                expected: provisioned.to_b58check(),
                got: op_chain.to_b58check(),
            };
            if let Some(ref callback) = self.watermark_error_callback {
                callback(pkh, op_chain, &err);
            }
            return Err(Error::Watermark(err));
        }

        // 2a + 2a'. Large-gap and missing-watermark prechecks under one read.
        // Drop the lock before any UI callback. Precedence: missing floor first
        // (no current level), else large gap when the floor exists.
        if let Some(chain_id) = operation_chain_id
            && let Some(ref watermark) = self.watermark
            && let Some(requested_level) = parsed.level
        {
            let check_gap = self.large_gap_callback.is_some()
                && self.blocks_per_cycle.is_some_and(|bpc| bpc > 0);
            let check_missing = self.missing_watermark_callback.is_some();
            if check_gap || check_missing {
                let current_level = {
                    let wm = watermark.read()?;
                    wm.get_current_level(chain_id, &pkh)
                };
                match current_level {
                    None if check_missing => {
                        if let Some(ref callback) = self.missing_watermark_callback {
                            callback(pkh, chain_id, requested_level);
                        }
                        return Err(Error::Watermark(
                            crate::high_watermark::WatermarkError::NotInitialized {
                                chain_id: chain_id.to_b58check(),
                                pkh: pkh.to_b58check(),
                            },
                        ));
                    }
                    Some(current_level) if check_gap => {
                        let blocks_per_cycle = self.blocks_per_cycle.unwrap();
                        let gap = requested_level.saturating_sub(current_level);
                        let threshold = LARGE_GAP_CYCLES * blocks_per_cycle;
                        if gap > threshold {
                            if let Some(ref callback) = self.large_gap_callback {
                                callback(pkh, chain_id, current_level, requested_level);
                            }
                            let cycles = gap / blocks_per_cycle;
                            return Err(Error::Watermark(
                                crate::high_watermark::WatermarkError::LargeLevelGap {
                                    current_level,
                                    requested_level,
                                    gap,
                                    cycles,
                                },
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }

        #[cfg(feature = "perf-trace")]
        log::info!("[PERF] Watermark check: {:?}", t.elapsed());

        // Magic bytes already checked on the request; sign via Unencrypted
        // directly so we do not rebuild a Handler (and re-check magic) per sign.
        let sign_data = || signer.sign(data, None, None);

        // 2b+4. Check watermark, then BLS sign + watermark persist in parallel.
        //    Write lock is held from check_and_update through write_watermark to
        //    prevent concurrent requests from interleaving disk writes.
        //    Both must succeed before the signature is returned.
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        let sign_start = std::time::Instant::now();

        let (signature, sign_duration) = if let Some(chain_id) = operation_chain_id
            && let Some(ref watermark) = self.watermark
        {
            let mut wm = watermark.write()?;
            let watermark_update = match (parsed.op_type, parsed.level, parsed.round) {
                (Some(op_type), Some(level), Some(round)) => {
                    wm.check_and_update_parsed(chain_id, &pkh, op_type, level, round)
                }
                // Parse failed for a tenderbake body, or non-watermarked magic
                // with a chain id: re-enter the data path for InvalidData / None.
                _ => wm.check_and_update(chain_id, &pkh, data),
            };
            let watermark_update = match watermark_update {
                Ok(update) => update,
                Err(e) => {
                    // Drop lock BEFORE calling callback to avoid deadlock
                    // The callback may trigger UI events that could contend for locks
                    drop(wm);
                    if let Some(ref callback) = self.watermark_error_callback {
                        callback(pkh, chain_id, &e);
                    }
                    return Err(Error::Watermark(e));
                }
            };

            if let Some(ref update) = watermark_update {
                // Fast path: ceiling on stable storage covers this update — no disk
                // I/O needed, just BLS sign. The background ceiling thread will
                // update the file after we return the signature.
                // Slow path: no ceiling — fdatasync needed, parallelize with BLS.
                let (sign_result, write_result) = if wm.ceiling_covers(update) {
                    (sign_data(), Ok(()))
                } else {
                    std::thread::scope(|s| {
                        let sign_handle = s.spawn(sign_data);
                        let write_result = wm.write_watermark(update);
                        (
                            sign_handle.join().expect("sign thread panicked"),
                            write_result,
                        )
                    })
                };

                // If either failed, roll back in-memory so baker can retry at this level.
                // Roll back disk too if it was the sign that failed (disk already written).
                if sign_result.is_err() || write_result.is_err() {
                    wm.rollback_update(update);
                    if sign_result.is_err()
                        && write_result.is_ok()
                        && let Err(e) = wm.rollback_disk_watermark(update)
                    {
                        log::warn!("Failed to roll back disk watermark: {e}");
                    }
                }

                // Release write lock — both check and persist are complete
                drop(wm);

                // If watermark write failed, refuse to return signature (fail-safe)
                if let Err(e) = write_result {
                    log::error!(
                        "CRITICAL: Watermark write failed, refusing to return signature: {e}"
                    );
                    return Err(Error::Watermark(e));
                }

                let signature = sign_result?;

                // Schedule background ceiling write for the next expected level.
                // Delayed 1s so the full signing burst (~3 signs in ~20ms)
                // completes before any ceiling thread acquires the write lock.
                if let Some(ceil_level) = update.level().checked_add(1) {
                    let watermark_arc = Arc::clone(watermark);
                    let ceil_pkh = update.pkh();
                    let ceil_idx = update.idx();
                    let notify = self.signing_notify_callback.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(1));
                        let ok = if let Ok(mut wm) = watermark_arc.write() {
                            match wm.write_ceiling(ceil_pkh, ceil_idx, ceil_level) {
                                Ok(()) => true,
                                Err(e) => {
                                    log::warn!("Failed to write ceiling watermark: {e}");
                                    false
                                }
                            }
                        } else {
                            false
                        };
                        if ok && let Some(ref cb) = notify {
                            cb();
                        }
                    });
                }

                (signature, sign_start.elapsed())
            } else {
                // Non-watermarked operation type
                drop(wm);
                let signature = sign_data()?;
                (signature, sign_start.elapsed())
            }
        } else {
            // No watermark configured — just sign
            let signature = sign_data()?;
            (signature, sign_start.elapsed())
        };

        #[cfg(feature = "perf-trace")]
        log::info!("[PERF] BLS sign + watermark write: {:?}", t.elapsed());

        // Exact role aliases only: substring matches would mis-classify keys and
        // still notify the UI for a frame that did not change.
        let mut activity_recorded = false;
        if let Some(ref activity_tracker) = self.signing_activity {
            match activity_tracker.lock() {
                Ok(mut activity) => {
                    let operation_type = if data.is_empty() {
                        None
                    } else {
                        crate::signing_activity::OperationType::from_magic_byte(data[0])
                    };
                    let level = parsed.level;

                    let sig_activity = crate::signing_activity::SignatureActivity {
                        level,
                        timestamp: std::time::SystemTime::now(),
                        duration: Some(sign_duration),
                        operation_type,
                        data_size: Some(data.len()),
                    };

                    if let Some(role) = crate::key_role::KeyRole::from_device_alias(&key_name) {
                        activity.set_last(role, sig_activity);
                        activity
                            .recent_events
                            .push(crate::signing_activity::SigningEvent {
                                role,
                                activity: sig_activity,
                            });
                        activity.total_signatures += 1;
                        activity_recorded = true;
                        log::debug!(
                            "Updated {role:?} signing activity: level={level:?}, duration={}ms",
                            sign_duration.as_millis()
                        );
                    } else if !self
                        .unknown_alias_reported
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        let expected: Vec<_> = crate::key_role::KeyRole::ALL
                            .iter()
                            .map(|r| r.device_alias())
                            .collect();
                        log::error!(
                            "Signed successfully with unexpected key alias {key_name:?}; \
                             activity not recorded (expected one of {expected:?})"
                        );
                    }
                }
                Err(e) => {
                    if !self
                        .activity_poison_reported
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        log::error!(
                            "Signing activity lock poisoned after successful sign; \
                             activity not recorded, UI not notified: {e}"
                        );
                    }
                }
            }
        }

        #[cfg(feature = "perf-trace")]
        log::info!(
            "[PERF] ===== TOTAL SIGN REQUEST: {:?} =====",
            request_start.elapsed()
        );

        // Demos without a tracker still expect a post-sign callback. With a
        // tracker, only notify when the ring advanced — otherwise the UI draws
        // an identical frame and refresh policy Skips that InPlace.
        if let Some(ref callback) = self.signing_notify_callback
            && (self.signing_activity.is_none() || activity_recorded)
        {
            callback();
        }

        Ok((SignerResponse::Signature(signature), operation_chain_id))
    }

    /// Handle public key request
    fn handle_public_key(&self, pkh: PublicKeyHash) -> Result<SignerResponse> {
        let signer = self.get_signer_or_alert(&pkh)?;
        Ok(SignerResponse::PublicKey(signer.public_key().clone()))
    }

    /// Handle authorized keys request
    fn handle_authorized_keys() -> SignerResponse {
        // OCaml behavior: return None when authentication is not required
        // This tells the client that no authentication is needed
        SignerResponse::AuthorizedKeys(None)
    }

    /// Handle deterministic nonce request
    fn handle_deterministic_nonce(
        &self,
        pkh: PublicKeyHash,
        data: &[u8],
    ) -> Result<SignerResponse> {
        let signer = self.get_signer_or_alert(&pkh)?;

        let handler = Handler::new(signer, None);

        // Generate nonce directly (requests are serial)
        let nonce = handler.deterministic_nonce(data);

        Ok(SignerResponse::Nonce(nonce))
    }

    /// Handle deterministic nonce hash request
    fn handle_deterministic_nonce_hash(
        &self,
        pkh: PublicKeyHash,
        data: &[u8],
    ) -> Result<SignerResponse> {
        let signer = self.get_signer_or_alert(&pkh)?;

        let handler = Handler::new(signer, None);

        // Generate nonce hash directly (requests are serial)
        let nonce_hash = handler.deterministic_nonce_hash(data);

        Ok(SignerResponse::NonceHash(nonce_hash))
    }

    /// Handle supports deterministic nonces request
    fn handle_supports_deterministic_nonces(&self, pkh: PublicKeyHash) -> Result<SignerResponse> {
        // Check if key exists
        self.get_signer_or_alert(&pkh)?;

        // All BLS signers support deterministic nonces
        Ok(SignerResponse::Bool(true))
    }

    /// Handle known keys request
    fn handle_known_keys(&self) -> Result<SignerResponse> {
        if !self.allow_list_known_keys {
            return Err(Error::NotAuthorized(
                "Listing known keys is not authorized. Use --allow-list-known-keys to enable."
                    .to_string(),
            ));
        }
        let keys = self.keys.read()?;
        let key_list = keys.list_keys();
        Ok(SignerResponse::KnownKeys(key_list))
    }

    /// Handle BLS proof of possession request
    fn handle_bls_prove(
        &self,
        pkh: PublicKeyHash,
        override_pk: Option<&PublicKey>,
    ) -> Result<SignerResponse> {
        if !self.allow_prove_possession {
            return Err(Error::NotAuthorized(
                "Proof of possession is not authorized. Use --allow-to-prove-possession to enable."
                    .to_string(),
            ));
        }
        let signer = self.get_signer_or_alert(&pkh)?;

        let handler = Handler::new(signer, None);
        let proof = handler.bls_prove_possession(override_pk)?;

        Ok(SignerResponse::Signature(proof))
    }

    /// Extract level from Tenderbake operation data
    /// Single parse of tenderbake chain id + level/round for one sign request.
    ///
    /// This crate only holds BLS keys, so attestation/preattestation always use
    /// the BLS layout (`is_bls = true`) — no base58 pkh allocation.
    fn parse_sign_payload(data: &[u8]) -> ParsedSignPayload {
        if data.is_empty() {
            return ParsedSignPayload::default();
        }

        let chain_id = magic_bytes::get_chain_id_for_tenderbake(data).map(|bytes| {
            let mut padded = [0u8; 32];
            padded[..4].copy_from_slice(&bytes);
            ChainId::from_bytes(&padded)
        });

        let op_type = crate::high_watermark::OperationType::from_magic_byte(data[0]);
        let (level, round) = match data[0] {
            0x11 => magic_bytes::get_level_and_round_for_tenderbake_block(data)
                .ok()
                .map_or((None, None), |(l, r)| (Some(l), Some(r))),
            0x12 | 0x13 => magic_bytes::get_level_and_round_for_tenderbake_attestation(data, true)
                .ok()
                .map_or((None, None), |(l, r)| (Some(l), Some(r))),
            _ => (None, None),
        };

        ParsedSignPayload {
            chain_id,
            op_type,
            level,
            round,
        }
    }
}

/// Pre-parsed tenderbake fields for one Sign request (parsed once per `handle_sign`).
#[derive(Clone, Copy, Default)]
struct ParsedSignPayload {
    chain_id: Option<ChainId>,
    op_type: Option<crate::high_watermark::OperationType>,
    level: Option<u32>,
    round: Option<u32>,
}

/// Handle a single TCP connection
///
/// Corresponds to: src/bin_signer/socket_daemon.ml:158-193
fn handle_connection(
    mut socket: TcpStream,
    addr: SocketAddr,
    handler: &Arc<RequestHandler>,
    timeout: Option<Duration>,
    max_message_size: usize,
) -> Result<()> {
    log::debug!("handle_connection started for {addr}");
    configure_socket(&socket, timeout)?;

    // Boost CPU for entire connection (covers all requests in the burst)
    handler.notify_request_received();
    let result = handle_connection_inner(&mut socket, addr, handler, max_message_size);
    handler.notify_request_complete();
    result
}

fn handle_connection_inner(
    socket: &mut TcpStream,
    addr: SocketAddr,
    handler: &Arc<RequestHandler>,
    max_message_size: usize,
) -> Result<()> {
    let mut request_count = 0;
    loop {
        request_count += 1;
        log::debug!("Waiting for request #{request_count} from {addr}");

        let Some(msg_len) = read_message_length(socket, addr, request_count, max_message_size)?
        else {
            return Ok(()); // Client closed connection
        };

        #[cfg(feature = "perf-trace")]
        let _guard = RequestGuard::new(addr);
        #[cfg(feature = "perf-trace")]
        let request_start = std::time::Instant::now();

        process_request(socket, addr, msg_len, handler)?;

        #[cfg(feature = "perf-trace")]
        log::info!(
            "[PERF] ===== TOTAL REQUEST (including TCP): {:?} =====",
            request_start.elapsed()
        );
    }
}

fn configure_socket(socket: &TcpStream, timeout: Option<Duration>) -> Result<()> {
    socket.set_nodelay(true)?;
    if let Some(timeout_duration) = timeout {
        socket.set_read_timeout(Some(timeout_duration))?;
        socket.set_write_timeout(Some(timeout_duration))?;
    }
    Ok(())
}

/// Read and validate message length. Returns None if client closed connection.
fn read_message_length(
    socket: &mut TcpStream,
    addr: SocketAddr,
    request_count: u32,
    max_message_size: usize,
) -> Result<Option<usize>> {
    let mut len_buf = [0u8; 2];
    if let Err(e) = socket.read_exact(&mut len_buf) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            log::debug!(
                "Client {} closed connection after {} requests",
                addr,
                request_count - 1
            );
            return Ok(None);
        }
        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
            log::debug!("Timeout reading from {addr}: {e}");
            return Err(Error::Timeout);
        }
        log::debug!("Read error from {addr}: {e}");
        return Err(e.into());
    }

    let msg_len = u16::from_be_bytes(len_buf) as usize;
    if msg_len > max_message_size {
        return Err(check_http_and_size_error(len_buf, addr, msg_len));
    }
    Ok(Some(msg_len))
}

fn check_http_and_size_error(len_buf: [u8; 2], addr: SocketAddr, msg_len: usize) -> Error {
    let possible_http = String::from_utf8_lossy(&len_buf);
    if possible_http.starts_with("GET ")
        || possible_http.starts_with("POST")
        || possible_http.starts_with("HEAD")
    {
        log::warn!("Client {addr} sent HTTP request, but this server expects raw TCP protocol");
        log::warn!("   HTTP request starts with: {possible_http}");
        log::warn!(
            "   SOLUTION: Change baker config from 'http://...' to 'tcp://...' or just the address"
        );
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP protocol not supported - use raw TCP (tcp://... or just address)",
        ))
    } else {
        Error::MessageTooLarge(msg_len)
    }
}

/// Process a single request: read, decode, handle, encode, write
fn process_request(
    socket: &mut TcpStream,
    addr: SocketAddr,
    msg_len: usize,
    handler: &Arc<RequestHandler>,
) -> Result<()> {
    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let mut msg_buf = vec![0u8; msg_len];
    socket.read_exact(&mut msg_buf)?;

    #[cfg(feature = "perf-trace")]
    log::info!("[PERF] TCP read: {:?}", t.elapsed());

    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let request = decode_request(&msg_buf)?;
    log::debug!("<= RECV request from {addr}: {request:?}");

    #[cfg(feature = "perf-trace")]
    log::info!("[PERF] Decode request: {:?}", t.elapsed());

    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let (response, _chain_id) = match handler.handle_request(request) {
        Ok((resp, chain_id)) => (resp, chain_id),
        Err(e) => (SignerResponse::Error(e.to_string()), None),
    };

    #[cfg(feature = "perf-trace")]
    log::info!("[PERF] Handle request: {:?}", t.elapsed());

    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let response_data = encode_response(&response)?;

    #[cfg(feature = "perf-trace")]
    log::info!("[PERF] Encode response: {:?}", t.elapsed());

    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let response_len = u16::try_from(response_data.len())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Response too large for OCaml protocol (max 65535 bytes)",
            )
        })?
        .to_be_bytes();
    socket.write_all(&response_len)?;
    socket.write_all(&response_data)?;
    socket.flush()?;

    #[cfg(feature = "perf-trace")]
    log::info!("[PERF] TCP write: {:?}", t.elapsed());

    Ok(())
}

/// TCP signer server
///
/// Corresponds to: `src/bin_signer/socket_daemon.ml`
pub struct Server {
    /// Listen address
    address: SocketAddr,
    /// Handler for signing requests
    handler: Arc<RequestHandler>,
    /// Optional timeout for client connections
    timeout: Option<Duration>,
    /// Maximum message size (default: 64KB)
    max_message_size: usize,
    /// Maximum concurrent connections (default: 4)
    max_connections: usize,
    /// Optional connection counter (incremented on connect, decremented on disconnect)
    connection_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl Server {
    /// Create new signer server
    #[must_use]
    pub fn new(
        address: SocketAddr,
        handler: Arc<RequestHandler>,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            address,
            handler,
            timeout,
            max_message_size: 64 * 1024, // 64KB default (sufficient for Tezos operations)
            max_connections: 4,          // Default: 4 concurrent connections
            connection_count: Some(Arc::new(std::sync::atomic::AtomicUsize::new(0))),
        }
    }

    /// Set maximum message size
    #[must_use]
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set maximum concurrent connections
    #[must_use]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set connection counter for tracking active connections
    #[must_use]
    pub fn with_connection_counter(mut self, counter: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.connection_count = Some(counter);
        self
    }

    /// Run the server
    ///
    /// Runs the server accept loop. This method will run indefinitely
    /// until an error occurs or the task is cancelled.
    ///
    /// Note: Signal handling (Ctrl+C, SIGTERM) should be implemented
    /// by the calling application. Call `shutdown()` for graceful shutdown.
    ///
    /// Corresponds to: src/bin_signer/socket_daemon.ml:195-281
    ///
    /// # Errors
    ///
    /// Returns an error if binding to the address fails or the accept loop encounters
    /// an unrecoverable I/O error.
    pub fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.address)?;

        log::info!("Listening on {}", self.address);

        self.accept_loop(&listener)
    }

    /// Main accept loop for incoming connections
    fn accept_loop(&self, listener: &TcpListener) -> Result<()> {
        loop {
            let (socket, addr) = listener.accept()?;

            // Check connection limit before spawning thread
            if let Some(ref counter) = self.connection_count {
                let current = counter.load(std::sync::atomic::Ordering::Relaxed);
                if current >= self.max_connections {
                    log::warn!(
                        "Connection limit reached ({}/{}), rejecting connection from {}",
                        current,
                        self.max_connections,
                        addr
                    );
                    // Drop socket to close connection
                    drop(socket);
                    continue;
                }
            }

            let handler = Arc::clone(&self.handler);
            let timeout = self.timeout;
            let max_message_size = self.max_message_size;

            // Create connection guard (increments counter, decrements on drop)
            let guard = ConnectionGuard::new(self.connection_count.clone());

            // Spawn thread for each connection
            std::thread::spawn(move || {
                // Guard is moved into thread and will be dropped when thread completes
                let _guard = guard;

                if let Err(e) = handle_connection(socket, addr, &handler, timeout, max_message_size)
                {
                    log::error!("Connection error from {addr}: {e}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::generate_key;
    use crate::test_utils::{new_watermark, preinit_watermarks};
    use tempfile::TempDir;

    #[test]
    fn test_key_manager_basic() {
        let mut mgr = KeyManager::new();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        mgr.add_signer(pkh, signer, "test_key".to_string());

        assert!(mgr.get_signer(&pkh).is_ok());
        assert_eq!(mgr.list_keys().len(), 1);
    }

    #[test]
    fn test_key_manager_not_found() {
        let mgr = KeyManager::new();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        assert!(mgr.get_signer(&pkh).is_err());
    }

    #[test]
    fn test_request_handler_public_key() {
        let seed = [42u8; 32];
        let (pkh, pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            None,
            None,
            true, // allow_list_known_keys
            true, // allow_prove_possession
        );

        let (response, _) = handler
            .handle_request(SignerRequest::PublicKey { pkh })
            .unwrap();

        match response {
            SignerResponse::PublicKey(returned_pk) => {
                assert_eq!(returned_pk, pk);
            }
            _ => panic!("Expected PublicKey response"),
        }
    }

    #[test]
    fn test_request_handler_known_keys() {
        use crate::key_role::KeyRole;

        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let (consensus_pkh, _pk1, _sk1) = generate_key(Some(&seed1)).unwrap();
        let (companion_pkh, _pk2, _sk2) = generate_key(Some(&seed2)).unwrap();

        let signer1 = Unencrypted::generate(Some(&seed1)).unwrap();
        let signer2 = Unencrypted::generate(Some(&seed2)).unwrap();

        let mut mgr = KeyManager::new();
        // Insert companion first to prove ordering is by role, not insertion order
        mgr.add_signer(
            companion_pkh,
            signer2,
            KeyRole::Companion.device_alias().to_string(),
        );
        mgr.add_signer(
            consensus_pkh,
            signer1,
            KeyRole::Consensus.device_alias().to_string(),
        );

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            None,
            None,
            true, // allow_list_known_keys
            true, // allow_prove_possession
        );

        let (response, _) = handler.handle_request(SignerRequest::KnownKeys).unwrap();

        match response {
            SignerResponse::KnownKeys(keys) => {
                assert_eq!(keys.len(), 2);
                assert_eq!(keys[0], consensus_pkh);
                assert_eq!(keys[1], companion_pkh);
            }
            _ => panic!("Expected KnownKeys response"),
        }
    }

    /// Two stored keys can carry the same role alias (case aside). The role
    /// slot then has to be picked, and the pick must come from the pkhs
    /// themselves — lowest base58 — not from `HashMap` iteration.
    #[test]
    fn list_keys_alias_collision_takes_lowest_b58() {
        use crate::key_role::KeyRole;

        let mut mgr = KeyManager::new();
        let mut colliding = Vec::new();
        for (seed, alias) in [
            ([1u8; 32], KeyRole::Consensus.device_alias().to_string()),
            ([2u8; 32], KeyRole::Consensus.device_alias().to_uppercase()),
        ] {
            let (pkh, _, _) = generate_key(Some(&seed)).unwrap();
            let signer = Unencrypted::generate(Some(&seed)).unwrap();
            mgr.add_signer(pkh, signer, alias);
            colliding.push(pkh);
        }

        let winner = *colliding
            .iter()
            .min_by_key(|pkh| pkh.to_b58check())
            .unwrap();
        let loser = *colliding.iter().find(|pkh| **pkh != winner).unwrap();

        let listed = mgr.list_keys();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], winner, "role slot takes the lowest base58");
        assert_eq!(listed[1], loser, "the other lands in the sorted extras");
    }

    #[test]
    fn list_keys_role_order_is_case_insensitive_and_extras_sorted() {
        let seeds: [[u8; 32]; 4] = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let mut pkhs = Vec::new();
        let mut mgr = KeyManager::new();
        for (i, seed) in seeds.iter().enumerate() {
            let (pkh, _, _) = generate_key(Some(seed)).unwrap();
            let signer = Unencrypted::generate(Some(seed)).unwrap();
            let name = match i {
                // Mixed case must still land in the global role slots.
                0 => "Consensus".to_string(),
                1 => "COMPANION".to_string(),
                2 => "extra_z".to_string(),
                _ => "extra_a".to_string(),
            };
            mgr.add_signer(pkh, signer, name);
            pkhs.push(pkh);
        }

        let listed = mgr.list_keys();
        assert_eq!(listed.len(), 4);
        assert_eq!(listed[0], pkhs[0]);
        assert_eq!(listed[1], pkhs[1]);
        // Non-role keys follow, sorted by base58 (not HashMap / insertion order).
        let extra_a = pkhs[3].to_b58check();
        let extra_z = pkhs[2].to_b58check();
        if extra_a < extra_z {
            assert_eq!(listed[2], pkhs[3]);
            assert_eq!(listed[3], pkhs[2]);
        } else {
            assert_eq!(listed[2], pkhs[2]);
            assert_eq!(listed[3], pkhs[3]);
        }
    }

    #[test]
    fn test_request_handler_sign_with_watermark() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        // Match the chain the watermark store is bound to; a foreign chain would
        // be rejected before the level check this test exercises.
        let chain_id = crate::test_utils::default_test_chain_id();

        // Pre-initialize watermarks BEFORE creating HighWatermark
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::new(RwLock::new(hwm))),
            Some(magic_bytes::MagicByte::all()),
            true, // allow_list_known_keys
            true, // allow_prove_possession
        );

        // Create block data at level 100
        let mut data = vec![0x11]; // Block magic byte
        data.extend_from_slice(&chain_id.as_bytes()[..4]); // chain_id
        data.extend_from_slice(&100u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        // First sign should succeed
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, 0),
                data: data.clone(),
                signature: None,
            })
            .unwrap();

        assert!(matches!(response, SignerResponse::Signature(_)));

        // Create data at level 99 (below watermark)
        let mut data_low = vec![0x11];
        data_low.extend_from_slice(&chain_id.as_bytes()[..4]);
        data_low.extend_from_slice(&99u32.to_be_bytes());
        data_low.push(0);
        data_low.extend_from_slice(&[0u8; 32]);
        data_low.extend_from_slice(&[0u8; 8]);
        data_low.push(0);
        data_low.extend_from_slice(&[0u8; 32]);
        data_low.extend_from_slice(&8u32.to_be_bytes());
        data_low.extend_from_slice(&0u32.to_be_bytes());

        // Second sign at lower level should fail with watermark error
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data: data_low,
            signature: None,
        });

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Watermark(_)));
    }

    #[test]
    fn test_sign_rejects_foreign_chain() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        // Watermark store is bound to the default test chain ([0, 0, 0, 1]).
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::new(RwLock::new(hwm))),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        );

        // Block for mainnet, a chain this device was not provisioned for, at a
        // level above the floor so only the chain check can reject it.
        let data = crate::test_utils::create_block_data_with_chain(
            &crate::test_utils::MAINNET_CHAIN_ID,
            100,
            0,
        );

        let err = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            })
            .unwrap_err();

        assert!(
            matches!(
                err,
                Error::Watermark(crate::high_watermark::WatermarkError::ChainMismatch { .. })
            ),
            "Expected ChainMismatch, got: {err:?}"
        );
    }

    #[test]
    fn test_sign_accepts_provisioned_chain() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        // Watermark store is bound to the default test chain ([0, 0, 0, 1]).
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::new(RwLock::new(hwm))),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        );

        // Block on the provisioned chain at a level above the floor.
        let data = crate::test_utils::create_block_data_with_chain(&[0, 0, 0, 1], 100, 0);

        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            })
            .unwrap();

        assert!(matches!(response, SignerResponse::Signature(_)));
    }

    #[test]
    fn test_watermark_persists_after_sign() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        // Pre-initialize watermarks BEFORE creating HighWatermark
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        );

        // Create block data at level 100
        let mut data = vec![0x11]; // Block magic byte
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&100u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        // Sign the data (watermark write happens inside handle_request)
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            })
            .unwrap();

        assert!(matches!(response, SignerResponse::Signature(_)));

        // Verify watermark was persisted: reload from disk.
        // Disk has either the actual value (100) or the ceiling (101) depending
        // on whether the background ceiling thread has run yet.
        let hwm2 = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        let chain_id = ChainId::from_bytes(&{
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&[0, 0, 0, 1]);
            b
        });
        let (block_level, _, _) = hwm2.get_current_levels(chain_id, &pkh).unwrap();
        assert!(
            block_level == 100 || block_level == 101,
            "Disk should have level 100 (actual) or 101 (ceiling), got {block_level}"
        );
    }

    #[test]
    fn below_floor_request_rejected_without_lowering_floor() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        preinit_watermarks(temp_dir.path(), &pkh, 100);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        );

        // Block at level 50, below the floor of 100.
        let mut data = vec![0x11];
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&50u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        });

        // A below-floor request is refused, never signed.
        assert!(
            matches!(
                result,
                Err(Error::Watermark(
                    crate::high_watermark::WatermarkError::LevelTooLow { .. }
                ))
            ),
            "below-floor request must return LevelTooLow, got: {result:?}"
        );

        // The floor is neither advanced nor lowered by the rejected request.
        let chain_id = ChainId::from_bytes(&{
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&[0, 0, 0, 1]);
            b
        });
        let (block_level, _, _) = hwm
            .read()
            .unwrap()
            .get_current_levels(chain_id, &pkh)
            .unwrap();
        assert_eq!(
            block_level, 100,
            "a rejected below-floor request must leave the floor untouched"
        );
    }

    #[test]
    fn test_large_level_gap_detection() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let _chain_id = ChainId::from_bytes(&chain_id_bytes);

        // Pre-initialize watermarks BEFORE creating HighWatermark
        preinit_watermarks(temp_dir.path(), &pkh, 100);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        // Track if callback was triggered
        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = Arc::clone(&callback_triggered);

        // With blocks_per_cycle=100, threshold = 4 * 100 = 400 blocks
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_large_gap_callback(
            Arc::new(move |_pkh, _chain_id, current, requested| {
                callback_triggered_clone.store(true, Ordering::SeqCst);
                assert_eq!(current, 100);
                assert_eq!(requested, 600);
            }),
            100, // blocks_per_cycle
        );

        // Create block data at level 600 (gap of 500, exceeds 400 threshold)
        let mut data = vec![0x11]; // Block magic byte
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&600u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        // Sign should fail with LargeLevelGap error
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Watermark(crate::high_watermark::WatermarkError::LargeLevelGap { .. })
            ),
            "Expected LargeLevelGap error, got: {err:?}"
        );

        // Verify callback was triggered
        assert!(
            callback_triggered.load(Ordering::SeqCst),
            "Large gap callback should have been triggered"
        );
    }

    #[test]
    fn test_no_large_gap_below_threshold() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let _chain_id = ChainId::from_bytes(&chain_id_bytes);

        // Pre-initialize watermarks BEFORE creating HighWatermark
        preinit_watermarks(temp_dir.path(), &pkh, 100);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        // With blocks_per_cycle=100, threshold = 4 * 100 = 400 blocks
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_large_gap_callback(
            Arc::new(|_pkh, _chain_id, _current, _requested| {
                panic!("Callback should not be triggered for gap below threshold");
            }),
            100, // blocks_per_cycle
        );

        // Create block data at level 400 (gap of 300, below 400 threshold)
        let mut data = vec![0x11]; // Block magic byte
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&400u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        // Sign should succeed (gap is 300, below 400 threshold)
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        });

        assert!(
            result.is_ok(),
            "Sign should succeed for gap below threshold"
        );
    }

    #[test]
    fn test_missing_watermark_detection() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        // No preinit: the key has no watermark files, so it is uninitialized.
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_watermark_missing_callback(Arc::new(move |_pkh, _chain_id, requested| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            assert_eq!(requested, 600);
        }));

        // Block data at level 600
        let mut data = vec![0x11]; // Block magic byte
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&600u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        });

        // Signing is still refused for an uninitialized key.
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                Error::Watermark(crate::high_watermark::WatermarkError::NotInitialized { .. })
            ),
            "Expected NotInitialized error for uninitialized key"
        );

        // The missing-watermark callback fired exactly once with the request's level.
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Missing watermark callback should fire exactly once"
        );
    }

    #[test]
    fn test_unknown_key_rejected_before_watermark_recovery() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let temp_dir = TempDir::new().unwrap();
        let (known_pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();
        let known_signer = Unencrypted::generate(Some(&[42u8; 32])).unwrap();
        let (unknown_pkh, _pk2, _sk2) = generate_key(Some(&[7u8; 32])).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(known_pkh, known_signer, "known".to_string());

        let hwm = Arc::new(RwLock::new(
            new_watermark(temp_dir.path(), &[known_pkh]).unwrap(),
        ));

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_watermark_missing_callback(Arc::new(move |_pkh, _chain_id, _requested| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
        }));

        // Block data at level 600 for a key the signer does not hold.
        let mut data = vec![0x11];
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&600u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (unknown_pkh, 0),
            data,
            signature: None,
        });

        // An unknown key rejects as KeyNotFound, before any watermark work.
        assert!(
            matches!(result.unwrap_err(), Error::KeyNotFound(_)),
            "an unheld key must reject as KeyNotFound, not surface watermark recovery"
        );
        // Watermark recovery must never be offered for a key we cannot sign.
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "missing-watermark callback must not fire for an unknown key"
        );
    }

    #[test]
    fn test_unknown_key_callback_fires_once_and_still_rejects() {
        use std::sync::Mutex;

        let temp_dir = TempDir::new().unwrap();
        let (known_pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();
        let known_signer = Unencrypted::generate(Some(&[42u8; 32])).unwrap();
        let (unknown_pkh, _pk2, _sk2) = generate_key(Some(&[7u8; 32])).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(known_pkh, known_signer, "known".to_string());

        let hwm = Arc::new(RwLock::new(
            new_watermark(temp_dir.path(), &[known_pkh]).unwrap(),
        ));

        let seen: Arc<Mutex<Vec<PublicKeyHash>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen);

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_unknown_key_callback(Arc::new(move |pkh| {
            seen_clone.lock().unwrap().push(pkh);
        }));

        // Block data at level 600 for a key the signer does not hold.
        let mut data = vec![0x11];
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&600u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (unknown_pkh, 0),
            data,
            signature: None,
        });

        // The rejection is unchanged by the callback.
        assert!(
            matches!(result.unwrap_err(), Error::KeyNotFound(_)),
            "an unheld key must still reject as KeyNotFound"
        );
        // The callback fired exactly once, with the requested pkh. (Dedup is
        // app-side; this layer fires per request.)
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.as_slice(),
            &[unknown_pkh],
            "unknown-key callback must fire exactly once with the requested pkh"
        );
    }

    /// Build a handler holding one key, an unheld pkh to request, and a log
    /// of every unknown-key callback invocation.
    fn handler_with_unknown_key_recording() -> (
        RequestHandler,
        PublicKeyHash,
        Arc<std::sync::Mutex<Vec<PublicKeyHash>>>,
    ) {
        let (known_pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();
        let known_signer = Unencrypted::generate(Some(&[42u8; 32])).unwrap();
        let (unknown_pkh, _pk2, _sk2) = generate_key(Some(&[7u8; 32])).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(known_pkh, known_signer, "known".to_string());

        let seen: Arc<std::sync::Mutex<Vec<PublicKeyHash>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen);

        let handler = RequestHandler::new(Arc::new(RwLock::new(mgr)), None, None, true, true)
            .with_unknown_key_callback(Arc::new(move |pkh| {
                seen_clone.lock().unwrap().push(pkh);
            }));

        (handler, unknown_pkh, seen)
    }

    #[test]
    fn test_unknown_key_callback_fires_on_every_pkh_bearing_request() {
        type MakeRequest = fn(PublicKeyHash) -> SignerRequest;
        let requests: [(&str, MakeRequest); 5] = [
            ("PublicKey", |pkh| SignerRequest::PublicKey { pkh }),
            ("DeterministicNonce", |pkh| {
                SignerRequest::DeterministicNonce {
                    pkh: (pkh, 0),
                    data: vec![0x01, 0x02, 0x03],
                    signature: None,
                }
            }),
            ("DeterministicNonceHash", |pkh| {
                SignerRequest::DeterministicNonceHash {
                    pkh: (pkh, 0),
                    data: vec![0x01, 0x02, 0x03],
                    signature: None,
                }
            }),
            ("SupportsDeterministicNonces", |pkh| {
                SignerRequest::SupportsDeterministicNonces { pkh }
            }),
            ("BlsProveRequest", |pkh| SignerRequest::BlsProveRequest {
                pkh,
                override_pk: None,
            }),
        ];

        for (name, make_request) in requests {
            let (handler, unknown_pkh, seen) = handler_with_unknown_key_recording();

            let result = handler.handle_request(make_request(unknown_pkh));

            assert!(
                matches!(result.unwrap_err(), Error::KeyNotFound(_)),
                "{name}: an unheld key must reject as KeyNotFound"
            );
            assert_eq!(
                seen.lock().unwrap().as_slice(),
                &[unknown_pkh],
                "{name}: unknown-key callback must fire exactly once with the requested pkh"
            );
        }
    }

    #[test]
    fn test_unknown_key_callback_fires_per_request_without_dedup() {
        let (handler, unknown_pkh, seen) = handler_with_unknown_key_recording();

        for _ in 0..2 {
            let result = handler.handle_request(SignerRequest::Sign {
                pkh: (unknown_pkh, 0),
                data: vec![0x11, 0x01, 0x02],
                signature: None,
            });
            assert!(
                matches!(result.unwrap_err(), Error::KeyNotFound(_)),
                "an unheld key must reject as KeyNotFound"
            );
        }

        // Dedup is app-side; this layer fires per request.
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[unknown_pkh, unknown_pkh],
            "identical requests must each fire the unknown-key callback"
        );
    }

    #[test]
    fn test_missing_watermark_not_fired_when_initialized() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        // Initialize the key's watermark at level 100.
        preinit_watermarks(temp_dir.path(), &pkh, 100);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_watermark_missing_callback(Arc::new(|_pkh, _chain_id, _requested| {
            panic!("Missing watermark callback should not fire for an initialized key");
        }));

        // Block data at level 200 (above current 100, a valid advance)
        let mut data = vec![0x11]; // Block magic byte
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&200u32.to_be_bytes()); // level
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        });

        assert!(
            result.is_ok(),
            "Initialized key should sign successfully: {result:?}"
        );
    }

    #[test]
    fn test_watermark_write_failure_prevents_signature_return() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        // Inject write error
        hwm.write().unwrap().force_write_error = true;

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        );

        // Create block data at level 100
        let data = crate::test_utils::create_block_data(100, 0);

        // Sign request should fail (watermark write fails → no signature returned)
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        });

        assert!(
            result.is_err(),
            "Should refuse to return signature when watermark write fails"
        );
        assert!(
            matches!(result.unwrap_err(), Error::Watermark(_)),
            "Error should be a watermark error"
        );

        // Verify watermark was rolled back in-memory (baker can retry)
        let wm = hwm.read().unwrap();
        assert_eq!(
            wm.get_current_level(
                ChainId::from_bytes(&{
                    let mut b = [0u8; 32];
                    b[..4].copy_from_slice(&[0, 0, 0, 1]);
                    b
                }),
                &pkh
            ),
            Some(99),
            "In-memory watermark should be rolled back after write failure"
        );
    }

    #[test]
    fn test_zero_blocks_per_cycle_does_not_panic() {
        // Test that blocks_per_cycle = 0 doesn't cause division by zero
        // The gap detection should be skipped when blocks_per_cycle is 0
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let _chain_id = ChainId::from_bytes(&chain_id_bytes);

        // Pre-initialize watermarks BEFORE creating HighWatermark
        preinit_watermarks(temp_dir.path(), &pkh, 100);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        // Track if callback was triggered (it should NOT be triggered with blocks_per_cycle=0)
        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = Arc::clone(&callback_triggered);

        // With blocks_per_cycle=0, gap detection should be SKIPPED entirely
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_large_gap_callback(
            Arc::new(move |_pkh, _chain_id, _current, _requested| {
                callback_triggered_clone.store(true, Ordering::SeqCst);
            }),
            0, // blocks_per_cycle = 0 (should skip gap detection, not panic)
        );

        // Create block data at level 10000 (huge gap, would trigger callback if enabled)
        let mut data = vec![0x11]; // Block magic byte
        data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
        data.extend_from_slice(&10000u32.to_be_bytes()); // level (huge gap)
        data.push(0); // proto
        data.extend_from_slice(&[0u8; 32]); // predecessor
        data.extend_from_slice(&[0u8; 8]); // timestamp
        data.push(0); // validation_pass
        data.extend_from_slice(&[0u8; 32]); // operations_hash
        data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
        data.extend_from_slice(&0u32.to_be_bytes()); // round

        // Sign should succeed because gap detection is skipped with blocks_per_cycle=0
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, 0),
            data,
            signature: None,
        });

        // Should succeed (no division by zero panic, gap detection skipped)
        assert!(
            result.is_ok(),
            "Sign should succeed when blocks_per_cycle is 0: {result:?}"
        );

        // Callback should NOT have been triggered
        assert!(
            !callback_triggered.load(Ordering::SeqCst),
            "Gap callback should not be triggered when blocks_per_cycle is 0"
        );
    }

    // === Signing activity recording + notify (Activity page data path) ===

    fn activity_sign_fixture(
        alias: &str,
    ) -> (
        RequestHandler,
        PublicKeyHash,
        Arc<std::sync::Mutex<crate::signing_activity::SigningActivity>>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let seed = [7u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, alias.to_string());

        let activity = Arc::new(std::sync::Mutex::new(
            crate::signing_activity::SigningActivity::default(),
        ));
        let notify_count = Arc::new(AtomicUsize::new(0));
        let notify_count_cb = Arc::clone(&notify_count);
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            None,
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        )
        .with_signing_activity(Arc::clone(&activity))
        .with_signing_notify(Arc::new(move || {
            notify_count_cb.fetch_add(1, Ordering::SeqCst);
        }));

        (handler, pkh, activity, notify_count)
    }

    fn sign_block(handler: &RequestHandler, pkh: PublicKeyHash, level: u32) {
        let data = crate::test_utils::create_block_data(level, 0);
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            })
            .expect("sign should succeed");
        assert!(matches!(response, SignerResponse::Signature(_)));
    }

    /// Successful Sign with a production consensus alias must advance the ring
    /// and counters with display-complete fields (level, duration, op type).
    #[test]
    fn sign_consensus_alias_records_activity_and_notifies() {
        use crate::key_role::KeyRole;
        use crate::signing_activity::OperationType;
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) =
            activity_sign_fixture(KeyRole::Consensus.device_alias());
        sign_block(&handler, pkh, 150);

        assert_eq!(notify_count.load(Ordering::SeqCst), 1);

        let a = activity.lock().unwrap();
        assert_eq!(a.total_signatures, 1);
        assert_eq!(a.recent_events.iter().count(), 1);
        let event = a.recent_events.iter().next().unwrap();
        assert_eq!(event.role, KeyRole::Consensus);
        assert_eq!(event.activity.level, Some(150));
        assert!(event.activity.duration.is_some());
        assert_eq!(event.activity.operation_type, Some(OperationType::Block));
        assert!(a.last(KeyRole::Consensus).is_some());
        assert!(a.last(KeyRole::Companion).is_none());
    }

    #[test]
    fn sign_companion_alias_records_activity_and_notifies() {
        use crate::key_role::KeyRole;
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) =
            activity_sign_fixture(KeyRole::Companion.device_alias());
        sign_block(&handler, pkh, 200);

        assert_eq!(notify_count.load(Ordering::SeqCst), 1);
        let a = activity.lock().unwrap();
        assert_eq!(a.total_signatures, 1);
        let event = a.recent_events.iter().next().unwrap();
        assert_eq!(event.role, KeyRole::Companion);
        assert_eq!(event.activity.level, Some(200));
        assert!(a.last(KeyRole::Companion).is_some());
        assert!(a.last(KeyRole::Consensus).is_none());
    }

    /// Alias matching is case-insensitive (`to_lowercase` before exact match).
    #[test]
    fn sign_consensus_alias_is_case_insensitive() {
        let (handler, pkh, activity, _) = activity_sign_fixture("Consensus");
        sign_block(&handler, pkh, 10);
        assert_eq!(activity.lock().unwrap().total_signatures, 1);
    }

    /// Unmatched alias: sign still succeeds, but activity is not advanced and
    /// the UI is not notified (avoids Invalidate → identical frame → Skip).
    #[test]
    fn sign_unmatched_alias_neither_records_nor_notifies() {
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) = activity_sign_fixture("baker_key");
        sign_block(&handler, pkh, 300);

        assert_eq!(
            notify_count.load(Ordering::SeqCst),
            0,
            "notify must not fire when activity was not recorded"
        );
        let a = activity.lock().unwrap();
        assert_eq!(a.total_signatures, 0);
        assert_eq!(a.recent_events.iter().count(), 0);
        for role in crate::key_role::KeyRole::ALL {
            assert!(a.last(role).is_none());
        }
    }

    /// Substring is not a role: only exact role aliases record.
    #[test]
    fn sign_substring_alias_neither_records_nor_notifies() {
        use crate::key_role::KeyRole;
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) =
            activity_sign_fixture(&format!("my-{}-key", KeyRole::Consensus.device_alias()));
        sign_block(&handler, pkh, 1);
        assert_eq!(activity.lock().unwrap().total_signatures, 0);
        assert_eq!(notify_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sign_attestation_records_level_and_operation_type() {
        use crate::key_role::KeyRole;
        use crate::signing_activity::OperationType;

        let (handler, pkh, activity, _) = activity_sign_fixture(KeyRole::Consensus.device_alias());
        let data = crate::test_utils::create_attestation_data(42, 1);
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, 0),
                data,
                signature: None,
            })
            .unwrap();
        assert!(matches!(response, SignerResponse::Signature(_)));

        let a = activity.lock().unwrap();
        let event = a.recent_events.iter().next().unwrap();
        assert_eq!(event.activity.level, Some(42));
        assert_eq!(
            event.activity.operation_type,
            Some(OperationType::Attestation)
        );
    }
}
