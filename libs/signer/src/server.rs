//! TCP server implementation for russignol-signer
//!
//! This module implements the TCP server that accepts connections from octez-client
//! and handles signing requests using the binary protocol.
//!
//! Corresponds to: `src/bin_signer/socket_daemon.ml`

use crate::high_watermark::{ChainId, HighWatermark};
use crate::magic_bytes;
use crate::protocol::encoding::{decode_request, encode_response};
use crate::protocol::{SignerRequest, SignerResponse};
use crate::scheme::{PublicKey, PublicKeyHash, Scheme};
use crate::signer::{Handler, SignatureVersion, Unencrypted};
use crate::xmss::Epoch;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

/// How long the deferred writer waits for the signing burst to end before
/// writing anyway, so a card under continuous load still gets its ceiling and
/// its epoch reservation.
const BURST_WAIT: Duration = Duration::from_secs(1);

/// Connections being served, and waiters parked on `idle`.
///
/// One lock covers both, so a caller that acquires it and finds a waiter
/// counted knows that waiter is inside its wait: the park releases this lock
/// atomically, and the count is raised while it is still held.
#[derive(Default)]
struct GateState {
    serving: usize,
    waiting: usize,
}

/// Counts the connections a handler is serving, so work deferred out of the
/// sign path can wait for the burst to end rather than for a timer.
///
/// A level's three signatures arrive on one connection — `handle_connection`
/// brackets the whole of it — so the count reaching zero is the burst ending
/// rather than a gap inside one.
#[derive(Default)]
struct IdleGate {
    state: Mutex<GateState>,
    idle: Condvar,
}

impl IdleGate {
    /// The state itself, taken back from a poisoned lock: nothing between the
    /// lock and the unlock can panic, and a dropped increment would leave the
    /// deferred writer believing a live connection had closed.
    fn state(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn enter(&self) {
        self.state().serving += 1;
    }

    fn leave(&self) {
        let mut state = self.state();
        state.serving = state.serving.saturating_sub(1);
        if state.serving == 0 {
            self.idle.notify_all();
        }
    }

    /// Wait until nothing is being served, or `timeout` elapses.
    ///
    /// Returns whether it saw the handler idle; the caller writes either way,
    /// since a card under continuous load would otherwise never get its
    /// write-ahead at all.
    fn wait_for_idle(&self, timeout: Duration) -> bool {
        let mut state = self.state();
        state.waiting += 1;
        let (mut state, saw_idle) = match self
            .idle
            .wait_timeout_while(state, timeout, |state| state.serving > 0)
        {
            Ok((state, wait)) => (state, !wait.timed_out()),
            Err(poisoned) => (poisoned.into_inner().0, false),
        };
        state.waiting -= 1;
        saw_idle
    }
}

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

    /// Add a signer under the address its own key material derives.
    ///
    /// The address is read off the signer rather than passed alongside it, so a
    /// request naming one key cannot be answered by another's material.
    pub fn add_signer(&mut self, signer: Unencrypted, name: String) {
        let pkh = *signer.public_key_hash();
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

    /// List all known public key hashes in deterministic device-key order.
    ///
    /// The keys from [`crate::key_role::DeviceKey::ALL`] come first (consensus,
    /// companion, then the tz6 consensus key), matched case-insensitively so
    /// stored casing cannot reshuffle the prefix. Any key under no device alias
    /// follows. Both groups break ties by base58 pkh, so `HashMap` iteration
    /// order cannot reach the result even when two stored keys carry the same
    /// alias.
    ///
    /// A stored alias is resolved rather than compared against the canonical
    /// spelling, so a card provisioned before the scheme suffix puts each of
    /// its keys in the slot the host reads it from.
    ///
    /// The host utility reads the prefix by slot, so a device key holds its own
    /// slot whatever else is stored: leaving the tz6 key to the sorted tail puts
    /// whichever unrelated key sorts lowest where the host looks for it.
    #[must_use]
    pub fn list_keys(&self) -> Vec<PublicKeyHash> {
        use crate::key_role::DeviceKey;

        // Resolved once per stored name rather than once per slot: which key a
        // name names does not depend on the slot being filled.
        let resolved: Vec<(DeviceKey, PublicKeyHash)> = self
            .key_names
            .iter()
            .filter_map(|(pkh, name)| DeviceKey::from_device_alias(name).map(|key| (key, *pkh)))
            .collect();

        let mut keys = Vec::with_capacity(self.signers.len());
        let mut seen = std::collections::HashSet::with_capacity(DeviceKey::COUNT);
        for device_key in DeviceKey::ALL {
            if let Some(pkh) = resolved
                .iter()
                .filter(|(key, _)| *key == device_key)
                .map(|(_, pkh)| *pkh)
                .min_by_key(|pkh| {
                    DeviceKey::slot_order(device_key.device_alias(), &pkh.to_b58check())
                })
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
    /// Open connections, which the deferred writer waits out before taking the
    /// watermark's write lock.
    idle: Arc<IdleGate>,
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
            idle: Arc::new(IdleGate::default()),
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
        self.idle.enter();
        if let Some(ref callback) = self.pre_sign_callback {
            callback();
        }
    }

    /// Notify that a client connection has closed (e.g., restore CPU frequency).
    pub fn notify_request_complete(&self) {
        self.idle.leave();
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
                    let name = keys.get_key_name(pkh).unwrap_or("").to_string();
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
        pkh_and_version: (PublicKeyHash, SignatureVersion),
        data: &[u8],
    ) -> Result<(SignerResponse, Option<ChainId>)> {
        let (pkh, version) = pkh_and_version;
        log::debug!(
            "Signature request for key: {} (version {})",
            pkh.to_b58check(),
            version.number()
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

        // A version whose union lacks this key's scheme can never be answered.
        // Refusing here rather than at the signature keeps the mark where it
        // was and, for a tz6 key, spends no epoch on a request with no answer.
        signer.check_version(version)?;

        // 2. Check high watermark
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        // Parse tenderbake fields once for prechecks, activity, and check_and_update.
        let parsed = Self::parse_sign_payload(data, pkh.scheme());
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
        // The client's requested version decides the union the response is read
        // back under, so a key whose scheme that union lacks is refused rather
        // than answered with bytes the client cannot parse.
        let sign_data = |epoch: Option<Epoch>| signer.sign_at(data, None, Some(version), epoch);

        // 2b+4. Check watermark, then sign + watermark persist in parallel.
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

            // Under a scheme that spends one, the epoch is claimed here: the
            // resume point past it reaches stable storage before the epoch
            // leaves the store, so a crash costs the epoch rather than the key.
            // That write cannot run beside the signature the way the mark's
            // does — a mark written late still refuses the next request at that
            // level, where an epoch reused after a crash discloses the secret.
            let epoch = if wm.spends_epochs(&pkh) {
                match wm.claim_epoch(&pkh) {
                    Ok(epoch) => Some(epoch),
                    Err(e) => {
                        if let Some(ref update) = watermark_update {
                            wm.rollback_update(update);
                        }
                        drop(wm);
                        if let Some(ref callback) = self.watermark_error_callback {
                            callback(pkh, chain_id, &e);
                        }
                        return Err(Error::Watermark(e));
                    }
                }
            } else {
                None
            };

            if let Some(ref update) = watermark_update {
                // Fast path: ceiling on stable storage covers this update — no disk
                // I/O needed, just sign. The background ceiling thread will
                // update the file after we return the signature.
                // Slow path: no ceiling — fdatasync needed, parallelize with signing.
                let (sign_result, write_result) = if wm.ceiling_covers(update) {
                    (sign_data(epoch), Ok(()))
                } else {
                    std::thread::scope(|s| {
                        let sign_handle = s.spawn(|| sign_data(epoch));
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

                // Write ahead for the next level once this burst is over, so
                // neither its fsync sits in front of a signature.
                if let Some(ceil_level) = update.level().checked_add(1) {
                    let watermark_arc = Arc::clone(watermark);
                    let ceil_pkh = update.pkh();
                    let ceil_op_type = update.op_type();
                    let notify = self.signing_notify_callback.clone();
                    let idle = Arc::clone(&self.idle);
                    let warm_signer = signer.clone();
                    std::thread::spawn(move || {
                        if !idle.wait_for_idle(BURST_WAIT) {
                            log::debug!("Writing ahead while a connection is still open");
                        }
                        let ok = write_ahead_of_next_level(
                            &watermark_arc,
                            ceil_pkh,
                            ceil_op_type,
                            ceil_level,
                        );
                        if let Some(epoch) =
                            warm_ahead_of_next_boundary(&watermark_arc, &warm_signer, &ceil_pkh)
                        {
                            log::debug!("Warmed the subtree covering epoch {epoch}");
                        }
                        if ok && let Some(ref cb) = notify {
                            cb();
                        }
                    });
                }

                (signature, sign_start.elapsed())
            } else {
                // Non-watermarked operation type
                drop(wm);
                let signature = sign_data(epoch)?;
                (signature, sign_start.elapsed())
            }
        } else {
            // No watermark configured, so no store could have claimed an epoch;
            // a key of a scheme that spends one refuses rather than choosing.
            let signature = sign_data(None)?;
            (signature, sign_start.elapsed())
        };

        #[cfg(feature = "perf-trace")]
        log::info!("[PERF] BLS sign + watermark write: {:?}", t.elapsed());

        // Exact device aliases only: substring matches would mis-classify keys
        // and still notify the UI for a frame that did not change.
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

                    // Through the device key rather than the role, so the tz6
                    // consensus key records in the consensus slot: the activity
                    // views are role-indexed and carry no scheme.
                    if let Some(role) = crate::key_role::DeviceKey::from_device_alias(&key_name)
                        .map(crate::key_role::DeviceKey::role)
                    {
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
                        let expected: Vec<_> = crate::key_role::DeviceKey::ALL
                            .iter()
                            .map(|k| k.device_alias())
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
    /// The attestation and preattestation layout is the signing key's, since a
    /// tz4 payload omits the committee slot every other scheme's carries.
    fn parse_sign_payload(data: &[u8], scheme: Scheme) -> ParsedSignPayload {
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
            0x12 | 0x13 => {
                magic_bytes::get_level_and_round_for_tenderbake_attestation(data, scheme)
                    .ok()
                    .map_or((None, None), |(l, r)| (Some(l), Some(r)))
            }
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

/// Put the next level's durable state on disk: the ceiling that lets its marks
/// skip an fsync, and the epochs its signatures will spend.
///
/// Both take the watermark's write lock, which is why they run together and
/// out of the sign path rather than beside a signature. Returns whether the
/// ceiling reached disk, which is what a UI refresh keys on; a key of a scheme
/// that spends no epochs reserves none.
fn write_ahead_of_next_level(
    watermark: &RwLock<HighWatermark>,
    pkh: PublicKeyHash,
    op_type: crate::high_watermark::OperationType,
    ceil_level: u32,
) -> bool {
    let Ok(mut wm) = watermark.write() else {
        return false;
    };

    let wrote_ceiling = match wm.write_ceiling(pkh, op_type, ceil_level) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("Failed to write ceiling watermark: {e}");
            false
        }
    };

    if let Some(next) = wm.next_epoch(&pkh)
        && let Err(e) = wm.reserve_epochs(&pkh, next + crate::high_watermark::EPOCH_BURST)
    {
        log::warn!("Failed to reserve epochs: {e}");
    }

    wrote_ceiling
}

/// Build the subtree the next burst of signatures crosses into, and report
/// the epoch built for.
///
/// Runs after [`write_ahead_of_next_level`] rather than inside it: that holds
/// the watermark's write lock, and a build under it would hold every signature
/// for the build's length, which at the largest range is seconds. Takes the read
/// lock only, for the epoch a claim will hand out next.
fn warm_ahead_of_next_boundary(
    watermark: &RwLock<HighWatermark>,
    signer: &Unencrypted,
    pkh: &PublicKeyHash,
) -> Option<crate::xmss::Epoch> {
    let next = watermark.read().ok()?.next_epoch(pkh)?;
    let next = crate::xmss::Epoch::try_from(next).ok()?;
    let lookahead = crate::xmss::Lookahead(
        crate::xmss::Epoch::try_from(crate::high_watermark::EPOCH_BURST).ok()?,
    );

    let secret = signer.secret_key();
    let epoch = secret.epoch_to_warm(next, lookahead)?;
    match secret.warm(epoch) {
        Ok(warmed) => warmed,
        Err(e) => {
            log::warn!("Failed to warm the subtree covering epoch {epoch}: {e}");
            None
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
    use crate::test_utils::generate_key;
    use crate::test_utils::{
        create_attestation_data_for, create_block_data, create_preattestation_data_for,
        default_test_chain_id, new_epoch_watermark, new_mixed_watermark, new_watermark,
        preinit_watermarks,
    };
    use tempfile::TempDir;

    /// A tz4 attestation omits the committee slot a tz6 one carries, so reading
    /// one at the other's offset takes slot bytes for level bytes and marks a
    /// level the baker never asked to sign.
    #[test]
    fn a_consensus_payload_is_parsed_in_its_signing_key_s_layout() {
        for scheme in [Scheme::Bls, Scheme::Xmss] {
            for data in [
                create_attestation_data_for(scheme, 100, 3),
                create_preattestation_data_for(scheme, 100, 3),
            ] {
                let parsed = RequestHandler::parse_sign_payload(&data, scheme);

                assert_eq!(
                    (parsed.level, parsed.round),
                    (Some(100), Some(3)),
                    "{scheme} magic byte 0x{:02X}",
                    data[0]
                );
            }
        }
    }

    /// A tz4 and a tz6 can hold the same 20 bytes. Resolving one to the other's
    /// signer would answer a request under a key it did not name, so the lookup
    /// distinguishes them.
    #[test]
    fn a_tz6_hash_does_not_resolve_to_the_tz4_signer_of_the_same_bytes() {
        let signer = Unencrypted::generate(Some(&[42u8; 32])).unwrap();
        let pkh = *signer.public_key_hash();
        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "consensus".to_string());

        let shadow = PublicKeyHash::from_bytes(Scheme::Xmss, pkh.to_bytes()).unwrap();

        assert_eq!(shadow.to_bytes(), pkh.to_bytes());
        assert!(mgr.get_signer(&pkh).is_ok());
        assert!(
            mgr.get_signer(&shadow).is_err(),
            "a tz6 request resolved to the tz4 signer of the same bytes"
        );
    }

    #[test]
    fn test_key_manager_basic() {
        let mut mgr = KeyManager::new();
        let seed = [42u8; 32];
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        mgr.add_signer(signer, "test_key".to_string());

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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();
        let pk = signer.public_key().clone();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
        use crate::key_role::{DeviceKey, KeyRole};

        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let signer1 = Unencrypted::generate(Some(&seed1)).unwrap();
        let signer2 = Unencrypted::generate(Some(&seed2)).unwrap();
        let consensus_pkh = *signer1.public_key_hash();
        let companion_pkh = *signer2.public_key_hash();

        let mut mgr = KeyManager::new();
        // Insert companion first to prove ordering is by role, not insertion order
        mgr.add_signer(
            signer2,
            DeviceKey::Bls(KeyRole::Companion)
                .device_alias()
                .to_string(),
        );
        mgr.add_signer(
            signer1,
            DeviceKey::Bls(KeyRole::Consensus)
                .device_alias()
                .to_string(),
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
        use crate::key_role::{DeviceKey, KeyRole};

        let mut mgr = KeyManager::new();
        let mut colliding = Vec::new();
        for (seed, alias) in [
            (
                [1u8; 32],
                DeviceKey::Bls(KeyRole::Consensus)
                    .device_alias()
                    .to_string(),
            ),
            (
                [2u8; 32],
                DeviceKey::Bls(KeyRole::Consensus)
                    .device_alias()
                    .to_uppercase(),
            ),
        ] {
            let signer = Unencrypted::generate(Some(&seed)).unwrap();
            let pkh = *signer.public_key_hash();
            mgr.add_signer(signer, alias);
            colliding.push(pkh);
        }

        let listed = mgr.list_keys();

        assert_eq!(listed.len(), 2);
        assert!(
            listed.iter().all(|pkh| colliding.contains(pkh)),
            "list_keys returned {listed:?}, not the added {colliding:?}"
        );
        let (role_slot, extra) = (listed[0].to_b58check(), listed[1].to_b58check());
        assert!(
            role_slot < extra,
            "role slot took {role_slot}, above {extra} in the sorted extras"
        );
    }

    /// The device holds three keys once a tz6 one is provisioned, and the host
    /// reads them by slot. The extra key is seeded so its address sorts below
    /// the tz6 key's: with the tz6 key left to the base58-sorted tail, that is
    /// what takes its slot.
    #[test]
    fn every_device_key_holds_its_slot_ahead_of_the_extras() {
        use crate::key_role::DeviceKey;

        let mut mgr = KeyManager::new();
        let mut device_pkhs = Vec::with_capacity(DeviceKey::COUNT);
        for (seed, key) in [[1u8; 32], [3u8; 32], [5u8; 32]]
            .into_iter()
            .zip(DeviceKey::ALL)
        {
            let signer = Unencrypted::generate(Some(&seed)).unwrap();
            device_pkhs.push(*signer.public_key_hash());
            mgr.add_signer(signer, key.device_alias().to_string());
        }
        let extra = Unencrypted::generate(Some(&[2u8; 32])).unwrap();
        let extra_pkh = *extra.public_key_hash();
        mgr.add_signer(extra, "extra".to_string());
        assert!(
            extra_pkh.to_b58check() < device_pkhs[2].to_b58check(),
            "the extra key no longer sorts below the tz6 key, so this cannot see the slot"
        );

        let listed = mgr.list_keys();

        assert_eq!(listed.len(), DeviceKey::COUNT + 1);
        assert_eq!(&listed[..DeviceKey::COUNT], &device_pkhs[..]);
        assert_eq!(listed[DeviceKey::COUNT], extra_pkh);
    }

    #[test]
    fn list_keys_role_order_is_case_insensitive_and_extras_sorted() {
        let seeds: [[u8; 32]; 4] = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let mut pkhs = Vec::new();
        let mut mgr = KeyManager::new();
        for (i, seed) in seeds.iter().enumerate() {
            let signer = Unencrypted::generate(Some(seed)).unwrap();
            let pkh = *signer.public_key_hash();
            let name = match i {
                // Mixed case must still land in the global role slots.
                0 => "Consensus".to_string(),
                1 => "COMPANION".to_string(),
                2 => "extra_z".to_string(),
                _ => "extra_a".to_string(),
            };
            mgr.add_signer(signer, name);
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

    /// A tz6 signer over a 16-epoch key. Generation walks every in-range leaf,
    /// so the range is kept small enough that the cost does not dominate a test.
    fn xmss_signer(seed: u8) -> Unencrypted {
        let (sk, _) = crate::xmss::SecretKey::generate([seed; 32], 0, 15).expect("range is valid");
        Unencrypted::new(crate::scheme::SecretKey::Xmss(std::sync::Arc::new(sk)))
    }

    /// The fixture's subtree width, taken off the key rather than derived from
    /// its range: upstream owns the width, and a second derivation here would
    /// put the test on a boundary the key does not use.
    fn subtree_width(signer: &Unencrypted) -> crate::xmss::Epoch {
        match signer.secret_key() {
            crate::scheme::SecretKey::Xmss(sk) => sk.subtree_width(),
            crate::scheme::SecretKey::Bls(_) => panic!("the fixture is a tz6 key"),
        }
    }

    /// A handler over `signers`, each key spending the epochs its own secret
    /// reports, with the Tenderbake marks seeded at `floor` and every epoch
    /// counter established at its range's first epoch.
    ///
    /// The store comes back beside the handler because what a request did to a
    /// counter is only readable there.
    fn device(
        dir: &std::path::Path,
        signers: &[Unencrypted],
        floor: u32,
    ) -> (RequestHandler, Arc<RwLock<HighWatermark>>) {
        let mut mgr = KeyManager::new();
        let mut keys = Vec::new();
        for signer in signers {
            let pkh = *signer.public_key_hash();
            preinit_watermarks(dir, &pkh, floor);
            keys.push((pkh, signer.secret_key().epoch_range()));
            mgr.add_signer(signer.clone(), pkh.scheme().to_string());
        }

        let mut hwm = new_mixed_watermark(dir, &keys).unwrap();
        for (pkh, epochs) in &keys {
            if epochs.is_some() {
                hwm.seed_epoch_floor(pkh, 0).unwrap();
            }
        }

        let hwm = Arc::new(RwLock::new(hwm));
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(magic_bytes::MagicByte::all()),
            true,
            true,
        );
        (handler, hwm)
    }

    fn sign_request(
        handler: &RequestHandler,
        pkh: PublicKeyHash,
        data: &[u8],
    ) -> Result<SignerResponse> {
        handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, SignatureVersion::V4),
                data: data.to_vec(),
                signature: None,
            })
            .map(|(response, _)| response)
    }

    fn xmss_signature(response: SignerResponse) -> Box<crate::xmss::Signature> {
        match response {
            SignerResponse::Signature(crate::scheme::Signature::Xmss(sig)) => sig,
            other => panic!("a tz6 request answered with {other:?}"),
        }
    }

    /// leanVM-b's verifier takes the epoch as a separate input and the wire has
    /// no field for one, so the signature carries it — and the epoch it carries
    /// is the one the device's store handed out, nothing the request chose.
    #[test]
    fn a_tz6_signature_carries_the_epoch_the_store_handed_out() {
        let temp_dir = TempDir::new().unwrap();
        let signer = xmss_signer(7);
        let pkh = *signer.public_key_hash();
        let (handler, hwm) = device(temp_dir.path(), std::slice::from_ref(&signer), 99);
        let claimed = hwm.read().unwrap().next_epoch(&pkh).unwrap();

        let data = create_block_data(100, 0);
        let signature = xmss_signature(sign_request(&handler, pkh, &data).unwrap());

        assert_eq!(u64::from(signature.epoch()), claimed);
        let PublicKey::Xmss(pk) = signer.public_key() else {
            panic!("a tz6 signer holds an xmpk");
        };
        pk.verify(&signature, None, &data)
            .expect("the signature verifies under the signing key at that epoch");
        assert_eq!(hwm.read().unwrap().next_epoch(&pkh), Some(claimed + 1));
    }

    /// Signing two messages at one epoch discloses the secret key, so every
    /// request spends its own — across the three magic bytes, whose marks
    /// advance independently, as much as within one.
    #[test]
    fn every_tz6_request_spends_a_fresh_epoch() {
        let temp_dir = TempDir::new().unwrap();
        let signer = xmss_signer(8);
        let pkh = *signer.public_key_hash();
        let (handler, _) = device(temp_dir.path(), &[signer], 99);

        let spent: Vec<u32> = [
            create_block_data(100, 0),
            create_preattestation_data_for(Scheme::Xmss, 100, 0),
            create_attestation_data_for(Scheme::Xmss, 100, 0),
            create_block_data(101, 0),
        ]
        .iter()
        .map(|data| xmss_signature(sign_request(&handler, pkh, data).unwrap()).epoch())
        .collect();

        let mut distinct = spent.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            spent.len(),
            "an epoch was spent twice: {spent:?}"
        );
    }

    /// An epoch used before its resume point is durable is handed out again
    /// after a crash, so a claim that will not persist refuses the signature —
    /// and leaves the mark where the baker can still retry at that level.
    #[test]
    fn a_tz6_request_whose_epoch_will_not_persist_yields_no_signature() {
        let temp_dir = TempDir::new().unwrap();
        let signer = xmss_signer(9);
        let pkh = *signer.public_key_hash();
        let (handler, hwm) = device(temp_dir.path(), &[signer], 99);
        let standing = hwm.read().unwrap().next_epoch(&pkh);

        hwm.write().unwrap().set_write_error(true);
        let refused = sign_request(&handler, pkh, &create_block_data(100, 0));

        assert!(
            matches!(
                refused,
                Err(Error::Watermark(crate::high_watermark::WatermarkError::Io(
                    _
                )))
            ),
            "expected a refusal, got {refused:?}"
        );
        assert_eq!(hwm.read().unwrap().next_epoch(&pkh), standing);

        hwm.write().unwrap().set_write_error(false);
        assert!(
            sign_request(&handler, pkh, &create_block_data(100, 0)).is_ok(),
            "the refused request left the mark advanced, so the retry was refused too"
        );
    }

    /// XMSS enters the signature union at V4, so a request below it can never
    /// be answered — and an epoch spent reaching that refusal is a one-time key
    /// gone for nothing.
    #[test]
    fn a_tz6_request_below_v4_spends_no_epoch() {
        let temp_dir = TempDir::new().unwrap();
        let signer = xmss_signer(6);
        let pkh = *signer.public_key_hash();
        let (handler, hwm) = device(temp_dir.path(), &[signer], 99);
        let standing = hwm.read().unwrap().next_epoch(&pkh);

        let refused = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V3),
            data: create_block_data(100, 0),
            signature: None,
        });

        assert!(
            matches!(refused, Err(Error::Signer(_))),
            "expected a refusal, got {refused:?}"
        );
        assert_eq!(hwm.read().unwrap().next_epoch(&pkh), standing);
        assert!(
            sign_request(&handler, pkh, &create_block_data(100, 0)).is_ok(),
            "the refused request left the mark advanced"
        );
    }

    /// One card holds a tz4 and a tz6 key. Each request moves its own key's
    /// state and nothing of the other's, and only the tz6 key spends epochs.
    #[test]
    fn a_tz4_and_a_tz6_request_advance_only_their_own_key() {
        let temp_dir = TempDir::new().unwrap();
        let tz4 = Unencrypted::generate(Some(&[3u8; 32])).unwrap();
        let tz6 = xmss_signer(4);
        let (bls_pkh, xmss_pkh) = (*tz4.public_key_hash(), *tz6.public_key_hash());
        let (handler, hwm) = device(temp_dir.path(), &[tz4, tz6], 99);

        assert_eq!(hwm.read().unwrap().next_epoch(&bls_pkh), None);
        let before = hwm.read().unwrap().next_epoch(&xmss_pkh).unwrap();

        sign_request(&handler, bls_pkh, &create_block_data(100, 0)).unwrap();
        assert_eq!(
            hwm.read().unwrap().next_epoch(&xmss_pkh),
            Some(before),
            "a tz4 signature spent the tz6 key's epoch"
        );

        sign_request(&handler, xmss_pkh, &create_block_data(100, 0)).unwrap();
        assert_eq!(hwm.read().unwrap().next_epoch(&xmss_pkh), Some(before + 1));
        assert_eq!(hwm.read().unwrap().next_epoch(&bls_pkh), None);
        assert_eq!(
            hwm.read()
                .unwrap()
                .get_current_level(default_test_chain_id(), &bls_pkh),
            Some(100),
            "each key keeps its own mark"
        );
    }

    /// The deferred writer must not take the write lock inside a signing burst,
    /// and a burst is a connection: a level's three signatures arrive on one.
    /// So the wait ends when the last connection closes rather than a second
    /// later.
    #[test]
    fn an_idle_wait_ends_when_the_last_connection_closes() {
        let gate = Arc::new(IdleGate::default());
        gate.enter();

        let waiter = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || gate.wait_for_idle(Duration::from_secs(30)))
        };

        // The count is raised while the waiter still holds the lock, and the
        // park releases it atomically, so reading the count from here at all
        // means that waiter is parked and only the notify can end its wait.
        // Without one it runs the full 30 seconds and times this test out.
        loop {
            let parked = gate.state().waiting;
            if parked > 0 {
                break;
            }
            std::thread::yield_now();
        }

        let closed = std::time::Instant::now();
        gate.leave();
        let saw_idle = waiter.join().unwrap();

        assert!(
            saw_idle,
            "the wait ended without ever seeing the handler idle"
        );
        assert!(
            closed.elapsed() < Duration::from_secs(5),
            "the wait outlived the connection by {:?}",
            closed.elapsed()
        );
    }

    /// A card under continuous load never goes idle, so the wait is bounded and
    /// the write goes ahead rather than never running.
    #[test]
    fn an_idle_wait_gives_up_while_a_connection_is_open() {
        let gate = IdleGate::default();
        gate.enter();

        assert!(!gate.wait_for_idle(Duration::from_millis(10)));
    }

    /// A claim outside a reservation pays an fsync before it can return the
    /// epoch, so the deferred write puts the next level's epochs on disk beside
    /// its ceiling — both under the one write lock it already has to take.
    #[test]
    fn the_deferred_write_reserves_the_next_level_s_epochs() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = *xmss_signer(5).public_key_hash();
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, 0..=63).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        hwm.claim_epoch(&pkh).unwrap();
        let watermark = RwLock::new(hwm);

        let wrote_ceiling = write_ahead_of_next_level(
            &watermark,
            pkh,
            crate::high_watermark::OperationType::Block,
            101,
        );

        let wm = watermark.read().unwrap();
        assert!(wrote_ceiling);
        assert_eq!(
            wm.get_disk_ceiling(&pkh, crate::high_watermark::OperationType::Block)
                .map(|entry| entry.level),
            Some(101)
        );
        assert_eq!(
            wm.epoch_resume_point(&pkh),
            wm.next_epoch(&pkh)
                .map(|next| next + crate::high_watermark::EPOCH_BURST),
            "the reservation does not cover the next level's three signatures"
        );
    }

    /// A tz4 key spends no epochs, so the deferred write has nothing to reserve
    /// for it and must not turn that into a failure the UI reads as one.
    #[test]
    fn the_deferred_write_reserves_nothing_for_a_tz4_key() {
        let temp_dir = TempDir::new().unwrap();
        let (pkh, ..) = generate_key(Some(&[11u8; 32])).unwrap();
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let watermark = RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap());

        let wrote_ceiling = write_ahead_of_next_level(
            &watermark,
            pkh,
            crate::high_watermark::OperationType::Block,
            101,
        );

        assert!(wrote_ceiling);
        assert_eq!(watermark.read().unwrap().epoch_resume_point(&pkh), None);
    }

    #[test]
    fn test_request_handler_sign_with_watermark() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
        let data = create_block_data(100, 0);

        // First sign should succeed
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, SignatureVersion::V4),
                data: data.clone(),
                signature: None,
            })
            .unwrap();

        assert!(matches!(response, SignerResponse::Signature(_)));

        // Create data at level 99 (below watermark)
        let data_low = create_block_data(99, 0);

        // Second sign at lower level should fail with watermark error
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
                pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
                pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
        let data = create_block_data(100, 0);

        // Sign the data (watermark write happens inside handle_request)
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
        let data = create_block_data(50, 0);

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let _chain_id = ChainId::from_bytes(&chain_id_bytes);

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
        let data = create_block_data(600, 0);

        // Sign should fail with LargeLevelGap error
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let _chain_id = ChainId::from_bytes(&chain_id_bytes);

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
        let data = create_block_data(400, 0);

        // Sign should succeed (gap is 300, below 400 threshold)
        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
        let data = create_block_data(600, 0);

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V4),
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
        let known_signer = Unencrypted::generate(Some(&[42u8; 32])).unwrap();
        let known_pkh = *known_signer.public_key_hash();
        let (unknown_pkh, ..) = generate_key(Some(&[7u8; 32])).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(known_signer, "known".to_string());

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
        let data = create_block_data(600, 0);

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (unknown_pkh, SignatureVersion::V4),
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
        let known_signer = Unencrypted::generate(Some(&[42u8; 32])).unwrap();
        let known_pkh = *known_signer.public_key_hash();
        let (unknown_pkh, ..) = generate_key(Some(&[7u8; 32])).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(known_signer, "known".to_string());

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
        let data = create_block_data(600, 0);

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (unknown_pkh, SignatureVersion::V4),
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
        let known_signer = Unencrypted::generate(Some(&[42u8; 32])).unwrap();
        let (unknown_pkh, ..) = generate_key(Some(&[7u8; 32])).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(known_signer, "known".to_string());

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
                    pkh: (pkh, SignatureVersion::V4),
                    data: vec![0x01, 0x02, 0x03],
                    signature: None,
                }
            }),
            ("DeterministicNonceHash", |pkh| {
                SignerRequest::DeterministicNonceHash {
                    pkh: (pkh, SignatureVersion::V4),
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
                pkh: (unknown_pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

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
        let data = create_block_data(200, 0);

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V4),
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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        // Inject write error
        hwm.write().unwrap().set_write_error(true);

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
            pkh: (pkh, SignatureVersion::V4),
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

    /// Gap detection divides the level difference by the cycle length, so a
    /// card whose chain record names no cycle length has to skip the check
    /// rather than reach the division at all.
    #[test]
    fn test_zero_blocks_per_cycle_does_not_panic() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();

        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, "test_key".to_string());

        preinit_watermarks(temp_dir.path(), &pkh, 100);
        let hwm = Arc::new(RwLock::new(new_watermark(temp_dir.path(), &[pkh]).unwrap()));

        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = Arc::clone(&callback_triggered);

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
            0,
        );

        // Far enough above the watermark that a cycle length of any width
        // would report a gap.
        let data = create_block_data(10000, 0);

        let result = handler.handle_request(SignerRequest::Sign {
            pkh: (pkh, SignatureVersion::V4),
            data,
            signature: None,
        });

        assert!(
            result.is_ok(),
            "Sign should succeed when blocks_per_cycle is 0: {result:?}"
        );

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
        let signer = Unencrypted::generate(Some(&seed)).unwrap();
        let pkh = *signer.public_key_hash();
        let mut mgr = KeyManager::new();
        mgr.add_signer(signer, alias.to_string());

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
                pkh: (pkh, SignatureVersion::V4),
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
        use crate::key_role::{DeviceKey, KeyRole};
        use crate::signing_activity::OperationType;
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) =
            activity_sign_fixture(DeviceKey::Bls(KeyRole::Consensus).device_alias());
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
        use crate::key_role::{DeviceKey, KeyRole};
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) =
            activity_sign_fixture(DeviceKey::Bls(KeyRole::Companion).device_alias());
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

    /// A tz6 signature is a consensus signature. The activity views are indexed
    /// by role and carry no scheme, so it belongs in the consensus slot beside
    /// the tz4 key's rather than in neither.
    #[test]
    fn sign_xmss_consensus_alias_records_under_the_consensus_role() {
        use crate::key_role::{DeviceKey, KeyRole};
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) =
            activity_sign_fixture(DeviceKey::XmssConsensus.device_alias());
        sign_block(&handler, pkh, 250);

        assert_eq!(notify_count.load(Ordering::SeqCst), 1);
        let a = activity.lock().unwrap();
        assert_eq!(a.total_signatures, 1);
        let event = a.recent_events.iter().next().unwrap();
        assert_eq!(event.role, KeyRole::Consensus);
        assert_eq!(event.activity.level, Some(250));
        assert!(a.last(KeyRole::Consensus).is_some());
        assert!(a.last(KeyRole::Companion).is_none());
    }

    /// A stored alias resolves whatever its casing, so the slot a signature
    /// records under does not depend on how the card spelled the key.
    #[test]
    fn sign_consensus_alias_is_case_insensitive() {
        use crate::key_role::KeyRole;

        let (handler, pkh, activity, _) = activity_sign_fixture("Consensus");
        sign_block(&handler, pkh, 10);

        let a = activity.lock().unwrap();
        assert_eq!(a.total_signatures, 1);
        let event = a.recent_events.iter().next().expect("one recorded event");
        assert_eq!(event.role, KeyRole::Consensus);
        assert_eq!(event.activity.level, Some(10));
        assert!(a.last(KeyRole::Consensus).is_some());
        assert!(a.last(KeyRole::Companion).is_none());
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

    /// A stored alias means one key whatever its casing, which is what
    /// `list_keys()` already reads it as when it puts the key in its slot. A
    /// second reader disagreeing leaves that key listed and signing while its
    /// signatures are recorded against nothing.
    #[test]
    fn sign_mixed_case_alias_records_activity() {
        use crate::key_role::{DeviceKey, KeyRole};
        use std::sync::atomic::Ordering;

        let stored = DeviceKey::Bls(KeyRole::Consensus)
            .device_alias()
            .to_uppercase();
        let (handler, pkh, activity, notify_count) = activity_sign_fixture(&stored);
        sign_block(&handler, pkh, 150);

        assert_eq!(notify_count.load(Ordering::SeqCst), 1);
        let a = activity.lock().unwrap();
        assert_eq!(a.total_signatures, 1);
        assert!(a.last(KeyRole::Consensus).is_some());
    }

    /// Substring is not a role: only exact role aliases record.
    #[test]
    fn sign_substring_alias_neither_records_nor_notifies() {
        use crate::key_role::{DeviceKey, KeyRole};
        use std::sync::atomic::Ordering;

        let (handler, pkh, activity, notify_count) = activity_sign_fixture(&format!(
            "my-{}-key",
            DeviceKey::Bls(KeyRole::Consensus).device_alias()
        ));
        sign_block(&handler, pkh, 1);
        assert_eq!(activity.lock().unwrap().total_signatures, 0);
        assert_eq!(notify_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sign_attestation_records_level_and_operation_type() {
        use crate::key_role::{DeviceKey, KeyRole};
        use crate::signing_activity::OperationType;

        let (handler, pkh, activity, _) =
            activity_sign_fixture(DeviceKey::Bls(KeyRole::Consensus).device_alias());
        let data = crate::test_utils::create_attestation_data(42, 1);
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, SignatureVersion::V4),
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

    /// The warm has to key on the epoch a claim will hand out, not the one just
    /// spent: a burst measured from the epoch behind it stops one short of the
    /// boundary and leaves the crossing signature to build the subtree itself.
    #[test]
    fn the_warm_reads_the_epoch_a_claim_will_hand_out_next() {
        let dir = TempDir::new().unwrap();
        let signer = xmss_signer(9);
        let pkh = *signer.public_key_hash();
        let (_handler, hwm) = device(dir.path(), std::slice::from_ref(&signer), 0);
        let width = subtree_width(&signer);

        assert_eq!(
            warm_ahead_of_next_boundary(&hwm, &signer, &pkh),
            None,
            "a burst from the range's first epoch stays inside its subtree"
        );

        hwm.write().unwrap().claim_epoch(&pkh).unwrap();

        assert_eq!(
            warm_ahead_of_next_boundary(&hwm, &signer, &pkh),
            Some(width)
        );
    }

    /// A tz4 key has no epoch counter, so nothing names an epoch to warm.
    #[test]
    fn a_key_spending_no_epochs_warms_nothing() {
        let dir = TempDir::new().unwrap();
        let signer = Unencrypted::generate(Some(&[4u8; 32])).unwrap();
        let pkh = *signer.public_key_hash();
        let (_handler, hwm) = device(dir.path(), std::slice::from_ref(&signer), 0);

        assert_eq!(warm_ahead_of_next_boundary(&hwm, &signer, &pkh), None);
    }
}
