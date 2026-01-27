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
use crate::signer::{SignerHandler, UnencryptedSigner};
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
        eprintln!(
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
        eprintln!(
            "[CONCURRENCY] Request completed (from {}), {} still active (was {})",
            self.addr,
            prev_count - 1,
            prev_count
        );
    }
}

/// Server error
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),

    /// Signer error
    #[error("Signer error: {0}")]
    Signer(#[from] crate::signer::SignerError),

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
pub type Result<T> = std::result::Result<T, ServerError>;

// Implement From for PoisonError to enable ? operator on lock operations
impl<T> From<std::sync::PoisonError<T>> for ServerError {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        ServerError::Internal(format!("Lock poisoned: {e}"))
    }
}

/// Key manager for storing and retrieving signers
pub struct KeyManager {
    /// Map of public key hash to signer
    signers: HashMap<PublicKeyHash, UnencryptedSigner>,
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
    pub fn add_signer(&mut self, pkh: PublicKeyHash, signer: UnencryptedSigner, name: String) {
        self.signers.insert(pkh, signer);
        self.key_names.insert(pkh, name);
    }

    /// Get a signer by public key hash
    pub fn get_signer(&self, pkh: &PublicKeyHash) -> Result<&UnencryptedSigner> {
        self.signers
            .get(pkh)
            .ok_or_else(|| ServerError::KeyNotFound(pkh.to_b58check()))
    }

    /// Get the name of a key by public key hash
    #[must_use]
    pub fn get_key_name(&self, pkh: &PublicKeyHash) -> Option<&str> {
        self.key_names.get(pkh).map(String::as_str)
    }

    /// List all known public key hashes
    #[must_use]
    pub fn list_keys(&self) -> Vec<PublicKeyHash> {
        self.signers.keys().copied().collect()
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

/// Type alias for signing notification callback (called after each successful signature)
type SigningNotifyCallback = Arc<dyn Fn() + Send + Sync>;

/// Number of cycles threshold for large level gap detection
const LARGE_GAP_CYCLES: u32 = 4;

/// Request handler for processing signer requests
///
/// Corresponds to: src/bin_signer/handler.ml:275-309
pub struct RequestHandler {
    /// Key manager
    keys: Arc<RwLock<KeyManager>>,
    /// High watermark tracker (if enabled)
    watermark: Option<Arc<RwLock<HighWatermark>>>,
    /// Allowed magic bytes
    allowed_magic_bytes: Option<Vec<u8>>,
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
    /// Blocks per cycle (chain-specific, used for gap threshold calculation)
    blocks_per_cycle: Option<u32>,
}

impl RequestHandler {
    /// Create new request handler
    pub fn new(
        keys: Arc<RwLock<KeyManager>>,
        watermark: Option<Arc<RwLock<HighWatermark>>>,
        allowed_magic_bytes: Option<Vec<u8>>,
        allow_list_known_keys: bool,
        allow_prove_possession: bool,
    ) -> Self {
        Self {
            keys,
            watermark,
            allowed_magic_bytes,
            allow_list_known_keys,
            allow_prove_possession,
            signing_activity: None,
            watermark_error_callback: None,
            signing_notify_callback: None,
            large_gap_callback: None,
            blocks_per_cycle: None,
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

    /// Handle a signer request
    pub fn handle_request(&self, req: SignerRequest) -> Result<(SignerResponse, Option<ChainId>)> {
        match req {
            SignerRequest::Sign {
                pkh,
                data,
                signature: _,
            } => {
                let (response, chain_id) = self.handle_sign(pkh, &data)?;
                Ok((response, chain_id))
            }
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
        log::info!(
            "📝 Signature request for key: {} (version {})",
            pkh.to_b58check(),
            version
        );

        #[cfg(feature = "perf-trace")]
        let request_start = std::time::Instant::now();

        // 1. Check magic byte
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        if let Some(ref allowed) = self.allowed_magic_bytes {
            magic_bytes::check_magic_byte(data, Some(allowed))?;
        }

        #[cfg(feature = "perf-trace")]
        eprintln!("[PERF] Magic byte check: {:?}", t.elapsed());

        // 2. Check high watermark
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        // Extract Chain ID from data if this is a Tenderbake operation
        // Only operations with magic bytes 0x11, 0x12, 0x13 have chain IDs
        // For other operations (or when chain ID extraction fails), we skip watermarking
        // This matches OCaml behavior in handler.ml:211-231
        let operation_chain_id = if data.is_empty() {
            None
        } else {
            magic_bytes::get_chain_id_for_tenderbake(data).map(|bytes| {
                let mut padded = [0u8; 32];
                padded[..4].copy_from_slice(&bytes);
                ChainId::from_bytes(&padded)
            })
        };

        // 2a. Check for large level gap (stale watermark detection)
        // This must happen BEFORE the normal watermark check
        if let Some(chain_id) = operation_chain_id
            && let Some(ref watermark) = self.watermark
            && let Some(ref callback) = self.large_gap_callback
            && let Some(blocks_per_cycle) = self.blocks_per_cycle
            && blocks_per_cycle > 0
        {
            // Extract requested level from data
            let requested_level = Self::extract_level_from_data(data, &pkh);
            if let Some(requested_level) = requested_level {
                // Get current watermark level
                let wm = watermark.read()?;
                if let Some(current_level) = wm.get_current_level(chain_id, &pkh) {
                    let gap = requested_level.saturating_sub(current_level);
                    let threshold = LARGE_GAP_CYCLES * blocks_per_cycle;
                    if gap > threshold {
                        // Drop lock BEFORE calling callback to avoid deadlock
                        drop(wm);
                        callback(pkh, chain_id, current_level, requested_level);
                        let cycles = gap / blocks_per_cycle;
                        return Err(ServerError::Watermark(
                            crate::high_watermark::WatermarkError::LargeLevelGap {
                                current_level,
                                requested_level,
                                gap,
                                cycles,
                            },
                        ));
                    }
                }
            }
        }

        // 2b. Check high watermark (level/round validation)
        if let Some(chain_id) = operation_chain_id
            && let Some(ref watermark) = self.watermark
        {
            let wm = watermark.write()?;
            if let Err(e) = wm.check_and_update(chain_id, &pkh, data) {
                // Drop lock BEFORE calling callback to avoid deadlock
                // The callback may trigger UI events that could contend for locks
                drop(wm);
                if let Some(ref callback) = self.watermark_error_callback {
                    callback(pkh, chain_id, &e);
                }
                return Err(ServerError::Watermark(e));
            }
        }

        #[cfg(feature = "perf-trace")]
        eprintln!("[PERF] Watermark check: {:?}", t.elapsed());

        // 3. Get key and sign
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        let keys = self.keys.read()?;
        let signer = keys.get_signer(&pkh)?;

        // Create handler with same magic byte restrictions
        let handler = if let Some(ref allowed) = self.allowed_magic_bytes {
            SignerHandler::new(signer.clone(), Some(allowed.clone()))
        } else {
            SignerHandler::new(signer.clone(), None)
        };

        #[cfg(feature = "perf-trace")]
        eprintln!("[PERF] Get signer: {:?}", t.elapsed());

        // Sign directly (requests are serial, no spawn_blocking needed)
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        let sign_start = std::time::Instant::now();
        let signature = handler.sign(data, None, None)?;
        let sign_duration = sign_start.elapsed();

        #[cfg(feature = "perf-trace")]
        eprintln!("[PERF] BLS signing: {:?}", t.elapsed());

        // Update signing activity with metrics
        if let Some(ref activity_tracker) = self.signing_activity
            && let Ok(mut activity) = activity_tracker.lock()
        {
            // Extract operation details from data
            let operation_type = if data.is_empty() {
                None
            } else {
                crate::signing_activity::OperationType::from_magic_byte(data[0])
            };

            // Extract level from data
            let level = Self::extract_level_from_data(data, &pkh);

            let sig_activity = crate::signing_activity::SignatureActivity {
                level,
                timestamp: std::time::SystemTime::now(),
                duration: Some(sign_duration),
                operation_type,
                data_size: Some(data.len()),
            };

            // Determine if this is consensus or companion based on key name
            let key_name = keys.get_key_name(&pkh).unwrap_or("").to_lowercase();
            if key_name.contains("consensus") {
                activity.consensus = Some(sig_activity);
                log::debug!(
                    "Updated consensus signing activity: level={:?}, duration={:?}ms",
                    level,
                    sign_duration.as_millis()
                );
            } else if key_name.contains("companion") {
                activity.companion = Some(sig_activity);
                log::debug!(
                    "Updated companion signing activity: level={:?}, duration={:?}ms",
                    level,
                    sign_duration.as_millis()
                );
            }
        }

        // 4. Update watermark with signature
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        if let Some(chain_id) = operation_chain_id
            && let Some(ref watermark) = self.watermark
        {
            let wm = watermark.write()?;
            wm.update_signature(chain_id, &pkh, data, &signature)?;
        }

        #[cfg(feature = "perf-trace")]
        eprintln!("[PERF] Update watermark signature: {:?}", t.elapsed());

        #[cfg(feature = "perf-trace")]
        eprintln!(
            "[PERF] ===== TOTAL SIGN REQUEST: {:?} =====\n",
            request_start.elapsed()
        );

        // Notify that a signature was completed (for UI refresh)
        if let Some(ref callback) = self.signing_notify_callback {
            callback();
        }

        Ok((SignerResponse::Signature(signature), operation_chain_id))
    }

    /// Handle public key request
    fn handle_public_key(&self, pkh: PublicKeyHash) -> Result<SignerResponse> {
        let keys = self.keys.read()?;
        let signer = keys.get_signer(&pkh)?;
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
        let keys = self.keys.read()?;
        let signer = keys.get_signer(&pkh)?;

        let handler = SignerHandler::new(signer.clone(), None);

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
        let keys = self.keys.read()?;
        let signer = keys.get_signer(&pkh)?;

        let handler = SignerHandler::new(signer.clone(), None);

        // Generate nonce hash directly (requests are serial)
        let nonce_hash = handler.deterministic_nonce_hash(data);

        Ok(SignerResponse::NonceHash(nonce_hash))
    }

    /// Handle supports deterministic nonces request
    fn handle_supports_deterministic_nonces(&self, pkh: PublicKeyHash) -> Result<SignerResponse> {
        let keys = self
            .keys
            .read()
            .map_err(|e| ServerError::Internal(format!("Lock poisoned: {e}")))?;
        // Check if key exists
        let _ = keys.get_signer(&pkh)?;

        // All BLS signers support deterministic nonces
        Ok(SignerResponse::Bool(true))
    }

    /// Handle known keys request
    fn handle_known_keys(&self) -> Result<SignerResponse> {
        if !self.allow_list_known_keys {
            return Err(ServerError::NotAuthorized(
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
            return Err(ServerError::NotAuthorized(
                "Proof of possession is not authorized. Use --allow-to-prove-possession to enable."
                    .to_string(),
            ));
        }
        let keys = self.keys.read()?;
        let signer = keys.get_signer(&pkh)?;

        let handler = SignerHandler::new(signer.clone(), None);
        let proof = handler.bls_prove_possession(override_pk)?;

        Ok(SignerResponse::Signature(proof))
    }

    /// Extract level from Tenderbake operation data
    fn extract_level_from_data(data: &[u8], pkh: &PublicKeyHash) -> Option<u32> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            0x11 => {
                // Block signing
                magic_bytes::get_level_and_round_for_tenderbake_block(data)
                    .ok()
                    .map(|(level, _round)| level)
            }
            0x12 | 0x13 => {
                // Attestation or Pre-attestation
                let is_bls = pkh.to_b58check().starts_with("tz4");
                magic_bytes::get_level_and_round_for_tenderbake_attestation(data, is_bls)
                    .ok()
                    .map(|(level, _round)| level)
            }
            _ => None,
        }
    }
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

    let mut request_count = 0;
    loop {
        request_count += 1;
        log::debug!("Waiting for request #{request_count} from {addr}");

        let Some(msg_len) =
            read_message_length(&mut socket, addr, request_count, max_message_size)?
        else {
            return Ok(()); // Client closed connection
        };

        #[cfg(feature = "perf-trace")]
        let _guard = RequestGuard::new(addr);
        #[cfg(feature = "perf-trace")]
        let request_start = std::time::Instant::now();

        let sign_info = process_request(&mut socket, addr, msg_len, handler)?;

        flush_watermark_if_needed(handler, sign_info)?;

        #[cfg(feature = "perf-trace")]
        eprintln!(
            "[PERF] ===== TOTAL REQUEST (including TCP): {:?} =====\n",
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
            return Err(ServerError::Timeout);
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

fn check_http_and_size_error(len_buf: [u8; 2], addr: SocketAddr, msg_len: usize) -> ServerError {
    let possible_http = String::from_utf8_lossy(&len_buf);
    if possible_http.starts_with("GET ")
        || possible_http.starts_with("POST")
        || possible_http.starts_with("HEAD")
    {
        eprintln!(
            "⚠️  ERROR: Client {addr} sent HTTP request, but this server expects raw TCP protocol"
        );
        eprintln!("   HTTP request starts with: {possible_http}");
        eprintln!(
            "   SOLUTION: Change baker config from 'http://...' to 'tcp://...' or just the address"
        );
        ServerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP protocol not supported - use raw TCP (tcp://... or just address)",
        ))
    } else {
        ServerError::MessageTooLarge(msg_len)
    }
}

/// Process a single request: read, decode, handle, encode, write
/// Returns (pkh, `chain_id`) if this was a sign request that needs watermark flush
fn process_request(
    socket: &mut TcpStream,
    addr: SocketAddr,
    msg_len: usize,
    handler: &Arc<RequestHandler>,
) -> Result<Option<(PublicKeyHash, ChainId)>> {
    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let mut msg_buf = vec![0u8; msg_len];
    socket.read_exact(&mut msg_buf)?;

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] TCP read: {:?}", t.elapsed());

    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let request = decode_request(&msg_buf)?;
    log::debug!("<= RECV request from {addr}: {request:?}");

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Decode request: {:?}", t.elapsed());

    let sign_pkh = match &request {
        SignerRequest::Sign { pkh, .. } => Some(pkh.0),
        _ => None,
    };

    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let (response, sign_chain_id) = match handler.handle_request(request) {
        Ok((resp, chain_id)) => (resp, chain_id),
        Err(e) => (SignerResponse::Error(e.to_string()), None),
    };

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Handle request: {:?}", t.elapsed());

    #[cfg(feature = "perf-trace")]
    let t = std::time::Instant::now();

    let response_data = encode_response(&response)?;

    #[cfg(feature = "perf-trace")]
    eprintln!("[PERF] Encode response: {:?}", t.elapsed());

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
    eprintln!("[PERF] TCP write: {:?}", t.elapsed());

    Ok(sign_pkh.zip(sign_chain_id))
}

fn flush_watermark_if_needed(
    handler: &Arc<RequestHandler>,
    sign_info: Option<(PublicKeyHash, ChainId)>,
) -> Result<()> {
    if let Some((pkh, chain_id)) = sign_info {
        #[cfg(feature = "perf-trace")]
        let t = std::time::Instant::now();

        if let Some(ref watermark) = handler.watermark {
            let wm = watermark.read()?;
            if let Err(e) = wm.flush_to_disk(chain_id, &pkh) {
                log::error!(
                    "CRITICAL: Failed to flush watermark for {pkh:?} on chain {chain_id:?}: {e}"
                );
            }
        }

        #[cfg(feature = "perf-trace")]
        eprintln!("[PERF] Watermark flush to disk: {:?}", t.elapsed());
    }
    Ok(())
}

/// TCP signer server
///
/// Corresponds to: `src/bin_signer/socket_daemon.ml`
pub struct SignerServer {
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

impl SignerServer {
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
    pub fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.address)?;

        eprintln!("Listening on {}", self.address);

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
                    eprintln!("Connection error from {addr}: {e}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::generate_key;
    use crate::test_utils::preinit_watermarks;
    use tempfile::TempDir;

    #[test]
    fn test_key_manager_basic() {
        let mut mgr = KeyManager::new();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

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
        let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

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
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let (pkh1, _pk1, _sk1) = generate_key(Some(&seed1)).unwrap();
        let (pkh2, _pk2, _sk2) = generate_key(Some(&seed2)).unwrap();

        let signer1 = UnencryptedSigner::generate(Some(&seed1)).unwrap();
        let signer2 = UnencryptedSigner::generate(Some(&seed2)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh1, signer1, "key1".to_string());
        mgr.add_signer(pkh2, signer2, "key2".to_string());

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
                assert!(keys.contains(&pkh1));
                assert!(keys.contains(&pkh2));
            }
            _ => panic!("Expected KnownKeys response"),
        }
    }

    #[test]
    fn test_request_handler_sign_with_watermark() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let hwm = HighWatermark::new(temp_dir.path()).unwrap();
        let chain_id = ChainId::from_bytes(&[1u8; 32]);

        // Pre-initialize watermarks at level 99 (below the level 100 we'll sign)
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::new(RwLock::new(hwm))),
            Some(vec![0x11, 0x12, 0x13]),
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
        assert!(matches!(result.unwrap_err(), ServerError::Watermark(_)));
    }

    #[test]
    fn test_watermark_stores_signature() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let hwm = Arc::new(RwLock::new(HighWatermark::new(temp_dir.path()).unwrap()));

        // Use a consistent chain_id for the test
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let chain_id = ChainId::from_bytes(&chain_id_bytes);

        // Pre-initialize watermarks at level 99 (below the level 100 we'll sign)
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);

        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(vec![0x11, 0x12, 0x13]),
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

        // Sign the data
        let (response, _) = handler
            .handle_request(SignerRequest::Sign {
                pkh: (pkh, 0),
                data: data.clone(),
                signature: None,
            })
            .unwrap();

        // Extract the signature
        let SignerResponse::Signature(signature) = response else {
            panic!("Expected Signature response");
        };

        // Manually flush watermark to disk to simulate what the server loop does
        handler
            .watermark
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .flush_to_disk(chain_id, &pkh)
            .unwrap();

        // Load the watermark and verify signature was stored
        let watermark = hwm.read().unwrap().load_watermark(chain_id, &pkh).unwrap();
        assert!(watermark.block.is_some());
        let block_wm = watermark.block.as_ref().unwrap();
        assert_eq!(block_wm.level, 100);
        assert_eq!(block_wm.signature, signature.to_b58check());
        assert!(!block_wm.signature.is_empty());
    }

    #[test]
    fn test_large_level_gap_detection() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let hwm = Arc::new(RwLock::new(HighWatermark::new(temp_dir.path()).unwrap()));

        // Use a consistent chain_id
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let chain_id = ChainId::from_bytes(&chain_id_bytes);

        // Pre-initialize watermarks at level 100
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 100);

        // Track if callback was triggered
        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = Arc::clone(&callback_triggered);

        // With blocks_per_cycle=100, threshold = 4 * 100 = 400 blocks
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(vec![0x11, 0x12, 0x13]),
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
                ServerError::Watermark(crate::high_watermark::WatermarkError::LargeLevelGap { .. })
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
        let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let hwm = Arc::new(RwLock::new(HighWatermark::new(temp_dir.path()).unwrap()));

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let chain_id = ChainId::from_bytes(&chain_id_bytes);

        // Pre-initialize watermarks at level 100
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 100);

        // With blocks_per_cycle=100, threshold = 4 * 100 = 400 blocks
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(vec![0x11, 0x12, 0x13]),
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
    fn test_zero_blocks_per_cycle_does_not_panic() {
        // Test that blocks_per_cycle = 0 doesn't cause division by zero
        // The gap detection should be skipped when blocks_per_cycle is 0
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

        let mut mgr = KeyManager::new();
        mgr.add_signer(pkh, signer, "test_key".to_string());

        let hwm = Arc::new(RwLock::new(HighWatermark::new(temp_dir.path()).unwrap()));

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
        let chain_id = ChainId::from_bytes(&chain_id_bytes);

        // Pre-initialize watermarks at level 100
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 100);

        // Track if callback was triggered (it should NOT be triggered with blocks_per_cycle=0)
        let callback_triggered = Arc::new(AtomicBool::new(false));
        let callback_triggered_clone = Arc::clone(&callback_triggered);

        // With blocks_per_cycle=0, gap detection should be SKIPPED entirely
        let handler = RequestHandler::new(
            Arc::new(RwLock::new(mgr)),
            Some(Arc::clone(&hwm)),
            Some(vec![0x11, 0x12, 0x13]),
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
}
