//! High watermark tracking for double-signing prevention
//!
//! This module implements high watermark protection to prevent signing
//! multiple blocks or attestations at the same level/round, which would
//! constitute double-signing (slashable offense in Tenderbake consensus).
//!
//! Corresponds to: src/bin_signer/handler.ml:27-232

use crate::bls::PublicKeyHash;
use crate::magic_bytes::{
    get_level_and_round_for_tenderbake_attestation, get_level_and_round_for_tenderbake_block,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Maximum entries in watermark cache before LRU eviction kicks in.
/// Normal operation uses 1-3 entries (one per key). 100 covers any legitimate setup.
/// Each entry is ~500 bytes, so 100 entries ≈ 50KB memory.
const MAX_CACHE_ENTRIES: usize = 100;

/// Maximum watermark file size (64KB). Normal files are 1-2KB.
/// Rejects maliciously large files that could cause OOM.
const MAX_WATERMARK_FILE_SIZE: u64 = 64 * 1024;

/// Chain identifier (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId([u8; 32]);

impl ChainId {
    /// Create from bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Convert to bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Base58check encoding with "Net" prefix (for OCaml compatibility)
    #[must_use]
    pub fn to_b58check(self) -> String {
        // Chain ID prefix: [87, 82, 0] = "Net"
        let mut prefixed = vec![87, 82, 0];
        prefixed.extend_from_slice(&self.0[..4]); // Chain IDs are 4 bytes
        bs58::encode(&prefixed).with_check().into_string()
    }
}

/// Operation watermark entry (OCaml-compatible format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationWatermark {
    /// Level of the operation
    pub level: u32,
    /// Round of the operation
    pub round: u32,
    /// Hash of the signed data (hex string)
    pub hash: String,
    /// Signature (base58check encoded)
    pub signature: String,
}

/// Watermark tracking data for a specific key
#[derive(Debug, Clone, Default)]
pub struct Watermark {
    /// Last signed block
    pub block: Option<OperationWatermark>,
    /// Last signed preattestation
    pub preattest: Option<OperationWatermark>,
    /// Last signed attestation
    pub attest: Option<OperationWatermark>,
}

/// Type of consensus operation (for watermark tracking)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationType {
    Block,
    Preattestation,
    Attestation,
}

impl OperationType {
    /// Convert from magic byte to operation type
    fn from_magic_byte(magic: u8) -> Option<Self> {
        match magic {
            0x11 => Some(Self::Block),
            0x12 => Some(Self::Preattestation),
            0x13 => Some(Self::Attestation),
            _ => None,
        }
    }
}

impl Watermark {
    /// Check if any operation has been signed (has non-empty signature)
    ///
    /// Used during LRU eviction to skip saving entries that were only probed
    /// but never actually signed (e.g., attack traffic).
    #[must_use]
    pub fn has_any_signature(&self) -> bool {
        let has_sig =
            |op: &Option<OperationWatermark>| op.as_ref().is_some_and(|w| !w.signature.is_empty());
        has_sig(&self.block) || has_sig(&self.preattest) || has_sig(&self.attest)
    }

    /// Get watermark for operation type
    fn get(&self, op_type: OperationType) -> Option<&OperationWatermark> {
        match op_type {
            OperationType::Block => self.block.as_ref(),
            OperationType::Preattestation => self.preattest.as_ref(),
            OperationType::Attestation => self.attest.as_ref(),
        }
    }

    /// Set watermark for operation type
    fn set(&mut self, op_type: OperationType, wm: OperationWatermark) {
        match op_type {
            OperationType::Block => self.block = Some(wm),
            OperationType::Preattestation => self.preattest = Some(wm),
            OperationType::Attestation => self.attest = Some(wm),
        }
    }

    /// Get mutable reference to watermark for operation type
    fn get_mut(&mut self, op_type: OperationType) -> Option<&mut OperationWatermark> {
        match op_type {
            OperationType::Block => self.block.as_mut(),
            OperationType::Preattestation => self.preattest.as_mut(),
            OperationType::Attestation => self.attest.as_mut(),
        }
    }
}

/// High watermark error
#[derive(Debug, thiserror::Error)]
pub enum WatermarkError {
    /// Level is below the high watermark
    #[error("Level too low: requested {requested}, current high watermark {current}")]
    LevelTooLow {
        /// Current high watermark level
        current: u32,
        /// Requested signing level
        requested: u32,
    },

    /// Round is below the high watermark at same level
    #[error(
        "Round too low at level {level}: requested {requested}, current high watermark {current}"
    )]
    RoundTooLow {
        /// Level at which round check failed
        level: u32,
        /// Current high watermark round
        current: u32,
        /// Requested signing round
        requested: u32,
    },

    /// Invalid data format
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Internal error (e.g., lock poisoning)
    #[error("Internal error: {0}")]
    Internal(String),

    /// Watermark not initialized - first signature without pre-configuration
    #[error(
        "Watermark not initialized for chain {chain_id}, key {pkh}. Configure watermarks before signing."
    )]
    NotInitialized {
        /// Chain ID (base58 encoded)
        chain_id: String,
        /// Public key hash (base58 encoded)
        pkh: String,
    },

    /// Large level gap detected - watermark may be stale
    #[error(
        "Large level gap: {gap} blocks (~{cycles} cycles). Current: {current_level}, requested: {requested_level}"
    )]
    LargeLevelGap {
        /// Current watermark level
        current_level: u32,
        /// Requested signing level
        requested_level: u32,
        /// Gap in blocks
        gap: u32,
        /// Approximate cycles (for display)
        cycles: u32,
    },
}

/// Result type for high watermark operations
pub type Result<T> = std::result::Result<T, WatermarkError>;

/// High watermark tracker
///
/// Prevents double-signing by tracking the highest level/round signed
/// for each operation type (block, preattestation, attestation).
///
/// Uses LRU eviction to bound memory usage on resource-constrained devices.
///
/// Corresponds to: src/bin_signer/handler.ml:27-232
pub struct HighWatermark {
    /// Storage directory
    base_dir: PathBuf,
    /// In-memory cache of watermarks per (`chain_id`, `pkh`)
    cache: Arc<RwLock<HashMap<(ChainId, PublicKeyHash), Watermark>>>,
    /// LRU order tracking (most recently used at back)
    lru_order: Arc<RwLock<VecDeque<(ChainId, PublicKeyHash)>>>,
}

impl HighWatermark {
    /// Create new high watermark tracker
    pub fn new<P: AsRef<Path>>(base_dir: P) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;

        Ok(Self {
            base_dir,
            cache: Arc::new(RwLock::new(HashMap::new())),
            lru_order: Arc::new(RwLock::new(VecDeque::new())),
        })
    }

    /// Check if data can be signed and update watermark if allowed
    ///
    /// Returns Ok(()) if signing is allowed, Err if it would constitute double-signing.
    pub fn check_and_update(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        data: &[u8],
    ) -> Result<()> {
        if data.is_empty() {
            return Err(WatermarkError::InvalidData("Empty data".to_string()));
        }

        let magic_byte = data[0];

        match magic_byte {
            0x11 => self.check_and_update_block(chain_id, pkh, data),
            0x12 => self.check_and_update_preattestation(chain_id, pkh, data),
            0x13 => self.check_and_update_attestation(chain_id, pkh, data),
            _ => Ok(()), // No watermark for other operation types
        }
    }

    /// Get the current watermark level for a key
    ///
    /// Returns the highest level from any of the three operation types (block,
    /// preattestation, attestation). Returns None if no watermark exists.
    #[must_use]
    pub fn get_current_level(&self, chain_id: ChainId, pkh: &PublicKeyHash) -> Option<u32> {
        let key = (chain_id, *pkh);

        // Extract max level from a watermark's three operation types
        let max_level_from = |wm: &Watermark| {
            [
                wm.block.as_ref().map(|w| w.level),
                wm.preattest.as_ref().map(|w| w.level),
                wm.attest.as_ref().map(|w| w.level),
            ]
            .into_iter()
            .flatten()
            .max()
        };

        // First try the cache
        if let Ok(cache) = self.cache.read()
            && let Some(wm) = cache.get(&key)
            && let Some(level) = max_level_from(wm)
        {
            return Some(level);
        }

        // Not in cache, try loading from disk
        if let Ok(wm) = self.load_watermark(chain_id, pkh)
            && let Some(level) = max_level_from(&wm)
        {
            return Some(level);
        }

        None
    }

    /// Update the signature field after signing
    ///
    /// This should be called after successful signing to record what signature
    /// was produced for the watermarked operation.
    pub fn update_signature(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        data: &[u8],
        signature: &crate::bls::Signature,
    ) -> Result<()> {
        if data.is_empty() {
            return Err(WatermarkError::InvalidData("Empty data".to_string()));
        }

        let magic_byte = data[0];
        let signature_b58 = signature.to_b58check();

        let key = (chain_id, *pkh);
        let mut cache = self
            .cache
            .write()
            .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;

        if let Some(wm) = cache.get_mut(&key)
            && let Some(op_type) = OperationType::from_magic_byte(magic_byte)
            && let Some(wm_entry) = wm.get_mut(op_type)
        {
            wm_entry.signature = signature_b58;
        }
        // Note: Disk write deferred until after TCP response (call flush_to_disk)

        Ok(())
    }

    /// Flush watermark to disk (call after TCP write completes)
    ///
    /// This writes the in-memory watermark state to disk. Should be called
    /// after successfully sending the response to the client.
    pub fn flush_to_disk(&self, chain_id: ChainId, pkh: &PublicKeyHash) -> Result<()> {
        self.save_watermark(chain_id, pkh)
    }

    /// Flush all cached watermarks to disk (call on shutdown)
    ///
    /// Ensures all in-memory watermark state is persisted before exit.
    pub fn flush_all(&self) -> Result<()> {
        let cache = self
            .cache
            .read()
            .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;

        for ((chain_id, pkh), _wm) in cache.iter() {
            // Ignore individual flush errors - log and continue
            if let Err(e) = self.save_watermark(*chain_id, pkh) {
                eprintln!(
                    "⚠️  WARNING: Failed to flush watermark for {}: {}",
                    pkh.to_b58check(),
                    e
                );
            }
        }

        Ok(())
    }

    /// Check and update block watermark
    fn check_and_update_block(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        data: &[u8],
    ) -> Result<()> {
        let (level, round) = get_level_and_round_for_tenderbake_block(data)
            .map_err(|e| WatermarkError::InvalidData(e.to_string()))?;
        self.check_and_update_operation(chain_id, pkh, data, level, round, OperationType::Block)
    }

    /// Check and update preattestation watermark
    fn check_and_update_preattestation(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        data: &[u8],
    ) -> Result<()> {
        let (level, round) = get_level_and_round_for_tenderbake_attestation(data, true)
            .map_err(|e| WatermarkError::InvalidData(e.to_string()))?;
        self.check_and_update_operation(
            chain_id,
            pkh,
            data,
            level,
            round,
            OperationType::Preattestation,
        )
    }

    /// Check and update attestation watermark
    fn check_and_update_attestation(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        data: &[u8],
    ) -> Result<()> {
        let (level, round) = get_level_and_round_for_tenderbake_attestation(data, true)
            .map_err(|e| WatermarkError::InvalidData(e.to_string()))?;
        self.check_and_update_operation(
            chain_id,
            pkh,
            data,
            level,
            round,
            OperationType::Attestation,
        )
    }

    /// Unified watermark check and update for all operation types
    fn check_and_update_operation(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        data: &[u8],
        level: u32,
        round: u32,
        op_type: OperationType,
    ) -> Result<()> {
        // Load watermark from disk on first access, or get from cache
        let _wm_loaded = self.get_or_load_watermark(chain_id, pkh)?;

        let key = (chain_id, *pkh);
        let mut cache = self
            .cache
            .write()
            .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;

        // Get mutable reference to watermark (will exist since we just loaded/created it)
        let wm = cache.get_mut(&key).ok_or_else(|| {
            WatermarkError::Internal("Watermark missing from cache after load".to_string())
        })?;

        // Check watermark exists (must be pre-configured before first signature)
        let Some(current_wm) = wm.get(op_type) else {
            return Err(WatermarkError::NotInitialized {
                chain_id: chain_id.to_b58check(),
                pkh: pkh.to_b58check(),
            });
        };

        // Check if level is too low
        if level < current_wm.level {
            return Err(WatermarkError::LevelTooLow {
                current: current_wm.level,
                requested: level,
            });
        }

        // If same level, round must be strictly higher to allow signing
        if level == current_wm.level && round <= current_wm.round {
            return Err(WatermarkError::RoundTooLow {
                level,
                current: current_wm.round,
                requested: round,
            });
        }

        // Update watermark with new operation (in-memory only)
        wm.set(
            op_type,
            OperationWatermark {
                level,
                round,
                hash: hex::encode(data),
                signature: String::new(), // Will be updated after signing
            },
        );

        // Note: Disk write deferred until after TCP response (call flush_to_disk)
        Ok(())
    }

    /// Save watermark to disk (OCaml-compatible format)
    fn save_watermark(&self, chain_id: ChainId, pkh: &PublicKeyHash) -> Result<()> {
        let key = (chain_id, *pkh);
        let cache = self
            .cache
            .read()
            .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;

        if let Some(wm) = cache.get(&key) {
            let chain_id_b58 = chain_id.to_b58check();
            let pkh_b58 = pkh.to_b58check();

            // Save block watermark (OCaml uses singular "watermark")
            if let Some(ref block_wm) = wm.block {
                self.save_operation_watermark(
                    "block_high_watermark",
                    &chain_id_b58,
                    &pkh_b58,
                    block_wm,
                )?;
            }

            // Save preattestation watermark
            if let Some(ref preattest_wm) = wm.preattest {
                self.save_operation_watermark(
                    "preattestation_high_watermark",
                    &chain_id_b58,
                    &pkh_b58,
                    preattest_wm,
                )?;
            }

            // Save attestation watermark
            if let Some(ref attest_wm) = wm.attest {
                self.save_operation_watermark(
                    "attestation_high_watermark",
                    &chain_id_b58,
                    &pkh_b58,
                    attest_wm,
                )?;
            }
        }

        Ok(())
    }

    /// Save a single operation watermark to its file
    fn save_operation_watermark(
        &self,
        filename: &str,
        chain_id: &str,
        pkh: &str,
        wm: &OperationWatermark,
    ) -> Result<()> {
        let path = self.base_dir.join(filename);

        // Load existing data or create new structure
        let mut data: serde_json::Value = if path.exists() {
            // Check file size before reading
            let meta = fs::metadata(&path)?;
            if meta.len() > MAX_WATERMARK_FILE_SIZE {
                eprintln!(
                    "⚠️  Watermark file {} too large ({} bytes), reinitializing",
                    path.display(),
                    meta.len()
                );
                serde_json::json!({})
            } else {
                let contents = fs::read_to_string(&path)?;
                // Handle empty or invalid JSON files gracefully
                if contents.trim().is_empty() {
                    serde_json::json!({})
                } else if let Ok(d) = serde_json::from_str(&contents) {
                    d
                } else {
                    // File contains invalid JSON - start fresh
                    eprintln!(
                        "⚠️  Reinitializing corrupted watermark file: {}",
                        path.display()
                    );
                    serde_json::json!({})
                }
            }
        } else {
            serde_json::json!({})
        };

        // Ensure chain_id exists
        if !data.is_object() {
            data = serde_json::json!({});
        }

        let obj = data.as_object_mut().unwrap();
        if !obj.contains_key(chain_id) {
            obj.insert(chain_id.to_string(), serde_json::json!({}));
        }

        // Update the watermark for this pkh
        obj.get_mut(chain_id)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(pkh.to_string(), serde_json::to_value(wm)?);

        // Write back to file
        let json = serde_json::to_string_pretty(&data)?;
        fs::write(path, json)?;

        Ok(())
    }

    /// Load watermark from disk (OCaml-compatible format)
    ///
    /// Handles missing, empty, and corrupt files gracefully.
    pub fn load_watermark(&self, chain_id: ChainId, pkh: &PublicKeyHash) -> Result<Watermark> {
        let chain_id_b58 = chain_id.to_b58check();
        let pkh_b58 = pkh.to_b58check();

        // Load all watermarks and construct struct directly
        // Errors are handled gracefully in load_operation_watermark
        // Note: OCaml uses singular "watermark", not "watermarks"
        let wm = Watermark {
            block: self.load_operation_watermark("block_high_watermark", &chain_id_b58, &pkh_b58),
            preattest: self.load_operation_watermark(
                "preattestation_high_watermark",
                &chain_id_b58,
                &pkh_b58,
            ),
            attest: self.load_operation_watermark(
                "attestation_high_watermark",
                &chain_id_b58,
                &pkh_b58,
            ),
        };

        Ok(wm)
    }

    /// Get or load watermark from cache
    ///
    /// Loads from disk on first access, returns cached value on subsequent access.
    /// Uses LRU eviction when cache exceeds `MAX_CACHE_ENTRIES`.
    fn get_or_load_watermark(&self, chain_id: ChainId, pkh: &PublicKeyHash) -> Result<Watermark> {
        let key = (chain_id, *pkh);

        // Try to get from cache first
        {
            let cache = self
                .cache
                .read()
                .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;
            if let Some(wm) = cache.get(&key) {
                // Update LRU order (move to back = most recently used)
                if let Ok(mut lru) = self.lru_order.write() {
                    if let Some(pos) = lru.iter().position(|k| *k == key) {
                        lru.remove(pos);
                    }
                    lru.push_back(key);
                }
                return Ok(wm.clone());
            }
        }

        // Not in cache - load from disk (or create empty if files don't exist/are corrupt)
        let wm = self.load_watermark(chain_id, pkh).unwrap_or_default();

        // Update cache with LRU eviction
        let mut cache = self
            .cache
            .write()
            .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;

        // Evict oldest entries if cache is full
        if cache.len() >= MAX_CACHE_ENTRIES {
            let mut lru = self
                .lru_order
                .write()
                .map_err(|e| WatermarkError::Internal(format!("LRU lock poisoned: {e}")))?;

            while cache.len() >= MAX_CACHE_ENTRIES {
                if let Some(old_key) = lru.pop_front() {
                    // Only save if entry was actually signed (has non-empty signature)
                    // This prevents attack traffic from causing disk I/O storms
                    if let Some(wm) = cache.get(&old_key)
                        && wm.has_any_signature()
                        && let Err(e) = self.save_watermark(old_key.0, &old_key.1)
                    {
                        eprintln!("⚠️  Failed to flush evicted watermark: {e}");
                    }
                    // else: entry was never signed, just drop it (attack probe)
                    cache.remove(&old_key);
                } else {
                    break; // LRU empty, shouldn't happen
                }
            }
        }

        cache.insert(key, wm.clone());

        // Add to LRU order
        if let Ok(mut lru) = self.lru_order.write() {
            lru.push_back(key);
        }

        Ok(wm)
    }

    /// Load a single operation watermark from its file
    ///
    /// Handles missing, empty, and corrupt files gracefully by returning None.
    /// Rejects files larger than `MAX_WATERMARK_FILE_SIZE` to prevent OOM.
    fn load_operation_watermark(
        &self,
        filename: &str,
        chain_id: &str,
        pkh: &str,
    ) -> Option<OperationWatermark> {
        let path = self.base_dir.join(filename);

        // Missing file is OK - return empty watermark
        if !path.exists() {
            return None;
        }

        // Check file size before reading to prevent OOM from malicious files
        match fs::metadata(&path) {
            Ok(meta) if meta.len() > MAX_WATERMARK_FILE_SIZE => {
                eprintln!(
                    "⚠️  WARNING: Watermark file {} is too large ({} bytes, max {})",
                    path.display(),
                    meta.len(),
                    MAX_WATERMARK_FILE_SIZE
                );
                eprintln!("   Refusing to load - possible attack or corruption");
                return None;
            }
            Err(e) => {
                eprintln!(
                    "⚠️  WARNING: Cannot stat watermark file {}: {}",
                    path.display(),
                    e
                );
                return None;
            }
            _ => {} // Size OK, continue
        }

        // Read file contents, handle errors gracefully
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "⚠️  WARNING: Failed to read watermark file {}: {}",
                    path.display(),
                    e
                );
                eprintln!("   Continuing with empty watermark for this operation type");
                return None;
            }
        };

        // Empty file is OK - return empty watermark
        if contents.trim().is_empty() {
            eprintln!("⚠️  WARNING: Watermark file {} is empty", path.display());
            eprintln!("   Continuing with empty watermark for this operation type");
            return None;
        }

        // Parse JSON, handle corrupt files gracefully
        let data: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "⚠️  WARNING: Watermark file {} contains invalid JSON: {}",
                    path.display(),
                    e
                );
                eprintln!("   Continuing with empty watermark for this operation type");
                return None;
            }
        };

        // Navigate to chain_id -> pkh
        if let Some(chain_obj) = data.get(chain_id)
            && let Some(wm_value) = chain_obj.get(pkh)
        {
            match serde_json::from_value(wm_value.clone()) {
                Ok(wm) => return Some(wm),
                Err(e) => {
                    eprintln!(
                        "⚠️  WARNING: Watermark entry for chain {} / {} in {} is invalid: {}",
                        chain_id,
                        pkh,
                        path.display(),
                        e
                    );
                    eprintln!("   Continuing with empty watermark for this operation type");
                    return None;
                }
            }
        }

        None
    }

    /// Get current watermark levels for display purposes
    ///
    /// Returns (`block_level`, `preattest_level`, `attest_level`) from the cache.
    ///
    /// # Errors
    /// Returns error if cache is not accessible or watermarks are not initialized.
    pub fn get_current_levels(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
    ) -> Result<(u32, u32, u32)> {
        let key = (chain_id, *pkh);

        let cache = self
            .cache
            .read()
            .map_err(|_| WatermarkError::Internal("Cache lock poisoned".to_string()))?;

        let wm = cache
            .get(&key)
            .ok_or_else(|| WatermarkError::NotInitialized {
                chain_id: chain_id.to_b58check(),
                pkh: pkh.to_b58check(),
            })?;

        let block = wm
            .block
            .as_ref()
            .ok_or_else(|| WatermarkError::Internal("Block watermark not set".to_string()))?
            .level;
        let preattest = wm
            .preattest
            .as_ref()
            .ok_or_else(|| WatermarkError::Internal("Preattest watermark not set".to_string()))?
            .level;
        let attest = wm
            .attest
            .as_ref()
            .ok_or_else(|| WatermarkError::Internal("Attest watermark not set".to_string()))?
            .level;

        Ok((block, preattest, attest))
    }

    /// Update watermark to a specific level
    ///
    /// This is used when a large level gap is detected and the user confirms
    /// updating to the new level. Sets all three operation types (block,
    /// preattestation, attestation) to the specified level with round 0.
    pub fn update_to_level(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        level: u32,
    ) -> Result<()> {
        let key = (chain_id, *pkh);
        let mut cache = self
            .cache
            .write()
            .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;

        // Create new watermark at the specified level
        let new_wm = OperationWatermark {
            level,
            round: 0,
            hash: String::new(),
            signature: String::new(),
        };

        // Update cache for all operation types
        let wm = cache.entry(key).or_default();
        wm.block = Some(new_wm.clone());
        wm.preattest = Some(new_wm.clone());
        wm.attest = Some(new_wm);

        // Update LRU order
        drop(cache); // Release cache lock before acquiring lru_order lock
        {
            let mut lru = self
                .lru_order
                .write()
                .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;
            lru.retain(|k| k != &key);
            lru.push_back(key);
        }

        // Persist to disk
        self.save_watermark(chain_id, pkh)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::generate_key;
    use crate::test_utils::{create_block_data, default_test_chain_id, preinit_watermarks};
    use tempfile::TempDir;

    fn create_test_chain_id() -> ChainId {
        default_test_chain_id()
    }

    #[test]
    fn test_allow_signing_at_higher_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Pre-initialize watermark at level 99
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();

        // Sign at level 100
        let data1 = create_block_data(100, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        // Sign at level 101 should succeed
        let data2 = create_block_data(101, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data2).is_ok());
    }

    #[test]
    fn test_reject_signing_at_lower_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Pre-initialize watermark at level 99
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();

        // Sign at level 100
        let data1 = create_block_data(100, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        // Sign at level 99 should fail
        let data2 = create_block_data(99, 0);
        let result = hwm.check_and_update(chain_id, &pkh, &data2);
        assert!(matches!(result, Err(WatermarkError::LevelTooLow { .. })));
    }

    #[test]
    fn test_allow_signing_at_higher_round_same_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Pre-initialize watermark at level 99
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();

        // Sign at level 100, round 5
        let data1 = create_block_data(100, 5);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        // Sign at level 100, round 6 should succeed
        let data2 = create_block_data(100, 6);
        assert!(hwm.check_and_update(chain_id, &pkh, &data2).is_ok());
    }

    #[test]
    fn test_reject_signing_at_lower_round_same_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Pre-initialize watermark at level 99
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();

        // Sign at level 100, round 5
        let data1 = create_block_data(100, 5);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        // Sign at level 100, round 4 should fail
        let data2 = create_block_data(100, 4);
        let result = hwm.check_and_update(chain_id, &pkh, &data2);
        assert!(matches!(result, Err(WatermarkError::RoundTooLow { .. })));
    }

    #[test]
    fn test_reject_signing_at_same_round_same_level() {
        // This test ensures we can't double-sign at exactly the same (level, round)
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Pre-initialize watermark at level 99
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();

        // Sign at level 100, round 5
        let data1 = create_block_data(100, 5);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        // Attempt to sign AGAIN at level 100, round 5 should fail (double-signing prevention)
        let data2 = create_block_data(100, 5);
        let result = hwm.check_and_update(chain_id, &pkh, &data2);
        assert!(
            matches!(result, Err(WatermarkError::RoundTooLow { .. })),
            "Should reject signing at same level and same round (double-signing)"
        );
    }

    #[test]
    fn test_persistence_across_instances() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Pre-initialize watermark at level 99
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);

        // First instance: sign at level 100
        {
            let hwm = HighWatermark::new(temp_dir.path()).unwrap();
            let data = create_block_data(100, 5);
            assert!(hwm.check_and_update(chain_id, &pkh, &data).is_ok());
            // Manually flush to disk to simulate server behavior
            hwm.flush_to_disk(chain_id, &pkh).unwrap();
        }

        // Second instance: load from disk and verify watermark
        {
            let hwm = HighWatermark::new(temp_dir.path()).unwrap();
            let loaded = hwm.load_watermark(chain_id, &pkh).unwrap();
            assert!(loaded.block.is_some());
            assert_eq!(loaded.block.as_ref().unwrap().level, 100);
            assert_eq!(loaded.block.as_ref().unwrap().round, 5);

            // Try to sign at level 99 should fail
            let data = create_block_data(99, 0);
            let result = hwm.check_and_update(chain_id, &pkh, &data);
            assert!(matches!(result, Err(WatermarkError::LevelTooLow { .. })));
        }
    }

    #[test]
    fn test_different_keys_have_separate_watermarks() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();

        let seed1 = [1u8; 32];
        let (pkh1, _pk1, _sk1) = generate_key(Some(&seed1)).unwrap();

        let seed2 = [2u8; 32];
        let (pkh2, _pk2, _sk2) = generate_key(Some(&seed2)).unwrap();

        // Pre-initialize watermarks for both keys at different levels
        preinit_watermarks(temp_dir.path(), chain_id, &pkh1, 99);
        preinit_watermarks(temp_dir.path(), chain_id, &pkh2, 49);
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();

        // Sign with key1 at level 100
        let data1 = create_block_data(100, 0);
        assert!(hwm.check_and_update(chain_id, &pkh1, &data1).is_ok());

        // Sign with key2 at level 50 should succeed (different key)
        let data2 = create_block_data(50, 0);
        assert!(hwm.check_and_update(chain_id, &pkh2, &data2).is_ok());
    }

    #[test]
    fn test_reject_first_signature_without_initialization() {
        // Test that signing without pre-initialized watermarks is rejected
        let temp_dir = TempDir::new().unwrap();
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Attempt to sign without pre-initialization should fail
        let data = create_block_data(100, 0);
        let result = hwm.check_and_update(chain_id, &pkh, &data);
        assert!(
            matches!(result, Err(WatermarkError::NotInitialized { .. })),
            "Should reject signing without pre-initialized watermark"
        );
    }

    #[test]
    fn test_watermark_get_mut_block() {
        let mut wm = Watermark::default();
        wm.set(
            OperationType::Block,
            OperationWatermark {
                level: 100,
                round: 0,
                hash: String::new(),
                signature: String::new(),
            },
        );

        let block_wm = wm.get_mut(OperationType::Block).unwrap();
        block_wm.signature = "test_sig".to_string();

        assert_eq!(wm.block.as_ref().unwrap().signature, "test_sig");
    }

    #[test]
    fn test_watermark_get_mut_returns_none_when_empty() {
        let mut wm = Watermark::default();
        assert!(wm.get_mut(OperationType::Block).is_none());
        assert!(wm.get_mut(OperationType::Preattestation).is_none());
        assert!(wm.get_mut(OperationType::Attestation).is_none());
    }

    #[test]
    fn test_operation_type_from_magic_byte() {
        assert_eq!(
            OperationType::from_magic_byte(0x11),
            Some(OperationType::Block)
        );
        assert_eq!(
            OperationType::from_magic_byte(0x12),
            Some(OperationType::Preattestation)
        );
        assert_eq!(
            OperationType::from_magic_byte(0x13),
            Some(OperationType::Attestation)
        );
        assert_eq!(OperationType::from_magic_byte(0x14), None);
        assert_eq!(OperationType::from_magic_byte(0x00), None);
    }

    /// Test that watermark JSON files have the expected OCaml-compatible schema.
    ///
    /// Structure: { chain_id: { pkh: { level, round, hash, signature } } }
    #[test]
    fn test_watermark_json_schema() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [77u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Pre-initialize and sign to create watermark file
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();

        let data = create_block_data(100, 5);
        hwm.check_and_update(chain_id, &pkh, &data).unwrap();
        hwm.flush_to_disk(chain_id, &pkh).unwrap();

        // Read and parse the JSON file directly
        let wm_path = temp_dir.path().join("block_high_watermark");
        let contents = std::fs::read_to_string(&wm_path).expect("Should read watermark file");
        let json: serde_json::Value =
            serde_json::from_str(&contents).expect("Should parse as JSON");

        // Verify top-level structure: { chain_id: { pkh: { ... } } }
        assert!(json.is_object(), "Root must be an object");

        let chain_id_b58 = chain_id.to_b58check();
        let chain_obj = json
            .get(&chain_id_b58)
            .expect("Chain ID key must exist")
            .as_object()
            .expect("Chain value must be an object");

        let pkh_b58 = pkh.to_b58check();
        let wm_obj = chain_obj
            .get(&pkh_b58)
            .expect("PKH key must exist")
            .as_object()
            .expect("Watermark value must be an object");

        // Verify exact field names and types (OCaml compatibility)
        assert!(
            wm_obj.get("level").unwrap().is_u64(),
            "level must be an integer"
        );
        assert!(
            wm_obj.get("round").unwrap().is_u64(),
            "round must be an integer"
        );
        assert!(
            wm_obj.get("hash").unwrap().is_string(),
            "hash must be a string"
        );
        assert!(
            wm_obj.get("signature").unwrap().is_string(),
            "signature must be a string"
        );

        // Verify no extra fields
        assert_eq!(
            wm_obj.len(),
            4,
            "Watermark must have exactly 4 fields: level, round, hash, signature"
        );

        // Verify values
        assert_eq!(wm_obj.get("level").unwrap().as_u64().unwrap(), 100);
        assert_eq!(wm_obj.get("round").unwrap().as_u64().unwrap(), 5);
        assert!(
            !wm_obj.get("hash").unwrap().as_str().unwrap().is_empty(),
            "hash should contain hex-encoded data"
        );
    }
}
