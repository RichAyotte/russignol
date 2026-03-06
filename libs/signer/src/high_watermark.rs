//! High watermark tracking for double-signing prevention
//!
//! This module implements high watermark protection to prevent signing
//! multiple blocks or attestations at the same level/round, which would
//! constitute double-signing (slashable offense in Tenderbake consensus).
//!
//! Watermarks are stored as 40-byte binary files (level + round + Blake3)
//! and fdatasynced to disk before any signature is returned. Each operation
//! type has a best-effort `.prev` backup for crash recovery.
//!
//! Watermarks are tracked per-key, so each public key hash has independent
//! watermark state. This supports companion key signing (DAL) where both
//! the consensus key and companion key sign at the same level/round.
//!
//! Corresponds to: src/bin_signer/handler.ml:27-232

use crate::bls::PublicKeyHash;
use crate::magic_bytes::{
    get_level_and_round_for_tenderbake_attestation, get_level_and_round_for_tenderbake_block,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use russignol_storage::watermark::{FILE_SIZE as WATERMARK_FILE_SIZE, FILENAMES};

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

/// Watermark entry: level + round
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatermarkEntry {
    /// Block level
    pub level: u32,
    /// Consensus round
    pub round: u32,
}

/// Type of consensus operation (for watermark tracking)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// Block proposal (magic byte 0x11)
    Block = 0,
    /// Preattestation (magic byte 0x12)
    Preattestation = 1,
    /// Attestation (magic byte 0x13)
    Attestation = 2,
}

impl OperationType {
    /// All operation types in index order
    const ALL: [Self; 3] = [Self::Block, Self::Preattestation, Self::Attestation];

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

/// Per-key watermark state: file handles and in-memory cache
struct PerKeyWatermark {
    /// Primary file handles, indexed by `OperationType as usize`
    files: [File; 3],
    /// Backup (.prev) file handles, indexed by `OperationType as usize`
    prev_files: [File; 3],
    /// In-memory cache, indexed by `OperationType as usize`
    entries: [Option<WatermarkEntry>; 3],
    /// What ceiling entry is on stable storage, indexed by `OperationType as usize`.
    /// A ceiling `(level, u32::MAX)` on disk means any crash recovery loads this value,
    /// allowing fdatasync to be skipped for updates covered by the ceiling.
    disk_ceiling: [Option<WatermarkEntry>; 3],
}

/// Info needed to persist a watermark update to disk.
///
/// Returned from [`HighWatermark::check_and_update`] when the watermark was
/// advanced. Pass to [`HighWatermark::write_watermark`] to persist.
#[derive(Debug)]
pub struct WatermarkUpdate {
    pkh: PublicKeyHash,
    idx: usize,
    level: u32,
    round: u32,
    /// Previous entry for rollback if BLS signing fails
    prev: Option<WatermarkEntry>,
}

impl WatermarkUpdate {
    /// Public key hash this update applies to
    #[must_use]
    pub fn pkh(&self) -> PublicKeyHash {
        self.pkh
    }

    /// Operation type index (0=block, 1=preattestation, 2=attestation)
    #[must_use]
    pub fn idx(&self) -> usize {
        self.idx
    }

    /// Block level of this update
    #[must_use]
    pub fn level(&self) -> u32 {
        self.level
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
/// for each operation type (block, preattestation, attestation) per key.
///
/// Each key gets its own subdirectory under the base watermark directory,
/// named by its base58check encoding (e.g. `tz4HKYQnfQChmDt.../`).
///
/// Watermarks are stored as 40-byte binary files and fdatasynced before
/// any signature is returned. All file handles (primary and `.prev` backup)
/// are opened at construction so no path lookups occur at signing time.
///
/// Corresponds to: src/bin_signer/handler.ml:27-232
pub struct HighWatermark {
    base_dir: PathBuf,
    /// Set of PKHs this tracker is authorised to manage (fixed at construction).
    known_pkhs: HashSet<PublicKeyHash>,
    keys: HashMap<PublicKeyHash, PerKeyWatermark>,
}

impl HighWatermark {
    /// Create new high watermark tracker
    ///
    /// Loads existing per-key watermark state for the given public key hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if creating the base directory or loading watermark files fails.
    pub fn new<P: AsRef<Path>>(base_dir: P, pkhs: &[PublicKeyHash]) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;

        let mut keys = HashMap::new();
        for pkh in pkhs {
            let key_dir = base_dir.join(pkh.to_b58check());
            if key_dir.is_dir() {
                let per_key = load_per_key_watermark(&key_dir)?;
                keys.insert(*pkh, per_key);
            }
        }

        let known_pkhs: HashSet<PublicKeyHash> = pkhs.iter().copied().collect();
        Ok(Self {
            base_dir,
            known_pkhs,
            keys,
        })
    }

    /// Ensure a per-key watermark entry exists, creating its subdirectory if needed.
    ///
    /// Only PKHs passed at construction are allowed; unknown keys return `NotInitialized`.
    fn ensure_key(&mut self, pkh: &PublicKeyHash) -> Result<()> {
        if self.keys.contains_key(pkh) {
            return Ok(());
        }
        if !self.known_pkhs.contains(pkh) {
            return Err(WatermarkError::NotInitialized {
                chain_id: String::new(),
                pkh: pkh.to_b58check(),
            });
        }
        let key_dir = self.base_dir.join(pkh.to_b58check());
        fs::create_dir_all(&key_dir)?;
        let per_key = load_per_key_watermark(&key_dir)?;
        self.keys.insert(*pkh, per_key);
        Ok(())
    }

    /// Check if data can be signed and update in-memory watermark if allowed.
    ///
    /// Returns `Ok(Some(update))` with a [`WatermarkUpdate`] that must be passed
    /// to [`write_watermark`](Self::write_watermark) before returning the signature.
    /// Returns `Ok(None)` for non-watermarked operations (magic byte not 0x11/0x12/0x13).
    ///
    /// # Panics
    ///
    /// Cannot panic: `ensure_key()` guarantees the key exists before the `.unwrap()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is invalid, the key is not initialized, or signing
    /// would violate the high watermark (double-signing protection).
    pub fn check_and_update(
        &mut self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        data: &[u8],
    ) -> Result<Option<WatermarkUpdate>> {
        if data.is_empty() {
            return Err(WatermarkError::InvalidData("Empty data".to_string()));
        }

        let magic_byte = data[0];
        let Some(op_type) = OperationType::from_magic_byte(magic_byte) else {
            return Ok(None); // No watermark for other operation types
        };

        let (level, round) = match magic_byte {
            0x11 => get_level_and_round_for_tenderbake_block(data)
                .map_err(|e| WatermarkError::InvalidData(e.to_string()))?,
            0x12 | 0x13 => get_level_and_round_for_tenderbake_attestation(data, true)
                .map_err(|e| WatermarkError::InvalidData(e.to_string()))?,
            _ => unreachable!(),
        };

        self.ensure_key(pkh)?;
        let per_key = self.keys.get_mut(pkh).unwrap();
        let idx = op_type as usize;

        // Check watermark exists (must be pre-configured before first signature)
        let Some(current) = per_key.entries[idx] else {
            return Err(WatermarkError::NotInitialized {
                chain_id: chain_id.to_b58check(),
                pkh: pkh.to_b58check(),
            });
        };

        // Check if level is too low
        if level < current.level {
            return Err(WatermarkError::LevelTooLow {
                current: current.level,
                requested: level,
            });
        }

        // If same level, round must be strictly higher to allow signing
        if level == current.level && round <= current.round {
            return Err(WatermarkError::RoundTooLow {
                level,
                current: current.round,
                requested: round,
            });
        }

        // Update in-memory cache (save previous for rollback)
        let prev = per_key.entries[idx];
        per_key.entries[idx] = Some(WatermarkEntry { level, round });

        Ok(Some(WatermarkUpdate {
            pkh: *pkh,
            idx,
            level,
            round,
            prev,
        }))
    }

    /// Get mutable reference to a key's watermark state.
    fn per_key_mut(&mut self, pkh: &PublicKeyHash) -> Result<&mut PerKeyWatermark> {
        self.keys
            .get_mut(pkh)
            .ok_or_else(|| WatermarkError::Internal(format!("Unknown key: {}", pkh.to_b58check())))
    }

    /// Roll back an in-memory watermark advance.
    ///
    /// Call this if BLS signing fails after [`check_and_update`](Self::check_and_update)
    /// succeeded, so the baker can retry at the same level.
    pub fn rollback_update(&mut self, update: &WatermarkUpdate) {
        if let Some(per_key) = self.keys.get_mut(&update.pkh) {
            per_key.entries[update.idx] = update.prev;
        }
    }

    /// Check if a ceiling on stable storage covers the given update.
    ///
    /// Returns `true` when the disk ceiling is at or above the update's level/round,
    /// meaning fdatasync can be safely skipped during [`write_watermark`](Self::write_watermark).
    #[must_use]
    pub fn ceiling_covers(&self, update: &WatermarkUpdate) -> bool {
        let Some(per_key) = self.keys.get(&update.pkh) else {
            return false;
        };
        per_key.disk_ceiling[update.idx].is_some_and(|c| {
            c.level > update.level || (c.level == update.level && c.round >= update.round)
        })
    }

    /// Write the previous watermark value back to disk after a BLS signing failure.
    ///
    /// Call this after [`rollback_update`](Self::rollback_update) when BLS signing
    /// fails but `write_watermark` already persisted the advanced value.
    /// Restores disk state to match the rolled-back in-memory state.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not initialized or disk I/O fails.
    pub fn rollback_disk_watermark(&mut self, update: &WatermarkUpdate) -> Result<()> {
        if let Some(prev) = update.prev {
            let per_key = self.per_key_mut(&update.pkh)?;
            let idx = update.idx;
            let buf = encode_entry(prev.level, prev.round);
            per_key.files[idx].write_all_at(&buf, 0)?;
            per_key.files[idx].sync_data()?;
            per_key.disk_ceiling[idx] = None;
        }
        Ok(())
    }

    /// Persist watermark to disk: `.prev` backup + pwrite + fdatasync.
    ///
    /// Only called when no ceiling covers the update (slow path).
    /// When a ceiling covers, the caller skips this entirely — no disk I/O
    /// in the signing critical path.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not initialized or disk I/O fails.
    pub fn write_watermark(&mut self, update: &WatermarkUpdate) -> Result<()> {
        let per_key = self.per_key_mut(&update.pkh)?;
        let idx = update.idx;

        // Best-effort copy previous value → .prev (no fsync, reaches disk via OS writeback)
        if let Some(prev) = update.prev {
            let prev_buf = encode_entry(prev.level, prev.round);
            let filename = FILENAMES[idx];
            if let Err(e) = per_key.prev_files[idx].write_all_at(&prev_buf, 0) {
                log::warn!("Failed to write {filename}.prev: {e}");
            }
        }

        // Build 40-byte buffer: level (4B BE) + round (4B BE) + blake3 (32B)
        let buf = encode_entry(update.level, update.round);

        // pwrite at offset 0 (no seek, no position change)
        per_key.files[idx].write_all_at(&buf, 0)?;

        // fdatasync — flushes data to stable storage (skips metadata since size is constant)
        per_key.files[idx].sync_data()?;
        // Actual value is now on stable storage; clear stale ceiling
        per_key.disk_ceiling[idx] = None;

        // Read-back verification in debug/test builds only
        #[cfg(debug_assertions)]
        {
            let filename = FILENAMES[idx];
            let readback = load_entry_from_file(&per_key.files[idx]).ok_or_else(|| {
                WatermarkError::Internal(format!(
                    "Read-back verification failed for {filename}: data on disk does not match expected watermark (level={}, round={})",
                    update.level, update.round
                ))
            })?;
            if readback.level != update.level || readback.round != update.round {
                return Err(WatermarkError::Internal(format!(
                    "Read-back mismatch for {filename}: expected level={}/round={}, got level={}/round={}",
                    update.level, update.round, readback.level, readback.round
                )));
            }
        }

        Ok(())
    }

    /// Write a ceiling watermark for the next expected level during idle time.
    ///
    /// Encodes `(ceiling_level, u32::MAX)` and fdatasyncs it to stable storage.
    /// On the next sign at `ceiling_level`, fdatasync can be skipped because
    /// any crash would load this ceiling value (which safely blocks that level).
    ///
    /// Skips the write if the watermark already advanced past `ceiling_level`
    /// or if an existing ceiling already covers it.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not initialized or disk I/O fails.
    pub fn write_ceiling(
        &mut self,
        pkh: PublicKeyHash,
        idx: usize,
        ceiling_level: u32,
    ) -> Result<()> {
        let per_key = self.per_key_mut(&pkh)?;

        // Skip if watermark already advanced to or past ceiling
        if per_key.entries[idx].is_some_and(|e| e.level >= ceiling_level) {
            return Ok(());
        }

        // Skip if existing ceiling already covers this level
        if per_key.disk_ceiling[idx].is_some_and(|c| c.level >= ceiling_level) {
            return Ok(());
        }

        let buf = encode_entry(ceiling_level, u32::MAX);
        per_key.files[idx].write_all_at(&buf, 0)?;
        per_key.files[idx].sync_data()?;
        per_key.disk_ceiling[idx] = Some(WatermarkEntry {
            level: ceiling_level,
            round: u32::MAX,
        });

        Ok(())
    }

    /// Get the current watermark level for a key.
    ///
    /// Returns the highest level from any of the three operation types.
    /// Returns None if no watermark exists.
    #[must_use]
    pub fn get_current_level(&self, _chain_id: ChainId, pkh: &PublicKeyHash) -> Option<u32> {
        self.keys
            .get(pkh)?
            .entries
            .iter()
            .filter_map(|e| e.map(|w| w.level))
            .max()
    }

    /// Get current watermark levels for display purposes.
    ///
    /// Returns (`block_level`, `preattest_level`, `attest_level`).
    ///
    /// # Errors
    ///
    /// Returns an error if the key has no watermark state initialized.
    pub fn get_current_levels(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
    ) -> Result<(u32, u32, u32)> {
        let per_key = self
            .keys
            .get(pkh)
            .ok_or_else(|| WatermarkError::NotInitialized {
                chain_id: chain_id.to_b58check(),
                pkh: pkh.to_b58check(),
            })?;
        let get = |idx: usize| -> Result<u32> {
            per_key.entries[idx]
                .map(|e| e.level)
                .ok_or_else(|| WatermarkError::NotInitialized {
                    chain_id: chain_id.to_b58check(),
                    pkh: pkh.to_b58check(),
                })
        };
        Ok((get(0)?, get(1)?, get(2)?))
    }

    /// Update all watermarks to a specific level (round 0).
    ///
    /// Used when a large level gap is detected and the user confirms the update.
    ///
    /// # Panics
    ///
    /// Cannot panic: `ensure_key()` guarantees the key exists before the `.unwrap()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not initialized or disk I/O fails.
    pub fn update_to_level(
        &mut self,
        _chain_id: ChainId,
        pkh: &PublicKeyHash,
        level: u32,
    ) -> Result<()> {
        self.ensure_key(pkh)?;
        let entry = WatermarkEntry { level, round: 0 };

        // Collect updates, then write (can't borrow self mutably and call write_watermark)
        let per_key = self.keys.get_mut(pkh).unwrap();
        let updates: Vec<WatermarkUpdate> = OperationType::ALL
            .iter()
            .enumerate()
            .map(|(i, op_type)| {
                let prev = per_key.entries[i];
                per_key.entries[i] = Some(entry);
                WatermarkUpdate {
                    pkh: *pkh,
                    idx: *op_type as usize,
                    level,
                    round: 0,
                    prev,
                }
            })
            .collect();

        for update in &updates {
            self.write_watermark(update)?;
        }
        Ok(())
    }

    /// Get entry for a specific key and operation type (test-only)
    #[cfg(test)]
    pub(crate) fn get_entry(
        &self,
        pkh: &PublicKeyHash,
        op_type: OperationType,
    ) -> Option<WatermarkEntry> {
        self.keys.get(pkh)?.entries[op_type as usize]
    }

    /// Get file handle for a specific key and operation type (test-only)
    #[cfg(test)]
    pub(crate) fn get_key_file(
        &self,
        pkh: &PublicKeyHash,
        op_type: OperationType,
    ) -> Option<&File> {
        Some(&self.keys.get(pkh)?.files[op_type as usize])
    }

    /// Get disk ceiling for a specific key and operation type (test-only)
    #[cfg(test)]
    pub(crate) fn get_disk_ceiling(
        &self,
        pkh: &PublicKeyHash,
        op_type: OperationType,
    ) -> Option<WatermarkEntry> {
        self.keys.get(pkh)?.disk_ceiling[op_type as usize]
    }
}

/// Load or create per-key watermark files from a directory.
fn load_per_key_watermark(key_dir: &Path) -> io::Result<PerKeyWatermark> {
    fs::create_dir_all(key_dir)?;

    let mut files_opt: [Option<File>; 3] = [None, None, None];
    let mut prev_files_opt: [Option<File>; 3] = [None, None, None];
    let mut entries: [Option<WatermarkEntry>; 3] = [None, None, None];

    for (i, filename) in FILENAMES.iter().enumerate() {
        let path = key_dir.join(filename);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        let prev_path = key_dir.join(format!("{filename}.prev"));
        let prev_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&prev_path)?;

        // Try primary, then fall back to .prev
        entries[i] = load_entry_from_file(&file).or_else(|| {
            let entry = load_entry_from_file(&prev_file);
            if entry.is_some() {
                log::warn!("Primary watermark {filename} corrupt/missing, loaded from .prev");
            }
            entry
        });

        files_opt[i] = Some(file);
        prev_files_opt[i] = Some(prev_file);
    }

    Ok(PerKeyWatermark {
        files: [
            files_opt[0].take().unwrap(),
            files_opt[1].take().unwrap(),
            files_opt[2].take().unwrap(),
        ],
        prev_files: [
            prev_files_opt[0].take().unwrap(),
            prev_files_opt[1].take().unwrap(),
            prev_files_opt[2].take().unwrap(),
        ],
        entries,
        disk_ceiling: [None; 3],
    })
}

/// Encode a watermark entry as 40 bytes: level (4B BE) + round (4B BE) + blake3 (32B)
#[must_use]
pub fn encode_entry(level: u32, round: u32) -> [u8; WATERMARK_FILE_SIZE] {
    russignol_storage::watermark::encode(level, round)
}

/// Decode a 40-byte buffer into a watermark entry, validating Blake3 hash.
fn decode_entry(buf: &[u8; WATERMARK_FILE_SIZE]) -> Option<WatermarkEntry> {
    let (level, round) = russignol_storage::watermark::decode(buf)?;
    Some(WatermarkEntry { level, round })
}

/// Load a watermark entry from an open file handle (pread at offset 0).
fn load_entry_from_file(file: &File) -> Option<WatermarkEntry> {
    let meta = file.metadata().ok()?;
    if meta.len() != WATERMARK_FILE_SIZE as u64 {
        return None;
    }
    let mut buf = [0u8; WATERMARK_FILE_SIZE];
    file.read_exact_at(&mut buf, 0).ok()?;
    decode_entry(&buf)
}

/// Load a watermark entry from a file path.
#[cfg(test)]
fn load_entry_from_path(path: &Path) -> Option<WatermarkEntry> {
    let data = fs::read(path).ok()?;
    if data.len() != WATERMARK_FILE_SIZE {
        return None;
    }
    let mut buf = [0u8; WATERMARK_FILE_SIZE];
    buf.copy_from_slice(&data);
    decode_entry(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::generate_key;
    use crate::test_utils::{
        create_attestation_data, create_block_data, default_test_chain_id, preinit_watermarks,
    };
    use tempfile::TempDir;

    fn create_test_chain_id() -> ChainId {
        default_test_chain_id()
    }

    #[test]
    fn test_per_key_watermark_isolation() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();

        let seed1 = [42u8; 32];
        let (pkh1, _pk1, _sk1) = generate_key(Some(&seed1)).unwrap();
        let seed2 = [43u8; 32];
        let (pkh2, _pk2, _sk2) = generate_key(Some(&seed2)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh1, 99);
        preinit_watermarks(temp_dir.path(), &pkh2, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh1, pkh2]).unwrap();

        // Consensus key signs attestation at (100, 0)
        let data = create_attestation_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh1, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Companion key signs attestation at (100, 0) — should succeed
        let update2 = hwm
            .check_and_update(chain_id, &pkh2, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update2).unwrap();
    }

    #[test]
    fn test_allow_signing_at_higher_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data1 = create_block_data(100, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        let data2 = create_block_data(101, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data2).is_ok());
    }

    #[test]
    fn test_reject_signing_at_lower_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data1 = create_block_data(100, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

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

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data1 = create_block_data(100, 5);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        let data2 = create_block_data(100, 6);
        assert!(hwm.check_and_update(chain_id, &pkh, &data2).is_ok());
    }

    #[test]
    fn test_reject_signing_at_lower_round_same_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data1 = create_block_data(100, 5);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        let data2 = create_block_data(100, 4);
        let result = hwm.check_and_update(chain_id, &pkh, &data2);
        assert!(matches!(result, Err(WatermarkError::RoundTooLow { .. })));
    }

    #[test]
    fn test_reject_signing_at_same_round_same_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data1 = create_block_data(100, 5);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

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

        preinit_watermarks(temp_dir.path(), &pkh, 99);

        // First instance: sign at level 100 and persist
        {
            let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
            let data = create_block_data(100, 5);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        // Second instance: load from disk and verify
        {
            let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

            // Verify loaded entry
            assert_eq!(
                hwm.get_entry(&pkh, OperationType::Block),
                Some(WatermarkEntry {
                    level: 100,
                    round: 5
                })
            );

            // Try to sign at level 99 should fail
            let data = create_block_data(99, 0);
            let result = hwm.check_and_update(chain_id, &pkh, &data);
            assert!(matches!(result, Err(WatermarkError::LevelTooLow { .. })));
        }
    }

    #[test]
    fn test_reject_first_signature_without_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data = create_block_data(100, 0);
        let result = hwm.check_and_update(chain_id, &pkh, &data);
        assert!(
            matches!(result, Err(WatermarkError::NotInitialized { .. })),
            "Should reject signing without pre-initialized watermark"
        );
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

    #[test]
    fn test_binary_file_format() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [77u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data = create_block_data(100, 5);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Read raw file and verify binary format
        let key_dir = temp_dir.path().join(pkh.to_b58check());
        let raw = fs::read(key_dir.join("block_watermark")).unwrap();
        assert_eq!(raw.len(), 40, "Watermark file must be exactly 40 bytes");

        let level = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let round = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let computed = blake3::hash(&raw[0..8]);

        assert_eq!(level, 100);
        assert_eq!(round, 5);
        assert_eq!(&raw[8..40], computed.as_bytes(), "Blake3 hash must match");
    }

    #[test]
    fn test_corrupt_primary_falls_back_to_prev() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let key_dir = temp_dir.path().join(pkh.to_b58check());

        // Sign at level 100, persist (creates .prev from init data)
        {
            let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
            let data = create_block_data(100, 5);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        // Sign at level 200, persist (copies level 100 to .prev)
        {
            let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
            let data = create_block_data(200, 3);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        // Corrupt the primary file
        fs::write(key_dir.join("block_watermark"), b"corrupted!!!").unwrap();

        // Reload — should fall back to .prev (level 100)
        let hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm.get_entry(&pkh, OperationType::Block),
            Some(WatermarkEntry {
                level: 100,
                round: 5
            }),
            "Should load from .prev after primary corruption"
        );
    }

    #[test]
    fn test_both_files_corrupt_returns_none() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Create per-key dir with garbage in both primary and .prev
        let key_dir = temp_dir.path().join(pkh.to_b58check());
        fs::create_dir_all(&key_dir).unwrap();
        fs::write(key_dir.join("block_watermark"), b"bad_data_xxx").unwrap();
        fs::write(key_dir.join("block_watermark.prev"), b"bad_data_xxx").unwrap();

        let hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm.get_entry(&pkh, OperationType::Block),
            None,
            "Both corrupt files should result in None entry"
        );

        // Attempting to sign should fail with NotInitialized
        let chain_id = create_test_chain_id();
        let data = create_block_data(100, 0);

        let mut hwm = hwm;
        let result = hwm.check_and_update(chain_id, &pkh, &data);
        assert!(matches!(result, Err(WatermarkError::NotInitialized { .. })));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let buf = encode_entry(12345, 67);
        let entry = decode_entry(&buf).expect("Should decode valid entry");
        assert_eq!(entry.level, 12345);
        assert_eq!(entry.round, 67);
    }

    #[test]
    fn test_encode_decode_zero() {
        let buf = encode_entry(0, 0);
        let entry = decode_entry(&buf).expect("Should decode zero entry");
        assert_eq!(entry.level, 0);
        assert_eq!(entry.round, 0);
    }

    #[test]
    fn test_encode_decode_max_values() {
        let buf = encode_entry(u32::MAX, u32::MAX);
        let entry = decode_entry(&buf).expect("Should decode max entry");
        assert_eq!(entry.level, u32::MAX);
        assert_eq!(entry.round, u32::MAX);
    }

    #[test]
    fn test_decode_rejects_bad_hash() {
        let mut buf = encode_entry(100, 5);
        buf[39] ^= 0xFF; // Flip last byte of hash
        assert!(decode_entry(&buf).is_none(), "Bad hash should be rejected");
    }

    #[test]
    fn test_wrong_file_size_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        let key_dir = temp_dir.path().join(pkh.to_b58check());
        fs::create_dir_all(&key_dir).unwrap();
        // Write 8 bytes instead of 40
        fs::write(key_dir.join("block_watermark"), [0u8; 8]).unwrap();

        let hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm.get_entry(&pkh, OperationType::Block),
            None,
            "Wrong size file should be rejected"
        );
    }

    #[test]
    fn test_update_to_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        hwm.update_to_level(chain_id, &pkh, 500).unwrap();

        // All three entries should be at level 500
        for op_type in OperationType::ALL {
            assert_eq!(
                hwm.get_entry(&pkh, op_type),
                Some(WatermarkEntry {
                    level: 500,
                    round: 0
                })
            );
        }

        // Reload from disk and verify persistence
        let hwm2 = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        for op_type in OperationType::ALL {
            assert_eq!(
                hwm2.get_entry(&pkh, op_type),
                Some(WatermarkEntry {
                    level: 500,
                    round: 0
                })
            );
        }
    }

    #[test]
    fn test_prev_file_created_on_write() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // .prev should exist and contain the pre-write data (level 99)
        let key_dir = temp_dir.path().join(pkh.to_b58check());
        let prev_entry = load_entry_from_path(&key_dir.join("block_watermark.prev")).unwrap();
        assert_eq!(prev_entry.level, 99);
        assert_eq!(prev_entry.round, 0);
    }

    #[test]
    fn test_preattestation_check_and_update_and_persist() {
        use crate::test_utils::create_preattestation_data;

        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Advance preattestation to level 100, round 3
        let data = create_preattestation_data(100, 3);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .expect("should produce update");
        hwm.write_watermark(&update).unwrap();

        // Same level, lower round rejected
        let data_low = create_preattestation_data(100, 2);
        assert!(hwm.check_and_update(chain_id, &pkh, &data_low).is_err());

        // Higher round accepted
        let data_high = create_preattestation_data(100, 4);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data_high)
            .unwrap()
            .expect("should produce update");
        hwm.write_watermark(&update2).unwrap();

        // Reload from disk and verify
        let hwm2 = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm2.get_entry(&pkh, OperationType::Preattestation),
            Some(WatermarkEntry {
                level: 100,
                round: 4
            })
        );
    }

    #[test]
    fn test_rollback_disk_watermark_with_none_prev() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Start with level 0 (the preinit level)
        preinit_watermarks(temp_dir.path(), &pkh, 0);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // First-ever advance: prev is Some (level 0)
        let data = create_block_data(1, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .expect("should produce update");
        hwm.write_watermark(&update).unwrap();

        // Rollback should write prev (level 0) back
        hwm.rollback_update(&update);
        hwm.rollback_disk_watermark(&update).unwrap();

        let hwm2 = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm2.get_entry(&pkh, OperationType::Block),
            Some(WatermarkEntry { level: 0, round: 0 })
        );
    }

    #[test]
    fn test_update_to_level_then_sign() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Jump to level 500
        hwm.update_to_level(chain_id, &pkh, 500).unwrap();

        // Signing at level 500, round 0 should be rejected (same level+round)
        let data = create_block_data(500, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data).is_err());

        // Signing at level 501 should succeed
        let data = create_block_data(501, 0);
        let update = hwm.check_and_update(chain_id, &pkh, &data).unwrap();
        assert!(update.is_some());

        // Signing at level 500, round 1 should be rejected (level too low after 501)
        let data = create_block_data(500, 1);
        assert!(hwm.check_and_update(chain_id, &pkh, &data).is_err());
    }

    #[test]
    fn test_read_back_verification_catches_corrupt_write() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Normal write should pass read-back verification
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .expect("should produce update");
        assert!(hwm.write_watermark(&update).is_ok());

        // Corrupt the file after write_watermark's internal fsync but before
        // a second write — simulate by directly corrupting the file, then
        // attempting a new write_watermark that should pass (since it writes
        // fresh data). This validates the verification runs on the NEW data.
        let corrupt_buf = [0xFFu8; WATERMARK_FILE_SIZE];
        hwm.get_key_file(&pkh, OperationType::Block)
            .unwrap()
            .write_all_at(&corrupt_buf, 0)
            .unwrap();

        // Next write should succeed (overwrites corrupt data, then verifies)
        let data2 = create_block_data(101, 0);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data2)
            .unwrap()
            .expect("should produce update");
        assert!(hwm.write_watermark(&update2).is_ok());

        // Verify the file is now correct
        let entry =
            load_entry_from_file(hwm.get_key_file(&pkh, OperationType::Block).unwrap()).unwrap();
        assert_eq!(entry.level, 101);
        assert_eq!(entry.round, 0);
    }

    #[test]
    fn test_ceiling_covers_next_level_sign() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block as usize, 101)
            .unwrap();

        // ceiling_covers should return true for sign at (101, 0)
        let data2 = create_block_data(101, 0);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data2)
            .unwrap()
            .unwrap();
        assert!(
            hwm.ceiling_covers(&update2),
            "Ceiling at (101, MAX) should cover sign at (101, 0)"
        );
    }

    #[test]
    fn test_ceiling_does_not_cover_level_skip() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block as usize, 101)
            .unwrap();

        // ceiling_covers should return false for sign at (102, 0)
        let data2 = create_block_data(102, 0);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data2)
            .unwrap()
            .unwrap();
        assert!(
            !hwm.ceiling_covers(&update2),
            "Ceiling at (101, MAX) should NOT cover sign at (102, 0)"
        );
    }

    #[test]
    fn test_ceiling_covers_any_round() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block as usize, 101)
            .unwrap();

        // Should cover any round at level 101
        for round in [0, 1, 999, u32::MAX - 1] {
            let data = create_block_data(101, round);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            assert!(
                hwm.ceiling_covers(&update),
                "Ceiling at (101, MAX) should cover (101, {round})"
            );
            // Roll back so next iteration can check_and_update at same level
            hwm.rollback_update(&update);
        }
    }

    #[test]
    fn test_ceiling_cleared_after_fdatasync() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // No ceiling — sign should do fdatasync and ceiling remains None
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        assert_eq!(
            hwm.get_disk_ceiling(&pkh, OperationType::Block),
            None,
            "Ceiling should be None after fdatasync write"
        );
    }

    #[test]
    fn test_ceiling_cleared_after_rollback() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block as usize, 101)
            .unwrap();
        assert!(hwm.get_disk_ceiling(&pkh, OperationType::Block).is_some());

        // Sign at 101, then rollback disk watermark — ceiling should be cleared
        let data2 = create_block_data(101, 0);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data2)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update2).unwrap();
        hwm.rollback_update(&update2);
        hwm.rollback_disk_watermark(&update2).unwrap();

        assert_eq!(
            hwm.get_disk_ceiling(&pkh, OperationType::Block),
            None,
            "Ceiling should be cleared after rollback"
        );
    }

    #[test]
    fn test_ceiling_safety_on_reload() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);

        // Sign at level 100, then write ceiling for 101
        {
            let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
            let data = create_block_data(100, 0);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
            hwm.write_ceiling(pkh, OperationType::Block as usize, 101)
                .unwrap();
        }

        // Simulate crash — reload from disk.
        // Disk has (101, MAX) ceiling. Reload should see that.
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Level 101 should be blocked (loaded ceiling has round=MAX, so
        // round <= MAX is rejected by the same-level round check)
        let data = create_block_data(101, 0);
        assert!(
            hwm.check_and_update(chain_id, &pkh, &data).is_err(),
            "Level 101 should be blocked after loading ceiling"
        );

        // Level 102 should succeed
        let data2 = create_block_data(102, 0);
        assert!(
            hwm.check_and_update(chain_id, &pkh, &data2).is_ok(),
            "Level 102 should succeed after ceiling blocks 101"
        );
    }

    #[test]
    fn test_ceiling_write_skipped_when_advanced() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100, then at level 102 (skipping 101)
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        let data2 = create_block_data(102, 0);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data2)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update2).unwrap();

        // Ceiling write for level 101 should be skipped (watermark at 102)
        hwm.write_ceiling(pkh, OperationType::Block as usize, 101)
            .unwrap();
        assert_eq!(
            hwm.get_disk_ceiling(&pkh, OperationType::Block),
            None,
            "Ceiling at 101 should be skipped when watermark is at 102"
        );

        // Verify disk still has level 102 (not regressed)
        let hwm2 = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm2.get_entry(&pkh, OperationType::Block),
            Some(WatermarkEntry {
                level: 102,
                round: 0
            })
        );
    }
}
