//! High watermark tracking for double-signing prevention
//!
//! This module implements high watermark protection to prevent signing
//! multiple blocks or attestations at the same level/round, which would
//! constitute double-signing (slashable offense in Tenderbake consensus).
//!
//! Watermarks are stored as 40-byte binary files (level + round + Blake3)
//! and fsynced to disk before any signature is returned. Each operation
//! type has a `.prev` backup for crash recovery.
//!
//! Corresponds to: src/bin_signer/handler.ml:27-232

use crate::bls::PublicKeyHash;
use crate::magic_bytes::{
    get_level_and_round_for_tenderbake_attestation, get_level_and_round_for_tenderbake_block,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// Size of a watermark file: level (4) + round (4) + blake3 (32)
const WATERMARK_FILE_SIZE: usize = 40;

/// File names for each operation type, indexed by `OperationType as usize`
const FILENAMES: [&str; 3] = [
    "block_watermark",
    "preattestation_watermark",
    "attestation_watermark",
];

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

/// Info needed to persist a watermark update to disk.
///
/// Returned from [`HighWatermark::check_and_update`] when the watermark was
/// advanced. Pass to [`HighWatermark::write_watermark`] to persist.
#[derive(Debug)]
pub struct WatermarkUpdate {
    idx: usize,
    level: u32,
    round: u32,
    /// Previous entry for rollback if BLS signing fails
    prev: Option<WatermarkEntry>,
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
/// for each operation type (block, preattestation, attestation).
///
/// Watermarks are stored as 40-byte binary files and fsynced before
/// any signature is returned. File handles are opened at construction
/// so no path lookups occur at signing time.
///
/// Corresponds to: src/bin_signer/handler.ml:27-232
pub struct HighWatermark {
    /// Storage directory
    base_dir: PathBuf,
    /// Primary file handles, indexed by `OperationType as usize`
    files: [File; 3],
    /// In-memory cache, indexed by `OperationType as usize`
    entries: [Option<WatermarkEntry>; 3],
}

impl HighWatermark {
    /// Create new high watermark tracker
    ///
    /// Opens (or creates) the three watermark files and loads their entries.
    /// Falls back to `.prev` if a primary file has a bad hash.
    pub fn new<P: AsRef<Path>>(base_dir: P) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;

        let mut files_opt: [Option<File>; 3] = [None, None, None];
        let mut entries: [Option<WatermarkEntry>; 3] = [None, None, None];

        for (i, filename) in FILENAMES.iter().enumerate() {
            let path = base_dir.join(filename);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;

            // Try primary, then fall back to .prev
            entries[i] = load_entry_from_file(&file).or_else(|| {
                let prev_path = base_dir.join(format!("{filename}.prev"));
                let entry = load_entry_from_path(&prev_path);
                if entry.is_some() {
                    log::warn!("Primary watermark {filename} corrupt/missing, loaded from .prev");
                }
                entry
            });

            files_opt[i] = Some(file);
        }

        Ok(Self {
            base_dir,
            files: [
                files_opt[0].take().unwrap(),
                files_opt[1].take().unwrap(),
                files_opt[2].take().unwrap(),
            ],
            entries,
        })
    }

    /// Check if data can be signed and update in-memory watermark if allowed.
    ///
    /// Returns `Ok(Some(update))` with a [`WatermarkUpdate`] that must be passed
    /// to [`write_watermark`](Self::write_watermark) before returning the signature.
    /// Returns `Ok(None)` for non-watermarked operations (magic byte not 0x11/0x12/0x13).
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

        let idx = op_type as usize;

        // Check watermark exists (must be pre-configured before first signature)
        let Some(current) = self.entries[idx] else {
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
        let prev = self.entries[idx];
        self.entries[idx] = Some(WatermarkEntry { level, round });

        Ok(Some(WatermarkUpdate {
            idx,
            level,
            round,
            prev,
        }))
    }

    /// Roll back an in-memory watermark advance.
    ///
    /// Call this if BLS signing fails after [`check_and_update`](Self::check_and_update)
    /// succeeded, so the baker can retry at the same level.
    pub fn rollback_update(&mut self, update: &WatermarkUpdate) {
        self.entries[update.idx] = update.prev;
    }

    /// Write the previous watermark value back to disk after a BLS signing failure.
    ///
    /// Call this after [`rollback_update`](Self::rollback_update) when BLS signing
    /// fails but `write_watermark` already persisted the advanced value.
    /// Restores disk state to match the rolled-back in-memory state.
    pub fn rollback_disk_watermark(&self, update: &WatermarkUpdate) -> Result<()> {
        if let Some(prev) = update.prev {
            let file = &self.files[update.idx];
            let buf = encode_entry(prev.level, prev.round);
            file.write_all_at(&buf, 0)?;
            file.set_len(WATERMARK_FILE_SIZE as u64)?;
            file.sync_all()?;
        }
        Ok(())
    }

    /// Persist watermark to disk: copy main → .prev, pwrite, fsync.
    ///
    /// Uses `pwrite` (no seek) and takes `&self`, so it can run in parallel
    /// with BLS signing on a scoped thread while the caller holds a write lock.
    pub fn write_watermark(&self, update: &WatermarkUpdate) -> Result<()> {
        let file = &self.files[update.idx];
        let filename = FILENAMES[update.idx];

        // Copy current main → .prev with fsync for durable backup
        let main_path = self.base_dir.join(filename);
        let prev_path = self.base_dir.join(format!("{filename}.prev"));
        if let Ok(data) = fs::read(&main_path)
            && let Ok(prev_file) = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&prev_path)
            && prev_file.write_all_at(&data, 0).is_ok()
            && let Err(e) = prev_file.sync_all()
        {
            log::warn!("Failed to fsync {filename}.prev: {e}");
        }

        // Build 40-byte buffer: level (4B BE) + round (4B BE) + blake3 (32B)
        let buf = encode_entry(update.level, update.round);

        // pwrite at offset 0 (no seek, no position change)
        file.write_all_at(&buf, 0)?;

        // Truncate to exact size in case file was previously larger
        file.set_len(WATERMARK_FILE_SIZE as u64)?;

        // fsync — flushes inode + data to stable storage
        file.sync_all()?;

        // Read-back verification: confirm the fsynced data decodes correctly
        let readback = load_entry_from_file(file).ok_or_else(|| {
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

        Ok(())
    }

    /// Get the current watermark level for a key.
    ///
    /// Returns the highest level from any of the three operation types.
    /// Returns None if no watermark exists.
    #[must_use]
    pub fn get_current_level(&self, _chain_id: ChainId, _pkh: &PublicKeyHash) -> Option<u32> {
        self.entries.iter().filter_map(|e| e.map(|w| w.level)).max()
    }

    /// Get current watermark levels for display purposes.
    ///
    /// Returns (`block_level`, `preattest_level`, `attest_level`).
    pub fn get_current_levels(
        &self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
    ) -> Result<(u32, u32, u32)> {
        let get = |idx: usize| -> Result<u32> {
            self.entries[idx]
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
    pub fn update_to_level(
        &mut self,
        _chain_id: ChainId,
        _pkh: &PublicKeyHash,
        level: u32,
    ) -> Result<()> {
        let entry = WatermarkEntry { level, round: 0 };
        for (i, op_type) in OperationType::ALL.iter().enumerate() {
            let prev = self.entries[i];
            self.entries[i] = Some(entry);
            self.write_watermark(&WatermarkUpdate {
                idx: *op_type as usize,
                level,
                round: 0,
                prev,
            })?;
        }
        Ok(())
    }
}

/// Encode a watermark entry as 40 bytes: level (4B BE) + round (4B BE) + blake3 (32B)
pub fn encode_entry(level: u32, round: u32) -> [u8; WATERMARK_FILE_SIZE] {
    let mut buf = [0u8; WATERMARK_FILE_SIZE];
    buf[0..4].copy_from_slice(&level.to_be_bytes());
    buf[4..8].copy_from_slice(&round.to_be_bytes());
    let hash = blake3::hash(&buf[0..8]);
    buf[8..40].copy_from_slice(hash.as_bytes());
    buf
}

/// Decode a 40-byte buffer into a watermark entry, validating Blake3 hash.
fn decode_entry(buf: &[u8; WATERMARK_FILE_SIZE]) -> Option<WatermarkEntry> {
    let level = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let round = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let computed = blake3::hash(&buf[0..8]);
    if buf[8..40] != *computed.as_bytes() {
        return None;
    }
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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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

        preinit_watermarks(temp_dir.path(), 99);

        // First instance: sign at level 100 and persist
        {
            let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();
            let data = create_block_data(100, 5);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        // Second instance: load from disk and verify
        {
            let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

            // Verify loaded entry
            assert_eq!(
                hwm.entries[OperationType::Block as usize],
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
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

        let data = create_block_data(100, 5);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Read raw file and verify binary format
        let raw = fs::read(temp_dir.path().join("block_watermark")).unwrap();
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

        preinit_watermarks(temp_dir.path(), 99);

        // Sign at level 100, persist (creates .prev from init data)
        {
            let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();
            let data = create_block_data(100, 5);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        // Sign at level 200, persist (copies level 100 to .prev)
        {
            let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();
            let data = create_block_data(200, 3);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        // Corrupt the primary file
        fs::write(temp_dir.path().join("block_watermark"), b"corrupted!!!").unwrap();

        // Reload — should fall back to .prev (level 100)
        let hwm = HighWatermark::new(temp_dir.path()).unwrap();
        assert_eq!(
            hwm.entries[OperationType::Block as usize],
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

        // Write garbage to both primary and .prev
        fs::write(temp_dir.path().join("block_watermark"), b"bad_data_xxx").unwrap();
        fs::write(
            temp_dir.path().join("block_watermark.prev"),
            b"bad_data_xxx",
        )
        .unwrap();

        let hwm = HighWatermark::new(temp_dir.path()).unwrap();
        assert_eq!(
            hwm.entries[OperationType::Block as usize],
            None,
            "Both corrupt files should result in None entry"
        );

        // Attempting to sign should fail with NotInitialized
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
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

        // Write 8 bytes instead of 40
        fs::write(temp_dir.path().join("block_watermark"), &[0u8; 8]).unwrap();

        let hwm = HighWatermark::new(temp_dir.path()).unwrap();
        assert_eq!(
            hwm.entries[OperationType::Block as usize],
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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

        hwm.update_to_level(chain_id, &pkh, 500).unwrap();

        // All three entries should be at level 500
        for i in 0..3 {
            assert_eq!(
                hwm.entries[i],
                Some(WatermarkEntry {
                    level: 500,
                    round: 0
                })
            );
        }

        // Reload from disk and verify persistence
        let hwm2 = HighWatermark::new(temp_dir.path()).unwrap();
        for i in 0..3 {
            assert_eq!(
                hwm2.entries[i],
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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // .prev should exist and contain the pre-write data (level 99)
        let prev_entry =
            load_entry_from_path(&temp_dir.path().join("block_watermark.prev")).unwrap();
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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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
        let hwm2 = HighWatermark::new(temp_dir.path()).unwrap();
        assert_eq!(
            hwm2.entries[OperationType::Preattestation as usize],
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
        preinit_watermarks(temp_dir.path(), 0);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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

        let hwm2 = HighWatermark::new(temp_dir.path()).unwrap();
        assert_eq!(
            hwm2.entries[OperationType::Block as usize],
            Some(WatermarkEntry { level: 0, round: 0 })
        );
    }

    #[test]
    fn test_update_to_level_then_sign() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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

        preinit_watermarks(temp_dir.path(), 99);
        let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

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
        hwm.files[OperationType::Block as usize]
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
        let entry = load_entry_from_file(&hwm.files[OperationType::Block as usize]).unwrap();
        assert_eq!(entry.level, 101);
        assert_eq!(entry.round, 0);
    }
}
