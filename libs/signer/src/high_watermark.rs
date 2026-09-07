//! High watermark tracking for double-signing prevention
//!
//! This module implements high watermark protection to prevent signing
//! multiple blocks or attestations at the same level/round, which would
//! constitute double-signing (slashable offense in Tenderbake consensus).
//!
//! Watermarks are stored as 72-byte binary files (level + round + Blake3 +
//! a PIN-derived keyed MAC) and fdatasynced to disk before any signature is
//! returned. Only the PIN-unlocked device holds the per-key MAC key, so a mark
//! that fails to verify (forged, corrupt, or legacy) is treated as absent and
//! the on-device recovery re-establishes an authenticated floor.
//!
//! Watermarks are tracked per-key, so each public key hash has independent
//! watermark state. This supports companion key signing (DAL) where both
//! the consensus key and companion key sign at the same level/round.
//!
//! Corresponds to: src/bin_signer/handler.ml:27-232

use crate::magic_bytes::{
    get_level_and_round_for_tenderbake_attestation, get_level_and_round_for_tenderbake_block,
};
use crate::scheme::{PublicKeyHash, SecretKey};
use crate::xmss::Epoch;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::RangeInclusive;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use russignol_storage::watermark::{
    AUTH_FILE_SIZE, EPOCH_AD_TAG, EPOCH_FILENAME, FILENAMES, decode_authenticated,
    encode_authenticated,
};
// The keyless prefix decode is only used by the debug/test read-back path; the
// release load path verifies the full authenticated record instead.
#[cfg(any(debug_assertions, test))]
use russignol_storage::watermark::{FILE_SIZE, decode as decode_prefix};

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

    /// Decode a base58check "Net…" chain id (inverse of [`to_b58check`]).
    ///
    /// The 4 chain bytes land in the leading positions of the 32-byte id, the
    /// same layout [`from_bytes`] and the signing path use.
    #[must_use]
    pub fn from_b58check(s: &str) -> Option<Self> {
        let decoded = bs58::decode(s).with_check(None).into_vec().ok()?;
        // 3-byte "Net" prefix followed by the 4 chain bytes.
        let chain = decoded.strip_prefix(&[87, 82, 0])?;
        let four: [u8; 4] = chain.get(..4)?.try_into().ok()?;
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&four);
        Some(Self(bytes))
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
    #[must_use]
    pub fn from_magic_byte(magic: u8) -> Option<Self> {
        match magic {
            0x11 => Some(Self::Block),
            0x12 => Some(Self::Preattestation),
            0x13 => Some(Self::Attestation),
            _ => None,
        }
    }
}

/// Signatures a baker spends at one level: block, preattestation, attestation.
const SIGNATURES_PER_LEVEL: u64 = 3;

/// Mainnet's block interval, which is the span those signatures are spent over:
/// `block_time` is 6 in Octez's `src/proto_alpha/lib_parameters/default_parameters.ml`.
const BLOCK_SECONDS: u64 = 6;

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// Epochs one durable write reserves ahead of use.
///
/// A reservation covers a level, the same span the Tenderbake ceiling is
/// written a level ahead for, so a crash wastes at most a level's epochs.
pub const EPOCH_BURST: u64 = SIGNATURES_PER_LEVEL;

/// What a key's epoch counter has left to spend.
///
/// Built where the range and the cursor sit together, so nothing downstream
/// subtracts one from the other a second time and no reading can report more
/// left than the key was generated with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochBudget {
    total: u64,
    remaining: u64,
}

impl EpochBudget {
    fn new(range: &RangeInclusive<Epoch>, next: u64) -> Self {
        let total = u64::from(*range.end()) - u64::from(*range.start()) + 1;
        Self {
            total,
            remaining: (u64::from(*range.end()) + 1)
                .saturating_sub(next)
                .min(total),
        }
    }

    /// Epochs the key was generated with. Each one is a signature, and a second
    /// signature at any of them discloses the key.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.total
    }

    /// Epochs left, counted from the one a claim hands out next rather than
    /// from the resume point, which sits a reservation ahead of what has been
    /// signed at.
    #[must_use]
    pub const fn remaining(self) -> u64 {
        self.remaining
    }

    /// Days of baking those epochs cover, at a level's signatures per block.
    #[must_use]
    pub const fn days_remaining(self) -> u64 {
        self.remaining * BLOCK_SECONDS / (SIGNATURES_PER_LEVEL * SECONDS_PER_DAY)
    }
}

/// What the mark store needs from a key's secret.
///
/// Read off the secret once at unlock and passed in, so nothing downstream
/// re-derives either value from key material it would have to hold to do so.
#[derive(Debug, Clone)]
pub struct MarkParams {
    /// Authenticates this key's watermark and epoch records. Derived from the
    /// PIN-unlocked secret, so a card thief without the PIN cannot reproduce it
    /// and a forged record fails to verify.
    pub mac_key: [u8; 32],
    /// The epochs this key may ever sign at, or `None` under a scheme that
    /// spends no epoch per signature.
    pub epochs: Option<RangeInclusive<Epoch>>,
}

impl From<&SecretKey> for MarkParams {
    fn from(secret_key: &SecretKey) -> Self {
        Self {
            mac_key: secret_key.watermark_mac_key(),
            epochs: secret_key.epoch_range(),
        }
    }
}

/// Where a key's epoch counter stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EpochCursor {
    /// The next epoch to hand out.
    next: u64,
    /// Epochs still covered by the resume point on stable storage. A claim
    /// needs no disk write while this is non-zero, and the resume point is
    /// `next + reserved`, so no state can put it below `next`.
    reserved: u64,
}

impl EpochCursor {
    /// The epoch a reload resumes at. Every epoch below it is spent whether or
    /// not it was ever handed out, and it reaches stable storage before any
    /// epoch it covers leaves the store.
    const fn resume_at(self) -> u64 {
        self.next + self.reserved
    }
}

/// Per-key epoch state, held only for a key whose every epoch is a one-time key.
struct PerKeyEpoch {
    file: File,
    /// The key's own range, as the key reports it.
    range: RangeInclusive<Epoch>,
    /// `None` until an authenticated record is on disk. A wiped or forged record
    /// reads the same way, so a claim fails closed rather than restarting the
    /// counter at the range's first epoch and re-signing every epoch spent.
    cursor: Option<EpochCursor>,
}

/// Per-key watermark state: file handles and in-memory cache
struct PerKeyWatermark {
    /// Primary file handles, indexed by `OperationType as usize`
    files: [File; 3],
    /// In-memory cache, indexed by `OperationType as usize`
    entries: [Option<WatermarkEntry>; 3],
    /// What ceiling entry is on stable storage, indexed by `OperationType as usize`.
    /// A ceiling `(level, u32::MAX)` on disk means any crash recovery loads this value,
    /// allowing fdatasync to be skipped for updates covered by the ceiling.
    disk_ceiling: [Option<WatermarkEntry>; 3],
    /// Last value confirmed on stable storage (after fdatasync), indexed by `OperationType as usize`.
    /// Initialized from disk at load time; updated after each successful `write_watermark`.
    disk_entries: [Option<WatermarkEntry>; 3],
    /// Present for a key of a scheme that spends an epoch per signature. The
    /// Tenderbake quadruple above stays regardless: equivocation is slashable
    /// whatever key signs it, and an epoch counter says nothing about levels.
    epoch: Option<PerKeyEpoch>,
}

/// Info needed to persist a watermark update to disk.
///
/// Returned from [`HighWatermark::check_and_update`] when the watermark was
/// advanced. Pass to [`HighWatermark::write_watermark`] to persist.
#[derive(Debug)]
pub struct WatermarkUpdate {
    pkh: PublicKeyHash,
    op_type: OperationType,
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

    /// Operation type this update advanced
    #[must_use]
    pub fn op_type(&self) -> OperationType {
        self.op_type
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

    /// Operation targets a chain the device was not provisioned for
    #[error("Chain mismatch: provisioned for {expected}, operation for {got}")]
    ChainMismatch {
        /// Provisioned chain ID (base58 encoded)
        expected: String,
        /// Operation's chain ID (base58 encoded)
        got: String,
    },

    /// An epoch was asked of a key whose scheme spends none
    #[error("Key {pkh} signs under a scheme that spends no epochs")]
    NoEpochCounter {
        /// Public key hash (base58 encoded)
        pkh: String,
    },

    /// The key holds no authenticated epoch record yet
    #[error(
        "Epoch record not initialized for key {pkh}. Establish the epoch floor before signing."
    )]
    EpochNotInitialized {
        /// Public key hash (base58 encoded)
        pkh: String,
    },

    /// Every epoch in the key's range has been handed out
    #[error("Epochs exhausted for key {pkh}: next {next}, last usable {last}")]
    EpochsExhausted {
        /// Public key hash (base58 encoded)
        pkh: String,
        /// The epoch that would be handed out next
        next: u64,
        /// The key's last usable epoch
        last: u64,
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
/// A key of a scheme that spends a one-time key per signature also gets an
/// epoch record in that subdirectory, and hands out epochs through
/// [`claim_epoch`](Self::claim_epoch).
///
/// Marks are stored as the 72-byte authenticated records of
/// `russignol_storage::watermark` and fdatasynced before any signature is
/// returned. All file handles are opened at construction so no path lookups
/// occur at signing time.
///
/// Corresponds to: src/bin_signer/handler.ml:27-232
pub struct HighWatermark {
    base_dir: PathBuf,
    /// Set of PKHs this tracker is authorised to manage (fixed at construction).
    known_pkhs: HashSet<PublicKeyHash>,
    keys: HashMap<PublicKeyHash, PerKeyWatermark>,
    /// What each key's secret told us at unlock: the MAC key authenticating its
    /// records, and the epochs it may sign at.
    key_params: HashMap<PublicKeyHash, MarkParams>,
    /// Chain the marks are bound to; part of every mark's authenticated data.
    chain_id: ChainId,
    /// Makes the next durable write fail. Private with only a `#[cfg(test)]`
    /// mutator, so nothing outside a test can reach it, and [`persist`] holds
    /// the one branch that reads it rather than each persist site carrying its
    /// own.
    force_write_error: bool,
}

impl HighWatermark {
    /// Create new high watermark tracker
    ///
    /// Loads existing per-key watermark state for the given public key hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if creating the base directory or loading watermark files fails.
    pub fn new<P: AsRef<Path>>(
        base_dir: P,
        pkhs: &[PublicKeyHash],
        key_params: HashMap<PublicKeyHash, MarkParams>,
        chain_id: ChainId,
    ) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;
        let ad = *chain_id.as_bytes();
        let epoch_ad = epoch_ad(chain_id);

        let mut keys = HashMap::new();
        for pkh in pkhs {
            let key_dir = base_dir.join(pkh.to_b58check());
            if key_dir.is_dir() {
                let params = params_for(&key_params, pkh)?;
                let per_key = load_per_key_watermark(&key_dir, params, &ad, &epoch_ad)?;
                keys.insert(*pkh, per_key);
            }
        }

        let known_pkhs: HashSet<PublicKeyHash> = pkhs.iter().copied().collect();
        Ok(Self {
            base_dir,
            known_pkhs,
            keys,
            key_params,
            chain_id,
            force_write_error: false,
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
        let params = self.params(pkh)?.clone();
        let ad = *self.chain_id.as_bytes();
        let epoch_ad = epoch_ad(self.chain_id);
        let per_key = load_per_key_watermark(&key_dir, &params, &ad, &epoch_ad)?;
        self.keys.insert(*pkh, per_key);
        Ok(())
    }

    /// What `pkh`'s secret told us at unlock, or a `NotInitialized` error if
    /// this key was not registered at construction.
    fn params(&self, pkh: &PublicKeyHash) -> Result<&MarkParams> {
        self.key_params
            .get(pkh)
            .ok_or_else(|| WatermarkError::NotInitialized {
                chain_id: self.chain_id.to_b58check(),
                pkh: pkh.to_b58check(),
            })
    }

    /// The MAC key for `pkh`, or a `NotInitialized` error if this key was not
    /// registered at construction.
    fn mac_key(&self, pkh: &PublicKeyHash) -> Result<&[u8; 32]> {
        Ok(&self.params(pkh)?.mac_key)
    }

    /// Make the next durable write fail, so a test can exercise the paths that
    /// must refuse a signature rather than return one no record covers.
    #[cfg(test)]
    pub(crate) fn set_write_error(&mut self, fail: bool) {
        self.force_write_error = fail;
    }

    /// Build the authenticated on-disk bytes for a mark under `pkh`'s MAC key.
    fn mark_bytes(
        &self,
        pkh: &PublicKeyHash,
        level: u32,
        round: u32,
    ) -> Result<[u8; AUTH_FILE_SIZE]> {
        let mac_key = self.mac_key(pkh)?;
        Ok(encode_authenticated(
            mac_key,
            self.chain_id.as_bytes(),
            level,
            round,
        ))
    }

    /// Check if data can be signed and update in-memory watermark if allowed.
    ///
    /// Returns `Ok(Some(update))` with a [`WatermarkUpdate`] that must be passed
    /// to [`write_watermark`](Self::write_watermark) before returning the signature.
    /// Returns `Ok(None)` for non-watermarked operations (magic byte not 0x11/0x12/0x13).
    ///
    /// Prefer [`check_and_update_parsed`](Self::check_and_update_parsed) when the
    /// caller already extracted level/round (avoids a second parse on the hot path).
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
            0x12 | 0x13 => get_level_and_round_for_tenderbake_attestation(data, pkh.scheme())
                .map_err(|e| WatermarkError::InvalidData(e.to_string()))?,
            _ => unreachable!(),
        };

        self.check_and_update_parsed(chain_id, pkh, op_type, level, round)
    }

    /// Like [`check_and_update`](Self::check_and_update) with level/round already parsed.
    ///
    /// # Panics
    ///
    /// Cannot panic: `ensure_key()` guarantees the key exists before the `.unwrap()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not initialized or signing would violate the
    /// high watermark (double-signing protection).
    pub fn check_and_update_parsed(
        &mut self,
        chain_id: ChainId,
        pkh: &PublicKeyHash,
        op_type: OperationType,
        level: u32,
        round: u32,
    ) -> Result<Option<WatermarkUpdate>> {
        self.ensure_key(pkh)?;
        let per_key = self.keys.get_mut(pkh).unwrap();
        let idx = op_type as usize;

        let Some(current) = per_key.entries[idx] else {
            return Err(WatermarkError::NotInitialized {
                chain_id: chain_id.to_b58check(),
                pkh: pkh.to_b58check(),
            });
        };

        if level < current.level {
            return Err(WatermarkError::LevelTooLow {
                current: current.level,
                requested: level,
            });
        }

        if level == current.level && round <= current.round {
            return Err(WatermarkError::RoundTooLow {
                level,
                current: current.round,
                requested: round,
            });
        }

        let prev = per_key.entries[idx];
        per_key.entries[idx] = Some(WatermarkEntry { level, round });

        Ok(Some(WatermarkUpdate {
            pkh: *pkh,
            op_type,
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

    /// Get a shared reference to a key's watermark state.
    fn per_key(&self, pkh: &PublicKeyHash) -> Result<&PerKeyWatermark> {
        self.keys
            .get(pkh)
            .ok_or_else(|| WatermarkError::Internal(format!("Unknown key: {}", pkh.to_b58check())))
    }

    /// Roll back an in-memory watermark advance.
    ///
    /// Call this if BLS signing fails after [`check_and_update`](Self::check_and_update)
    /// succeeded, so the baker can retry at the same level.
    pub fn rollback_update(&mut self, update: &WatermarkUpdate) {
        if let Some(per_key) = self.keys.get_mut(&update.pkh) {
            per_key.entries[update.op_type as usize] = update.prev;
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
        per_key.disk_ceiling[update.op_type as usize].is_some_and(|c| {
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
            let injected = self.force_write_error;
            let buf = self.mark_bytes(&update.pkh, prev.level, prev.round)?;
            let per_key = self.per_key_mut(&update.pkh)?;
            let idx = update.op_type as usize;
            persist(&per_key.files[idx], &buf, injected)?;
            per_key.disk_ceiling[idx] = None;
            per_key.disk_entries[idx] = Some(prev);
        }
        Ok(())
    }

    /// Persist watermark to disk: pwrite + fdatasync.
    ///
    /// Only called when no ceiling covers the update (slow path).
    /// When a ceiling covers, the caller skips this entirely — no disk I/O
    /// in the signing critical path.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not initialized or disk I/O fails.
    pub fn write_watermark(&mut self, update: &WatermarkUpdate) -> Result<()> {
        let injected = self.force_write_error;
        // Build the authenticated bytes before borrowing per_key mutably.
        let buf = self.mark_bytes(&update.pkh, update.level, update.round)?;
        let per_key = self.per_key_mut(&update.pkh)?;
        let idx = update.op_type as usize;

        persist(&per_key.files[idx], &buf, injected)?;
        per_key.disk_ceiling[idx] = None;
        per_key.disk_entries[idx] = Some(WatermarkEntry {
            level: update.level,
            round: update.round,
        });

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
        op_type: OperationType,
        ceiling_level: u32,
    ) -> Result<()> {
        let injected = self.force_write_error;
        let idx = op_type as usize;
        let per_key = self.per_key(&pkh)?;

        if per_key.entries[idx].is_some_and(|e| e.level >= ceiling_level) {
            return Ok(());
        }

        if per_key.disk_ceiling[idx].is_some_and(|c| c.level >= ceiling_level) {
            return Ok(());
        }

        // Below the skips so a call returning without writing pays nothing for
        // the keyed BLAKE3, and above the mutable borrow because `mark_bytes`
        // reads `&self`.
        let buf = self.mark_bytes(&pkh, ceiling_level, u32::MAX)?;
        let per_key = self.per_key_mut(&pkh)?;

        persist(&per_key.files[idx], &buf, injected)?;
        let ceiling_entry = WatermarkEntry {
            level: ceiling_level,
            round: u32::MAX,
        };
        per_key.disk_ceiling[idx] = Some(ceiling_entry);
        per_key.disk_entries[idx] = Some(ceiling_entry);

        Ok(())
    }

    /// Hand out the next unspent epoch for `pkh`.
    ///
    /// The resume point reaches stable storage before the epoch it covers
    /// leaves this store, so a reload after a crash resumes above every epoch
    /// ever handed out. Signing twice at one epoch discloses the secret key
    /// rather than costing a deposit, which is why the write precedes the claim
    /// here where a Tenderbake mark's runs beside the signature.
    ///
    /// # Errors
    ///
    /// [`WatermarkError::NoEpochCounter`] for a key whose scheme spends no
    /// epochs, [`WatermarkError::EpochNotInitialized`] before a floor exists,
    /// [`WatermarkError::EpochsExhausted`] past the key's last epoch, and an
    /// I/O error where the resume point will not persist.
    pub fn claim_epoch(&mut self, pkh: &PublicKeyHash) -> Result<Epoch> {
        self.ensure_key(pkh)?;
        let injected = self.force_write_error;
        let ad = epoch_ad(self.chain_id);
        let mac_key = *self.mac_key(pkh)?;
        let per_key = self.per_key_mut(pkh)?;
        let epochs = per_key
            .epoch
            .as_mut()
            .ok_or_else(|| no_epoch_counter(pkh))?;
        epochs.claim(pkh, &mac_key, &ad, injected)
    }

    /// Reserve epochs up to `resume_at` ahead of use, so a claim below it costs
    /// no disk write.
    ///
    /// Mirrors [`write_ceiling`](Self::write_ceiling) for epochs: skipped where
    /// the record already reaches `resume_at`, and clamped to the key's range.
    ///
    /// # Errors
    ///
    /// The reasons [`claim_epoch`](Self::claim_epoch) gives, less exhaustion.
    pub fn reserve_epochs(&mut self, pkh: &PublicKeyHash, resume_at: u64) -> Result<()> {
        self.ensure_key(pkh)?;
        let injected = self.force_write_error;
        let ad = epoch_ad(self.chain_id);
        let mac_key = *self.mac_key(pkh)?;
        let per_key = self.per_key_mut(pkh)?;
        let epochs = per_key
            .epoch
            .as_mut()
            .ok_or_else(|| no_epoch_counter(pkh))?;
        epochs.reserve(pkh, &mac_key, &ad, resume_at, injected)
    }

    /// Establish this key's epoch record at `resume_at`, never lowering it.
    ///
    /// The record names epochs already spent, so it only rises: a restored
    /// backup or a second unlock must never hand back an epoch the key has
    /// signed at. `resume_at` is raised to the range's first epoch, so `0`
    /// means wherever this key's range begins — which is what a card carrying
    /// no record yet needs before it can sign at all.
    ///
    /// # Errors
    ///
    /// [`WatermarkError::NoEpochCounter`] for a key whose scheme spends no
    /// epochs, and an I/O error where the record will not persist.
    pub fn seed_epoch_floor(&mut self, pkh: &PublicKeyHash, resume_at: u64) -> Result<()> {
        self.ensure_key(pkh)?;
        let injected = self.force_write_error;
        let ad = epoch_ad(self.chain_id);
        let mac_key = *self.mac_key(pkh)?;
        let per_key = self.per_key_mut(pkh)?;
        let epochs = per_key
            .epoch
            .as_mut()
            .ok_or_else(|| no_epoch_counter(pkh))?;
        epochs.seed(&mac_key, &ad, resume_at, injected)
    }

    /// Whether one signature by this key spends a one-time epoch, as the key's
    /// own secret reported at unlock.
    ///
    /// The sign path asks this rather than reading the scheme, so the fact has
    /// one source: the range [`MarkParams`] was built from.
    #[must_use]
    pub fn spends_epochs(&self, pkh: &PublicKeyHash) -> bool {
        self.key_params
            .get(pkh)
            .is_some_and(|params| params.epochs.is_some())
    }

    /// The next epoch this key would sign at.
    ///
    /// `None` under a scheme that spends no epochs, and for a key whose record
    /// is not established — where the answer is a refusal to sign rather than a
    /// number.
    #[must_use]
    pub fn next_epoch(&self, pkh: &PublicKeyHash) -> Option<u64> {
        Some(self.keys.get(pkh)?.epoch.as_ref()?.cursor?.next)
    }

    /// What this key's epoch counter has left.
    ///
    /// `None` in the two cases [`next_epoch`](Self::next_epoch) answers `None`
    /// for: a scheme spending no epochs, and a record not established, where
    /// what the key has left is unknown rather than zero.
    #[must_use]
    pub fn epoch_budget(&self, pkh: &PublicKeyHash) -> Option<EpochBudget> {
        let epoch = self.keys.get(pkh)?.epoch.as_ref()?;
        Some(EpochBudget::new(&epoch.range, epoch.cursor?.next))
    }

    /// The epoch a reload would resume at, which is the value on stable storage.
    #[must_use]
    pub fn epoch_resume_point(&self, pkh: &PublicKeyHash) -> Option<u64> {
        Some(self.keys.get(pkh)?.epoch.as_ref()?.cursor?.resume_at())
    }

    /// The chain this watermark store is bound to (the provisioned chain).
    #[must_use]
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Get the current in-memory watermark level for a key.
    ///
    /// Returns the highest level from any of the three operation types.
    /// Returns None if no watermark exists.
    #[must_use]
    pub fn get_current_level(&self, _chain_id: ChainId, pkh: &PublicKeyHash) -> Option<u32> {
        self.get_max_level(pkh)
    }

    /// Get the current in-memory watermark level for a key (without chain context).
    ///
    /// Returns the highest level from any of the three operation types.
    /// Returns None if no watermark exists.
    #[must_use]
    pub fn get_max_level(&self, pkh: &PublicKeyHash) -> Option<u32> {
        self.keys
            .get(pkh)?
            .entries
            .iter()
            .filter_map(|e| e.map(|w| w.level))
            .max()
    }

    /// Get the persisted (on-disk) watermark level for a key.
    ///
    /// Returns the highest level from any of the three operation types
    /// that has been confirmed on stable storage via fdatasync.
    /// Returns None if no watermark has been persisted.
    #[must_use]
    pub fn get_persisted_level(&self, pkh: &PublicKeyHash) -> Option<u32> {
        self.keys
            .get(pkh)?
            .disk_entries
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
                    op_type: *op_type,
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

    /// Establish an authenticated floor at `level`, unless an existing valid
    /// mark already sits at or above it.
    ///
    /// Consumes a staged config level after unlock: the device is the sole
    /// producer of authenticated marks, and a recovery boot may already hold a
    /// higher floor that must never be lowered.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is unknown or disk I/O fails.
    pub fn seed_floor(&mut self, chain_id: ChainId, pkh: &PublicKeyHash, level: u32) -> Result<()> {
        self.ensure_key(pkh)?;
        if self
            .get_max_level(pkh)
            .is_some_and(|existing| existing >= level)
        {
            return Ok(());
        }
        self.update_to_level(chain_id, pkh, level)
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

impl PerKeyEpoch {
    /// Open or create a key's epoch record beside its watermark files.
    fn load(
        key_dir: &Path,
        range: RangeInclusive<Epoch>,
        mac_key: &[u8; 32],
        ad: &[u8],
    ) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(key_dir.join(EPOCH_FILENAME))?;
        let cursor = load_epoch_cursor(&file, mac_key, ad)?;
        Ok(Self {
            file,
            range,
            cursor,
        })
    }

    /// Hand out the next unspent epoch, persisting a resume point past it first
    /// where the reservation on disk has run out.
    ///
    /// The cursor advances only after that write returns, so a persist failure
    /// leaves the counter where it was rather than skipping an epoch nothing
    /// recorded.
    fn claim(
        &mut self,
        pkh: &PublicKeyHash,
        mac_key: &[u8; 32],
        ad: &[u8],
        injected: bool,
    ) -> Result<Epoch> {
        let cursor = self.cursor.ok_or_else(|| epoch_not_initialized(pkh))?;
        let last = u64::from(*self.range.end());
        let epoch = Epoch::try_from(cursor.next)
            .ok()
            .filter(|epoch| epoch <= self.range.end())
            .ok_or_else(|| WatermarkError::EpochsExhausted {
                pkh: pkh.to_b58check(),
                next: cursor.next,
                last,
            })?;

        let reserved = if cursor.reserved == 0 {
            let reserving = (last + 1 - cursor.next).min(EPOCH_BURST);
            persist_epoch(&self.file, mac_key, ad, cursor.next + reserving, injected)?;
            reserving
        } else {
            cursor.reserved
        };

        self.cursor = Some(EpochCursor {
            next: cursor.next + 1,
            reserved: reserved - 1,
        });
        Ok(epoch)
    }

    /// Raise the resume point to `resume_at`, ignoring a value the record
    /// already reaches.
    fn reserve(
        &mut self,
        pkh: &PublicKeyHash,
        mac_key: &[u8; 32],
        ad: &[u8],
        resume_at: u64,
        injected: bool,
    ) -> Result<()> {
        let cursor = self.cursor.ok_or_else(|| epoch_not_initialized(pkh))?;
        let target = resume_at.min(u64::from(*self.range.end()) + 1);
        if target <= cursor.resume_at() {
            return Ok(());
        }
        persist_epoch(&self.file, mac_key, ad, target, injected)?;
        self.cursor = Some(EpochCursor {
            reserved: target - cursor.next,
            ..cursor
        });
        Ok(())
    }

    /// Establish the record at `resume_at`, raised to the range's first epoch
    /// and never lowered.
    fn seed(
        &mut self,
        mac_key: &[u8; 32],
        ad: &[u8],
        resume_at: u64,
        injected: bool,
    ) -> Result<()> {
        let target = resume_at
            .max(u64::from(*self.range.start()))
            .min(u64::from(*self.range.end()) + 1);
        if self
            .cursor
            .is_some_and(|cursor| cursor.resume_at() >= target)
        {
            return Ok(());
        }
        persist_epoch(&self.file, mac_key, ad, target, injected)?;
        self.cursor = Some(EpochCursor {
            next: target,
            reserved: 0,
        });
        Ok(())
    }
}

fn no_epoch_counter(pkh: &PublicKeyHash) -> WatermarkError {
    WatermarkError::NoEpochCounter {
        pkh: pkh.to_b58check(),
    }
}

fn epoch_not_initialized(pkh: &PublicKeyHash) -> WatermarkError {
    WatermarkError::EpochNotInitialized {
        pkh: pkh.to_b58check(),
    }
}

/// Width of an epoch record's associated data: a 32-byte chain id and the tag.
const EPOCH_AD_LEN: usize = 32 + EPOCH_AD_TAG.len();

/// Associated data for a key's epoch record: the chain its watermark records
/// already bind to, plus the tag that keeps the two kinds of record in one
/// directory from authenticating as each other.
///
/// Returned by value rather than held on the store, so a claim covered by its
/// reservation builds it on the stack and allocates nothing.
fn epoch_ad(chain_id: ChainId) -> [u8; EPOCH_AD_LEN] {
    let mut ad = [0u8; EPOCH_AD_LEN];
    ad[..32].copy_from_slice(chain_id.as_bytes());
    ad[32..].copy_from_slice(EPOCH_AD_TAG);
    ad
}

/// Write `resume_at` as a key's epoch record and wait for stable storage.
fn persist_epoch(
    file: &File,
    mac_key: &[u8; 32],
    ad: &[u8],
    resume_at: u64,
    injected: bool,
) -> Result<()> {
    let (high, low) = split_resume(resume_at);
    persist(
        file,
        &encode_authenticated(mac_key, ad, high, low),
        injected,
    )
}

/// Read a key's epoch record, or `None` where none authenticates — which is
/// also how an empty file and a forged one read.
fn load_epoch_cursor(
    file: &File,
    mac_key: &[u8; 32],
    ad: &[u8],
) -> io::Result<Option<EpochCursor>> {
    if file.metadata()?.len() != AUTH_FILE_SIZE as u64 {
        return Ok(None);
    }
    let mut buf = [0u8; AUTH_FILE_SIZE];
    file.read_exact_at(&mut buf, 0)?;
    Ok(
        decode_authenticated(mac_key, ad, &buf).map(|(high, low)| EpochCursor {
            next: join_resume(high, low),
            reserved: 0,
        }),
    )
}

/// The resume point rides in the record's two 32-bit slots as (high, low): it
/// can sit one past the last epoch of a range ending at `Epoch::MAX`, which a
/// single slot cannot hold.
fn split_resume(resume_at: u64) -> (u32, u32) {
    let bytes = resume_at.to_be_bytes();
    (
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    )
}

fn join_resume(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

/// Write `buf` at offset 0 and wait for stable storage.
///
/// Every durable record goes through here, so the failure a test injects is
/// selected at one boundary rather than at each persist site.
fn persist(file: &File, buf: &[u8], injected: bool) -> Result<()> {
    if injected {
        return Err(WatermarkError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected write error for testing",
        )));
    }
    // pwrite at offset 0 leaves the handle's position alone, and fdatasync
    // skips metadata because a record's size never changes.
    file.write_all_at(buf, 0)?;
    file.sync_data()?;
    Ok(())
}

/// What `pkh`'s secret told us at unlock, or an error if this tracker was
/// constructed without it.
fn params_for<'a>(
    key_params: &'a HashMap<PublicKeyHash, MarkParams>,
    pkh: &PublicKeyHash,
) -> io::Result<&'a MarkParams> {
    key_params.get(pkh).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no mark parameters for {}", pkh.to_b58check()),
        )
    })
}

/// Load or create per-key watermark files from a directory, verifying each
/// mark's MAC against the key's own MAC key and `ad`.
///
/// A key whose scheme spends an epoch per signature also gets its epoch
/// record, under `epoch_ad`.
fn load_per_key_watermark(
    key_dir: &Path,
    params: &MarkParams,
    ad: &[u8],
    epoch_ad: &[u8],
) -> io::Result<PerKeyWatermark> {
    fs::create_dir_all(key_dir)?;

    let mut files_opt: [Option<File>; 3] = [None, None, None];
    let mut entries: [Option<WatermarkEntry>; 3] = [None, None, None];

    for (i, filename) in FILENAMES.iter().enumerate() {
        let path = key_dir.join(filename);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        entries[i] = load_entry_authenticated(&file, &params.mac_key, ad)?;
        files_opt[i] = Some(file);
    }

    let epoch = params
        .epochs
        .clone()
        .map(|range| PerKeyEpoch::load(key_dir, range, &params.mac_key, epoch_ad))
        .transpose()?;

    Ok(PerKeyWatermark {
        files: [
            files_opt[0].take().unwrap(),
            files_opt[1].take().unwrap(),
            files_opt[2].take().unwrap(),
        ],
        disk_entries: entries,
        entries,
        disk_ceiling: [None; 3],
        epoch,
    })
}

/// Seed the watermark files for a key at the given level (round 0), authenticated
/// under the key's MAC key.
///
/// Creates the per-key subdirectory under `base_dir` and writes all three
/// operation-type watermark files. Required before the first signature:
/// initialization is mandatory. Signing then succeeds only above `level`.
///
/// # Errors
///
/// Returns an error if the directory or a watermark file cannot be written.
pub fn seed_watermarks(
    base_dir: &Path,
    pkh: &PublicKeyHash,
    level: u32,
    mac_key: &[u8; 32],
    chain_id: ChainId,
) -> io::Result<()> {
    let key_dir = base_dir.join(pkh.to_b58check());
    fs::create_dir_all(&key_dir)?;

    let buf = encode_authenticated(mac_key, chain_id.as_bytes(), level, 0);
    for filename in FILENAMES {
        fs::write(key_dir.join(filename), buf)?;
    }
    Ok(())
}

/// Decode a 40-byte prefix into a watermark entry, validating the Blake3 checksum.
/// Only the debug/test read-back path (`load_entry_from_file`) reads a prefix
/// this way, so it shares that cfg and is absent from release builds.
#[cfg(any(debug_assertions, test))]
fn decode_entry(buf: &[u8; FILE_SIZE]) -> Option<WatermarkEntry> {
    let (level, round) = decode_prefix(buf)?;
    Some(WatermarkEntry { level, round })
}

/// Load a watermark entry from an open file handle (pread at offset 0), reading
/// the level/round from the record prefix. Debug/test read-back check only.
#[cfg(any(debug_assertions, test))]
fn load_entry_from_file(file: &File) -> Option<WatermarkEntry> {
    let meta = file.metadata().ok()?;
    if meta.len() != AUTH_FILE_SIZE as u64 {
        return None;
    }
    let mut buf = [0u8; AUTH_FILE_SIZE];
    file.read_exact_at(&mut buf, 0).ok()?;
    let prefix: &[u8; FILE_SIZE] = buf[0..FILE_SIZE].try_into().ok()?;
    decode_entry(prefix)
}

/// Load an authenticated watermark entry.
///
/// Empty → `Ok(None)` (new key). Only a 72-byte record whose MAC verifies against
/// `mac_key`/`ad` yields a floor. Anything else — a forged or corrupt 72-byte
/// record, a legacy or attacker-written unauthenticated record of any other
/// size — resolves to `Ok(None)` so signing-time recovery re-establishes an
/// authenticated floor rather than trusting an unauthenticated value. Trusting
/// a shorter record would be exploitable: a card thief could delete the
/// authenticated file and write a low unauthenticated mark. Only genuine I/O
/// failures return `Err`.
fn load_entry_authenticated(
    file: &File,
    mac_key: &[u8; 32],
    ad: &[u8],
) -> io::Result<Option<WatermarkEntry>> {
    let len = file.metadata()?.len();
    if len != AUTH_FILE_SIZE as u64 {
        return Ok(None);
    }
    let mut buf = [0u8; AUTH_FILE_SIZE];
    file.read_exact_at(&mut buf, 0)?;
    Ok(decode_authenticated(mac_key, ad, &buf)
        .map(|(level, round)| WatermarkEntry { level, round }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::Scheme;
    use crate::test_utils::generate_key;
    use crate::test_utils::{
        create_attestation_data, create_block_data, default_test_chain_id, new_epoch_watermark,
        new_watermark, preinit_watermarks, test_mac_key,
    };
    use tempfile::TempDir;

    /// A tz6 address over repeated bytes. The epoch store needs an address and
    /// a range rather than key material, so no XMSS key is generated here.
    fn tz6(byte: u8) -> PublicKeyHash {
        PublicKeyHash::from_bytes(Scheme::Xmss, &[byte; 20]).expect("20 bytes is a hash")
    }

    /// A range wide enough to outlast a reservation several times over.
    fn epochs() -> RangeInclusive<Epoch> {
        100..=115
    }

    fn create_test_chain_id() -> ChainId {
        default_test_chain_id()
    }

    #[test]
    fn seed_watermarks_initializes_all_files_at_level() {
        let temp_dir = TempDir::new().unwrap();
        let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

        seed_watermarks(
            temp_dir.path(),
            &pkh,
            42,
            &test_mac_key(&pkh),
            default_test_chain_id(),
        )
        .unwrap();

        let hwm = new_watermark(temp_dir.path(), &[pkh])
            .expect("seeded watermarks must satisfy mandatory initialization");
        assert_eq!(hwm.get_persisted_level(&pkh), Some(42));
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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh1, pkh2]).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        for level in [100, 101] {
            let update = hwm
                .check_and_update(chain_id, &pkh, &create_block_data(level, 0))
                .unwrap()
                .expect("a block above the mark advances it");

            assert_eq!(update.level(), level);
            assert_eq!(update.op_type(), OperationType::Block);
            assert_eq!(
                hwm.get_entry(&pkh, OperationType::Block),
                Some(WatermarkEntry { level, round: 0 })
            );
        }
    }

    #[test]
    fn test_reject_signing_at_lower_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        let data1 = create_block_data(100, 0);
        assert!(hwm.check_and_update(chain_id, &pkh, &data1).is_ok());

        let data2 = create_block_data(99, 0);
        let result = hwm.check_and_update(chain_id, &pkh, &data2);
        assert!(matches!(result, Err(WatermarkError::LevelTooLow { .. })));
    }

    #[test]
    fn test_level_progression_at_u32_ceiling() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Seed just below the u32 ceiling so the boundary levels are reachable by
        // forward progression rather than a large gap.
        preinit_watermarks(temp_dir.path(), &pkh, u32::MAX - 2);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        for level in [u32::MAX - 1, u32::MAX] {
            let data = create_block_data(level, 0);
            assert!(
                hwm.check_and_update(chain_id, &pkh, &data)
                    .unwrap()
                    .is_some(),
                "block at level {level} should advance the floor"
            );
        }

        // Floor now sits at u32::MAX; the previous level is below it and rejected.
        let data = create_block_data(u32::MAX - 1, 0);
        assert!(matches!(
            hwm.check_and_update(chain_id, &pkh, &data),
            Err(WatermarkError::LevelTooLow { .. })
        ));
    }

    #[test]
    fn test_allow_signing_at_higher_round_same_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
            let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
            let data = create_block_data(100, 5);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        // Second instance: load from disk and verify
        {
            let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        let data = create_block_data(100, 5);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Read raw file and verify binary format
        let key_dir = temp_dir.path().join(pkh.to_b58check());
        let raw = fs::read(key_dir.join("block_watermark")).unwrap();
        assert_eq!(
            raw.len(),
            AUTH_FILE_SIZE,
            "authenticated watermark file must be exactly 72 bytes"
        );

        let level = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let round = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let computed = blake3::hash(&raw[0..8]);

        assert_eq!(level, 100);
        assert_eq!(round, 5);
        assert_eq!(&raw[8..40], computed.as_bytes(), "Blake3 prefix must match");

        // The trailing MAC verifies under the key's authenticated data.
        let buf: [u8; AUTH_FILE_SIZE] = raw.try_into().unwrap();
        assert_eq!(
            decode_authenticated(
                &test_mac_key(&pkh),
                default_test_chain_id().as_bytes(),
                &buf
            ),
            Some((100, 5))
        );
    }

    /// A wrong-size (corrupt) file is not trusted as a floor; the key loads
    /// uninitialized so signing-time recovery takes over rather than the signer
    /// aborting at startup.
    #[test]
    fn test_corrupt_primary_not_trusted() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let key_dir = temp_dir.path().join(pkh.to_b58check());

        {
            let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
            let data = create_block_data(100, 5);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
        }

        fs::write(key_dir.join("block_watermark"), b"corrupted!!!").unwrap();

        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert!(
            hwm.get_entry(&pkh, OperationType::Block).is_none(),
            "a corrupt block mark must not present a floor"
        );
    }

    /// A 40-byte record with a valid size but a bad checksum is not trusted.
    #[test]
    fn test_corrupt_primary_hash_mismatch_not_trusted() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        let key_dir = temp_dir.path().join(pkh.to_b58check());
        fs::create_dir_all(&key_dir).unwrap();
        let mut bad_buf = [0u8; FILE_SIZE];
        bad_buf[0..4].copy_from_slice(&500u32.to_be_bytes());
        bad_buf[8..FILE_SIZE].fill(0xFF); // valid size, bad checksum
        fs::write(key_dir.join("block_watermark"), bad_buf).unwrap();

        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert!(hwm.get_max_level(&pkh).is_none());
    }

    /// A forged authenticated record (valid checksum, wrong MAC) is not trusted.
    #[test]
    fn test_forged_mac_not_trusted() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        // Seed under a MAC key the loader does not hold.
        seed_watermarks(
            temp_dir.path(),
            &pkh,
            500,
            &[0u8; 32],
            default_test_chain_id(),
        )
        .unwrap();

        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert!(hwm.get_max_level(&pkh).is_none());
    }

    #[test]
    fn chain_id_b58check_roundtrip() {
        let chain_id = default_test_chain_id();
        let decoded = ChainId::from_b58check(&chain_id.to_b58check()).unwrap();
        assert_eq!(decoded.as_bytes(), chain_id.as_bytes());
    }

    #[test]
    fn chain_id_from_b58check_rejects_garbage() {
        assert!(ChainId::from_b58check("not-a-chain-id").is_none());
    }

    /// A legacy 40-byte (unauthenticated) record is not trusted as a floor; the
    /// upgrade re-establishes an authenticated floor through recovery rather than
    /// trusting a forgeable short record.
    #[test]
    fn test_legacy_record_not_trusted() {
        let temp_dir = TempDir::new().unwrap();
        let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

        let key_dir = temp_dir.path().join(pkh.to_b58check());
        fs::create_dir_all(&key_dir).unwrap();
        let legacy = russignol_storage::watermark::encode(4242, 0);
        for filename in FILENAMES {
            fs::write(key_dir.join(filename), legacy).unwrap();
        }

        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert!(hwm.get_max_level(&pkh).is_none());
    }

    /// An unexpected file size (neither 40 nor 72) is not trusted.
    #[test]
    fn test_wrong_file_size_not_trusted() {
        let temp_dir = TempDir::new().unwrap();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        let key_dir = temp_dir.path().join(pkh.to_b58check());
        fs::create_dir_all(&key_dir).unwrap();
        fs::write(key_dir.join("block_watermark"), [0u8; 8]).unwrap();

        let hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert!(hwm.get_max_level(&pkh).is_none());
    }

    /// Seeding a floor for a key with no prior mark establishes an authenticated
    /// floor that reloads under the same MAC key.
    #[test]
    fn seed_floor_establishes_when_absent() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = default_test_chain_id();
        let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert!(hwm.get_max_level(&pkh).is_none());

        hwm.seed_floor(chain_id, &pkh, 1_000).unwrap();
        assert_eq!(hwm.get_max_level(&pkh), Some(1_000));

        let hwm2 = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(hwm2.get_max_level(&pkh), Some(1_000));
    }

    /// Seeding never lowers a higher existing floor.
    #[test]
    fn seed_floor_preserves_higher_existing() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = default_test_chain_id();
        let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 2_000);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        hwm.seed_floor(chain_id, &pkh, 1_000).unwrap();
        assert_eq!(hwm.get_max_level(&pkh), Some(2_000));
    }

    /// Seeding raises a lower existing floor to the proposed level.
    #[test]
    fn seed_floor_raises_below_existing() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = default_test_chain_id();
        let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 500);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        hwm.seed_floor(chain_id, &pkh, 1_000).unwrap();
        assert_eq!(hwm.get_max_level(&pkh), Some(1_000));
    }

    #[test]
    fn test_update_to_level() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let hwm2 = new_watermark(temp_dir.path(), &[pkh]).unwrap();
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
    fn test_preattestation_check_and_update_and_persist() {
        use crate::test_utils::create_preattestation_data;

        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let hwm2 = new_watermark(temp_dir.path(), &[pkh]).unwrap();
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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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

        let hwm2 = new_watermark(temp_dir.path(), &[pkh]).unwrap();
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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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

    /// A watermark file corrupted on the card is replaced by the next write
    /// rather than left to fail every read-back after it, so a card recovers by
    /// signing rather than by re-provisioning. Nothing here reaches the failing
    /// side of that read-back: it compares what `write_watermark` just wrote
    /// against the same file, and only a corruption landing between the two
    /// would separate them.
    #[test]
    fn a_write_over_corrupt_bytes_replaces_them_and_verifies() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .expect("should produce update");
        assert!(hwm.write_watermark(&update).is_ok());

        let corrupt_buf = [0xFFu8; AUTH_FILE_SIZE];
        hwm.get_key_file(&pkh, OperationType::Block)
            .unwrap()
            .write_all_at(&corrupt_buf, 0)
            .unwrap();

        let data2 = create_block_data(101, 0);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data2)
            .unwrap()
            .expect("should produce update");
        assert!(hwm.write_watermark(&update2).is_ok());

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block, 101).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block, 101).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block, 101).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        // Sign at level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();

        // Write ceiling for level 101
        hwm.write_ceiling(pkh, OperationType::Block, 101).unwrap();
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
            let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
            let data = create_block_data(100, 0);
            let update = hwm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap()
                .unwrap();
            hwm.write_watermark(&update).unwrap();
            hwm.write_ceiling(pkh, OperationType::Block, 101).unwrap();
        }

        // Simulate crash — reload from disk.
        // Disk has (101, MAX) ceiling. Reload should see that.
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

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
        hwm.write_ceiling(pkh, OperationType::Block, 101).unwrap();
        assert_eq!(
            hwm.get_disk_ceiling(&pkh, OperationType::Block),
            None,
            "Ceiling at 101 should be skipped when watermark is at 102"
        );

        // Verify disk still has level 102 (not regressed)
        let hwm2 = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm2.get_entry(&pkh, OperationType::Block),
            Some(WatermarkEntry {
                level: 102,
                round: 0
            })
        );
    }

    #[test]
    fn test_write_failure_prevents_advance_and_allows_rollback() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        // Advance in-memory to level 100
        let data = create_block_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();

        // Inject write failure
        hwm.set_write_error(true);
        let write_result = hwm.write_watermark(&update);
        assert!(
            write_result.is_err(),
            "Write should fail with injected error"
        );

        // Roll back in-memory state
        hwm.rollback_update(&update);

        // Verify in-memory state is restored to level 99
        assert_eq!(
            hwm.get_entry(&pkh, OperationType::Block),
            Some(WatermarkEntry {
                level: 99,
                round: 0
            }),
            "In-memory watermark should be rolled back to pre-update state"
        );

        // Verify disk still has level 99
        let hwm2 = new_watermark(temp_dir.path(), &[pkh]).unwrap();
        assert_eq!(
            hwm2.get_entry(&pkh, OperationType::Block),
            Some(WatermarkEntry {
                level: 99,
                round: 0
            }),
            "Disk watermark should remain at original level after write failure"
        );

        // Disable injection and verify retry succeeds
        hwm.set_write_error(false);
        let update2 = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update2).unwrap();
        assert_eq!(
            hwm.get_entry(&pkh, OperationType::Block),
            Some(WatermarkEntry {
                level: 100,
                round: 0
            }),
        );
    }

    #[test]
    fn get_persisted_level_tracks_disk_writes() {
        let temp_dir = TempDir::new().unwrap();
        let chain_id = create_test_chain_id();
        let seed = [42u8; 32];
        let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        // After load, persisted level matches in-memory level
        assert_eq!(hwm.get_persisted_level(&pkh), Some(99));
        assert_eq!(hwm.get_current_level(chain_id, &pkh), Some(99));

        // Advance in-memory (check_and_update) but don't write to disk yet
        let data = create_attestation_data(100, 0);
        let update = hwm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .unwrap();
        assert_eq!(hwm.get_current_level(chain_id, &pkh), Some(100));
        assert_eq!(hwm.get_persisted_level(&pkh), Some(99)); // not yet written

        // Write to disk
        hwm.write_watermark(&update).unwrap();
        assert_eq!(hwm.get_persisted_level(&pkh), Some(100)); // now matches
    }

    /// A card arrives with no epoch record, and a wiped record reads the same
    /// way. Handing out the range's first epoch then would re-sign every epoch
    /// the key has already spent, so the store refuses until a floor exists.
    #[test]
    fn an_epoch_is_refused_until_a_floor_is_established() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(1);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();

        assert!(matches!(
            hwm.claim_epoch(&pkh),
            Err(WatermarkError::EpochNotInitialized { .. })
        ));
        assert_eq!(hwm.next_epoch(&pkh), None);

        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        assert_eq!(hwm.claim_epoch(&pkh).unwrap(), 100);
    }

    /// A reader rotates the key against what is left, so the count runs from
    /// the epoch a claim hands out next rather than from the resume point,
    /// which stands a reservation ahead of anything signed at.
    #[test]
    fn a_budget_counts_down_from_the_epoch_a_claim_hands_out() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(7);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        let budget = hwm.epoch_budget(&pkh).unwrap();
        assert_eq!(budget.total(), 16);
        assert_eq!(budget.remaining(), 16);

        hwm.claim_epoch(&pkh).unwrap();

        let budget = hwm.epoch_budget(&pkh).unwrap();
        assert_eq!(budget.remaining(), 15);
        assert_eq!(budget.total(), 16, "the range does not move as it is spent");
    }

    /// The exhausted key is what the count exists to make visible before it
    /// stops signing, and it reads as nothing left rather than wrapping past
    /// the range's last epoch.
    #[test]
    fn an_exhausted_key_has_nothing_left() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(8);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        for _ in 0..16 {
            hwm.claim_epoch(&pkh).unwrap();
        }

        assert!(matches!(
            hwm.claim_epoch(&pkh),
            Err(WatermarkError::EpochsExhausted { .. })
        ));
        assert_eq!(hwm.epoch_budget(&pkh).unwrap().remaining(), 0);
    }

    /// Nothing to report is not nothing left. A key whose scheme spends no
    /// epochs and one whose record is not established both answer with no
    /// budget, which is what keeps a page from drawing zero left beside a key
    /// that has every epoch it was born with.
    #[test]
    fn a_budget_is_absent_where_no_counter_stands() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(9);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();

        assert_eq!(hwm.epoch_budget(&pkh), None);

        // A refused claim opens the key's record without establishing it,
        // which is the state a wiped or forged one leaves behind.
        assert!(matches!(
            hwm.claim_epoch(&pkh),
            Err(WatermarkError::EpochNotInitialized { .. })
        ));
        assert_eq!(hwm.epoch_budget(&pkh), None);

        let bls_dir = TempDir::new().unwrap();
        let (tz4, ..) = generate_key(Some(&[43u8; 32])).unwrap();
        preinit_watermarks(bls_dir.path(), &tz4, 99);
        let bls = new_watermark(bls_dir.path(), &[tz4]).unwrap();

        assert_eq!(bls.epoch_budget(&tz4), None);
    }

    /// The figure a rotation is scheduled against: the deployed range is 2^24
    /// epochs, and a baker spends a level's three of them every block.
    #[test]
    fn the_days_left_are_the_epochs_spent_at_a_level_a_block() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(10);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, 0..=16_777_215).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        assert_eq!(hwm.epoch_budget(&pkh).unwrap().days_remaining(), 388);
    }

    /// Asking a tz4 key for an epoch is a routing mistake, not an exhausted
    /// range, and says so rather than answering with a number.
    #[test]
    fn a_key_whose_scheme_spends_no_epochs_has_none_to_claim() {
        let temp_dir = TempDir::new().unwrap();
        let (pkh, ..) = generate_key(Some(&[42u8; 32])).unwrap();
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

        assert!(matches!(
            hwm.claim_epoch(&pkh),
            Err(WatermarkError::NoEpochCounter { .. })
        ));
        assert!(matches!(
            hwm.seed_epoch_floor(&pkh, 0),
            Err(WatermarkError::NoEpochCounter { .. })
        ));
        assert_eq!(hwm.next_epoch(&pkh), None);
    }

    /// Two signatures at one epoch disclose the secret key, so no epoch is ever
    /// handed out twice — across a reservation boundary as much as within one.
    #[test]
    fn each_claim_returns_a_strictly_greater_epoch() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(2);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        let claimed: Vec<Epoch> = (0..8).map(|_| hwm.claim_epoch(&pkh).unwrap()).collect();

        assert_eq!(claimed, (100..108).collect::<Vec<Epoch>>());
        assert!(claimed.windows(2).all(|pair| pair[1] > pair[0]));
    }

    /// The resume point on stable storage sits above every epoch that has left
    /// the store, so a crash between a claim and its use costs the epoch rather
    /// than the key.
    #[test]
    fn a_reload_never_returns_an_epoch_already_handed_out() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(3);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        let mut handed_out = Vec::new();
        for _ in 0..5 {
            let epoch = hwm.claim_epoch(&pkh).unwrap();
            handed_out.push(epoch);

            let reloaded = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
            assert!(
                reloaded.next_epoch(&pkh).unwrap() > u64::from(epoch),
                "epoch {epoch} left the store above the durable resume point"
            );
        }
        drop(hwm);

        let mut reloaded = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        let next = reloaded.claim_epoch(&pkh).unwrap();

        assert!(
            handed_out.iter().all(|spent| next > *spent),
            "reload returned {next}, at or below one of {handed_out:?}"
        );
    }

    /// The reservation is what keeps the fsync off the signing path: a claim
    /// inside one persists nothing, so an injected write failure cannot reach
    /// it, and the claim that outruns the reservation fails rather than handing
    /// out an epoch no record covers.
    #[test]
    fn a_claim_inside_a_reservation_writes_nothing() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(4);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        hwm.reserve_epochs(&pkh, 108).unwrap();

        hwm.set_write_error(true);
        for expected in 100..108 {
            assert_eq!(hwm.claim_epoch(&pkh).unwrap(), expected);
        }

        assert!(hwm.claim_epoch(&pkh).is_err());
        assert_eq!(hwm.next_epoch(&pkh), Some(108));
    }

    /// A reservation the record already reaches is not rewritten, and one below
    /// the epoch the key has reached cannot pull the resume point back.
    #[test]
    fn a_reservation_never_lowers_the_resume_point() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(5);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        hwm.reserve_epochs(&pkh, 110).unwrap();

        hwm.set_write_error(true);
        hwm.reserve_epochs(&pkh, 105).unwrap();
        hwm.reserve_epochs(&pkh, 110).unwrap();

        assert_eq!(hwm.epoch_resume_point(&pkh), Some(110));
        assert_eq!(hwm.next_epoch(&pkh), Some(100));
    }

    /// Reserving before a floor exists would establish one at a point no key
    /// chose, so it is refused for the same reason a claim is.
    #[test]
    fn a_reservation_is_refused_before_a_floor_is_established() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(6);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();

        assert!(matches!(
            hwm.reserve_epochs(&pkh, 110),
            Err(WatermarkError::EpochNotInitialized { .. })
        ));
    }

    /// A forged or corrupt record is indistinguishable from a wiped one and
    /// routes to the same refusal: signing resumes only once the device has
    /// written a record it can authenticate.
    #[test]
    fn a_corrupt_epoch_record_reads_as_absent() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(7);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        hwm.claim_epoch(&pkh).unwrap();
        drop(hwm);

        let path = temp_dir.path().join(pkh.to_b58check()).join(EPOCH_FILENAME);
        let mut bytes = fs::read(&path).unwrap();
        bytes[AUTH_FILE_SIZE - 1] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();

        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();

        assert_eq!(hwm.next_epoch(&pkh), None);
        assert!(matches!(
            hwm.claim_epoch(&pkh),
            Err(WatermarkError::EpochNotInitialized { .. })
        ));
    }

    /// A record written under another key's secret reads as absent, so a card
    /// carrying a foreign record fails closed rather than resuming at a floor
    /// its own key never wrote.
    #[test]
    fn an_epoch_record_under_a_foreign_mac_key_reads_as_absent() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(8);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        hwm.claim_epoch(&pkh).unwrap();
        drop(hwm);

        let foreign = HashMap::from([(
            pkh,
            MarkParams {
                mac_key: [0x5A; 32],
                epochs: Some(epochs()),
            },
        )]);
        let mut hwm =
            HighWatermark::new(temp_dir.path(), &[pkh], foreign, default_test_chain_id()).unwrap();

        assert_eq!(hwm.next_epoch(&pkh), None);
        assert!(matches!(
            hwm.claim_epoch(&pkh),
            Err(WatermarkError::EpochNotInitialized { .. })
        ));
    }

    /// The epoch record and the watermark files sit in one directory under one
    /// MAC key, so a card thief who cannot forge a record could still move one
    /// over another. The domain tag is what makes each unreadable as the other.
    #[test]
    fn a_record_of_one_kind_does_not_authenticate_as_the_other() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(9);
        preinit_watermarks(temp_dir.path(), &pkh, 1_500_000);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        drop(hwm);

        let key_dir = temp_dir.path().join(pkh.to_b58check());
        let epoch_record = fs::read(key_dir.join(EPOCH_FILENAME)).unwrap();
        let block_mark = fs::read(key_dir.join(FILENAMES[0])).unwrap();

        fs::write(key_dir.join(EPOCH_FILENAME), &block_mark).unwrap();
        fs::write(key_dir.join(FILENAMES[0]), &epoch_record).unwrap();
        let hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();

        assert_eq!(hwm.next_epoch(&pkh), None, "a mark read as an epoch floor");
        assert_eq!(
            hwm.get_entry(&pkh, OperationType::Block),
            None,
            "an epoch record read as a mark at level 0, round 100"
        );
    }

    /// The record names epochs already spent, so a restore staging an older
    /// floor and a second unlock both leave it where it is.
    #[test]
    fn seeding_never_lowers_an_established_floor() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(10);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        for _ in 0..6 {
            hwm.claim_epoch(&pkh).unwrap();
        }
        let reached = hwm.epoch_resume_point(&pkh).unwrap();

        hwm.seed_epoch_floor(&pkh, 100).unwrap();

        assert_eq!(hwm.epoch_resume_point(&pkh), Some(reached));
        assert_eq!(hwm.claim_epoch(&pkh).unwrap(), 106);
        drop(hwm);

        let hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        assert!(hwm.next_epoch(&pkh).unwrap() >= reached);
    }

    /// A floor staged above where the key stands raises it, which is how a
    /// restored card resumes above every epoch the original ever used.
    #[test]
    fn seeding_above_the_counter_raises_it() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(11);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();
        hwm.claim_epoch(&pkh).unwrap();

        hwm.seed_epoch_floor(&pkh, 112).unwrap();

        assert_eq!(hwm.claim_epoch(&pkh).unwrap(), 112);
    }

    /// Past its last epoch the key has nothing left to sign with, and wrapping
    /// to the start would re-sign every epoch it ever spent.
    #[test]
    fn a_claim_past_the_last_epoch_is_refused() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(12);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, 100..=103).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        let claimed: Vec<Epoch> = (0..4).map(|_| hwm.claim_epoch(&pkh).unwrap()).collect();

        assert_eq!(claimed, vec![100, 101, 102, 103]);
        for _ in 0..2 {
            assert!(matches!(
                hwm.claim_epoch(&pkh),
                Err(WatermarkError::EpochsExhausted {
                    next: 104,
                    last: 103,
                    ..
                })
            ));
        }
    }

    /// A range ending at the last representable epoch needs a resume point one
    /// past it, which is why the record carries the point as 64 bits across its
    /// two 32-bit slots rather than as one.
    #[test]
    fn the_last_epoch_of_the_widest_range_is_usable() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(13);
        let range = (Epoch::MAX - 2)..=Epoch::MAX;
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, range.clone()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        let claimed: Vec<Epoch> = (0..3).map(|_| hwm.claim_epoch(&pkh).unwrap()).collect();

        assert_eq!(claimed, vec![Epoch::MAX - 2, Epoch::MAX - 1, Epoch::MAX]);
        assert_eq!(
            hwm.epoch_resume_point(&pkh),
            Some(u64::from(Epoch::MAX) + 1)
        );
        assert!(matches!(
            hwm.claim_epoch(&pkh),
            Err(WatermarkError::EpochsExhausted { .. })
        ));
        drop(hwm);

        let hwm = new_epoch_watermark(temp_dir.path(), &pkh, range).unwrap();
        assert_eq!(hwm.next_epoch(&pkh), Some(u64::from(Epoch::MAX) + 1));
    }

    /// The epoch counter and the Tenderbake marks are separate mechanisms on one
    /// key: equivocation is slashable whatever key signs it, and an epoch says
    /// nothing about levels.
    #[test]
    fn an_epoch_key_keeps_its_tenderbake_marks() {
        let temp_dir = TempDir::new().unwrap();
        let pkh = tz6(14);
        let chain_id = create_test_chain_id();
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let mut hwm = new_epoch_watermark(temp_dir.path(), &pkh, epochs()).unwrap();
        hwm.seed_epoch_floor(&pkh, 0).unwrap();

        let update = hwm
            .check_and_update(chain_id, &pkh, &create_block_data(100, 0))
            .unwrap()
            .unwrap();
        hwm.write_watermark(&update).unwrap();
        hwm.claim_epoch(&pkh).unwrap();

        assert!(matches!(
            hwm.check_and_update(chain_id, &pkh, &create_block_data(99, 0)),
            Err(WatermarkError::LevelTooLow { .. })
        ));
        assert_eq!(hwm.next_epoch(&pkh), Some(101));
    }
}
