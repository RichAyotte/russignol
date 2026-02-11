use std::time::{Duration, SystemTime};

/// Type of signing operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// Block signing (magic byte 0x11)
    Block,
    /// Pre-attestation (magic byte 0x12)
    PreAttestation,
    /// Attestation (magic byte 0x13)
    Attestation,
}

impl OperationType {
    /// Extract operation type from magic byte
    /// Returns None for unrecognized magic bytes (only 0x11, 0x12, 0x13 are valid)
    #[must_use]
    pub fn from_magic_byte(magic: u8) -> Option<Self> {
        match magic {
            0x11 => Some(OperationType::Block),
            0x12 => Some(OperationType::PreAttestation),
            0x13 => Some(OperationType::Attestation),
            _ => None,
        }
    }

    /// Get display string
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            OperationType::Block => "signed",
            OperationType::PreAttestation => "pre-attested",
            OperationType::Attestation => "attested",
        }
    }
}

/// Extract chain ID from block data (bytes 1-4)
#[must_use]
pub fn extract_chain_id(data: &[u8]) -> Option<[u8; 4]> {
    // Block format: [magic_byte:1][chain_id:4][level:4][...]
    if data.len() >= 5 && data[0] == 0x11 {
        Some([data[1], data[2], data[3], data[4]])
    } else {
        None
    }
}

/// Information about the last signature request for a specific key
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SignatureActivity {
    /// Block level (if available)
    pub level: Option<u32>,
    /// Timestamp of the signature request
    pub timestamp: SystemTime,
    /// Duration of the signing operation
    pub duration: Option<Duration>,
    /// Type of operation (block, attestation, etc.)
    pub operation_type: Option<OperationType>,
    /// Size of data signed (in bytes)
    pub data_size: Option<usize>,
}

impl Default for SignatureActivity {
    fn default() -> Self {
        Self {
            level: None,
            timestamp: SystemTime::UNIX_EPOCH,
            duration: None,
            operation_type: None,
            data_size: None,
        }
    }
}

/// Which key was used for signing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Consensus key
    Consensus,
    /// Companion key
    Companion,
}

/// A single signing event with key type and activity details
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SigningEvent {
    /// Which key was used
    pub key_type: KeyType,
    /// Activity details for this signing event
    pub activity: SignatureActivity,
}

/// Fixed-size ring buffer of signing events (capacity 5, matching display rows)
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SigningEventRing {
    events: [Option<SigningEvent>; 5],
    head: u8,
    len: u8,
}

impl SigningEventRing {
    /// Push a new event into the ring buffer, overwriting the oldest if full
    pub fn push(&mut self, event: SigningEvent) {
        self.events[self.head as usize % 5] = Some(event);
        self.head = (self.head + 1) % 5;
        if self.len < 5 {
            self.len += 1;
        }
    }

    /// Iterate over events oldest-first
    pub fn iter(&self) -> impl Iterator<Item = &SigningEvent> {
        let len = self.len as usize;
        let head = self.head as usize;
        (0..len).filter_map(move |i| {
            let idx = (head + 5 - len + i) % 5;
            self.events[idx].as_ref()
        })
    }
}

/// Tracks signature activity for consensus and companion keys
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SigningActivity {
    /// Last signature activity for consensus key
    pub consensus: Option<SignatureActivity>,
    /// Last signature activity for companion key
    pub companion: Option<SignatureActivity>,
    /// Chain ID detected from signature requests (first 4 bytes after magic byte)
    pub chain_id: Option<[u8; 4]>,
    /// Recent signing events (ring buffer, newest last)
    pub recent_events: SigningEventRing,
}

impl SigningActivity {
    /// Check if we've had any activity within the last N seconds
    #[must_use]
    pub fn has_recent_activity(&self, seconds: u64) -> bool {
        let now = SystemTime::now();

        let check_activity = |activity: &Option<SignatureActivity>| {
            if let Some(act) = activity
                && let Ok(elapsed) = now.duration_since(act.timestamp)
            {
                return elapsed.as_secs() < seconds;
            }
            false
        };

        check_activity(&self.consensus) || check_activity(&self.companion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_magic_byte_valid() {
        assert_eq!(
            OperationType::from_magic_byte(0x11),
            Some(OperationType::Block)
        );
        assert_eq!(
            OperationType::from_magic_byte(0x12),
            Some(OperationType::PreAttestation)
        );
        assert_eq!(
            OperationType::from_magic_byte(0x13),
            Some(OperationType::Attestation)
        );
    }

    #[test]
    fn test_from_magic_byte_invalid_returns_none() {
        // Invalid magic bytes should return None, not panic
        assert_eq!(OperationType::from_magic_byte(0x00), None);
        assert_eq!(OperationType::from_magic_byte(0x10), None);
        assert_eq!(OperationType::from_magic_byte(0x14), None);
        assert_eq!(OperationType::from_magic_byte(0xFF), None);
    }

    #[test]
    fn test_from_magic_byte_boundary_values() {
        // Test values just below and above valid range
        assert_eq!(OperationType::from_magic_byte(0x10), None);
        assert_eq!(
            OperationType::from_magic_byte(0x11),
            Some(OperationType::Block)
        );
        assert_eq!(
            OperationType::from_magic_byte(0x13),
            Some(OperationType::Attestation)
        );
        assert_eq!(OperationType::from_magic_byte(0x14), None);
    }

    #[test]
    fn test_extract_chain_id_valid_block() {
        // Valid block data: magic(0x11) + chain_id(4 bytes) + ...
        let data = vec![0x11, 0x7a, 0x06, 0xa7, 0x70, 0x00, 0x00, 0x00, 0x01];
        let chain_id = extract_chain_id(&data);
        assert_eq!(chain_id, Some([0x7a, 0x06, 0xa7, 0x70])); // Mainnet chain ID
    }

    #[test]
    fn test_extract_chain_id_wrong_magic_byte() {
        // Attestation magic byte (0x13) - extract_chain_id only works for blocks
        let data = vec![0x13, 0x7a, 0x06, 0xa7, 0x70, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(extract_chain_id(&data), None);
    }

    #[test]
    fn test_extract_chain_id_too_short() {
        // Less than 5 bytes
        let data = vec![0x11, 0x7a, 0x06, 0xa7];
        assert_eq!(extract_chain_id(&data), None);
    }

    #[test]
    fn test_extract_chain_id_empty_data() {
        let data: Vec<u8> = vec![];
        assert_eq!(extract_chain_id(&data), None);
    }

    #[test]
    fn test_extract_chain_id_exactly_5_bytes() {
        // Minimum valid length
        let data = vec![0x11, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(extract_chain_id(&data), Some([0x01, 0x02, 0x03, 0x04]));
    }

    #[test]
    fn test_has_recent_activity_no_activity() {
        let activity = SigningActivity::default();
        assert!(!activity.has_recent_activity(60));
    }

    #[test]
    fn test_has_recent_activity_recent_consensus() {
        let activity = SigningActivity {
            consensus: Some(SignatureActivity {
                level: Some(100),
                timestamp: SystemTime::now(),
                duration: None,
                operation_type: Some(OperationType::Block),
                data_size: None,
            }),
            ..Default::default()
        };

        assert!(activity.has_recent_activity(60));
    }

    #[test]
    fn test_has_recent_activity_recent_companion() {
        let activity = SigningActivity {
            companion: Some(SignatureActivity {
                level: Some(100),
                timestamp: SystemTime::now(),
                duration: None,
                operation_type: Some(OperationType::Attestation),
                data_size: None,
            }),
            ..Default::default()
        };

        assert!(activity.has_recent_activity(60));
    }

    #[test]
    fn test_has_recent_activity_old_activity() {
        let activity = SigningActivity {
            consensus: Some(SignatureActivity {
                level: Some(100),
                // 120 seconds ago
                timestamp: SystemTime::now() - Duration::from_secs(120),
                duration: None,
                operation_type: Some(OperationType::Block),
                data_size: None,
            }),
            ..Default::default()
        };

        // Should not be considered recent if threshold is 60 seconds
        assert!(!activity.has_recent_activity(60));
        // But should be recent if threshold is 180 seconds
        assert!(activity.has_recent_activity(180));
    }

    #[test]
    fn test_has_recent_activity_epoch_timestamp() {
        let activity = SigningActivity {
            consensus: Some(SignatureActivity {
                level: Some(100),
                timestamp: SystemTime::UNIX_EPOCH, // Very old timestamp
                duration: None,
                operation_type: None,
                data_size: None,
            }),
            ..Default::default()
        };

        assert!(!activity.has_recent_activity(60));
    }

    #[test]
    fn test_operation_type_as_str() {
        assert_eq!(OperationType::Block.as_str(), "signed");
        assert_eq!(OperationType::PreAttestation.as_str(), "pre-attested");
        assert_eq!(OperationType::Attestation.as_str(), "attested");
    }

    fn make_event(key_type: KeyType, level: u32) -> SigningEvent {
        SigningEvent {
            key_type,
            activity: SignatureActivity {
                level: Some(level),
                timestamp: SystemTime::now(),
                duration: Some(Duration::from_millis(42)),
                operation_type: Some(OperationType::Attestation),
                data_size: Some(128),
            },
        }
    }

    #[test]
    fn ring_empty_iterates_to_nothing() {
        let ring = SigningEventRing::default();
        assert_eq!(ring.iter().count(), 0);
    }

    #[test]
    fn ring_push_and_iterate_roundtrip() {
        let mut ring = SigningEventRing::default();
        let e1 = make_event(KeyType::Consensus, 100);
        let e2 = make_event(KeyType::Companion, 101);
        ring.push(e1);
        ring.push(e2);

        let events: Vec<_> = ring.iter().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].activity.level, Some(100));
        assert_eq!(events[1].activity.level, Some(101));
    }

    #[test]
    fn ring_push_exactly_5_returns_all_in_order() {
        let mut ring = SigningEventRing::default();
        for level in 1..=5 {
            ring.push(make_event(KeyType::Consensus, level));
        }

        let levels: Vec<_> = ring.iter().map(|e| e.activity.level.unwrap()).collect();
        assert_eq!(levels, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn ring_overflow_drops_oldest_preserves_newest() {
        let mut ring = SigningEventRing::default();
        for level in 1..=7 {
            ring.push(make_event(KeyType::Consensus, level));
        }

        let levels: Vec<_> = ring.iter().map(|e| e.activity.level.unwrap()).collect();
        assert_eq!(levels, vec![3, 4, 5, 6, 7]);
    }
}
