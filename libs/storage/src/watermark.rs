/// Size of a watermark file: level (4) + round (4) + blake3 (32)
pub const FILE_SIZE: usize = 40;

/// File names for each operation type, indexed by `OperationType as usize`
pub const FILENAMES: [&str; 3] = [
    "block_watermark",
    "preattestation_watermark",
    "attestation_watermark",
];

/// Encode a watermark entry as 40 bytes: level (4B BE) + round (4B BE) + blake3 (32B)
#[must_use]
pub fn encode(level: u32, round: u32) -> [u8; FILE_SIZE] {
    let mut buf = [0u8; FILE_SIZE];
    buf[0..4].copy_from_slice(&level.to_be_bytes());
    buf[4..8].copy_from_slice(&round.to_be_bytes());
    let hash = blake3::hash(&buf[0..8]);
    buf[8..40].copy_from_slice(hash.as_bytes());
    buf
}

/// Decode a 40-byte buffer into (level, round), validating the blake3 hash.
///
/// Returns `None` if the hash doesn't match.
#[must_use]
pub fn decode(buf: &[u8; FILE_SIZE]) -> Option<(u32, u32)> {
    let level = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let round = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let computed = blake3::hash(&buf[0..8]);
    if buf[8..40] != *computed.as_bytes() {
        return None;
    }
    Some((level, round))
}

/// Size of an authenticated watermark file: the 40-byte record plus a 32-byte
/// keyed MAC.
pub const AUTH_FILE_SIZE: usize = FILE_SIZE + 32;

/// Encode an authenticated watermark: the 40-byte `encode` record followed by a
/// keyed BLAKE3 MAC over `ad ‖ level ‖ round`, binding the mark to caller-chosen
/// associated data (chain id) under a per-key secret. Only a holder of `mac_key`
/// can produce a record `decode_authenticated` accepts.
#[must_use]
pub fn encode_authenticated(
    mac_key: &[u8; 32],
    ad: &[u8],
    level: u32,
    round: u32,
) -> [u8; AUTH_FILE_SIZE] {
    let mut buf = [0u8; AUTH_FILE_SIZE];
    buf[0..FILE_SIZE].copy_from_slice(&encode(level, round));
    let tag = mac(mac_key, ad, &buf[0..8]);
    buf[FILE_SIZE..AUTH_FILE_SIZE].copy_from_slice(tag.as_bytes());
    buf
}

/// Decode a 72-byte authenticated buffer into `(level, round)`, validating both
/// the BLAKE3 corruption checksum and the keyed MAC against `mac_key`/`ad`.
///
/// Returns `None` if either check fails — a forged mark (valid checksum, wrong
/// MAC) is indistinguishable from corruption and routes to the same fail-safe.
#[must_use]
pub fn decode_authenticated(
    mac_key: &[u8; 32],
    ad: &[u8],
    buf: &[u8; AUTH_FILE_SIZE],
) -> Option<(u32, u32)> {
    let prefix: &[u8; FILE_SIZE] = buf[0..FILE_SIZE].try_into().ok()?;
    let (level, round) = decode(prefix)?;
    let expected = mac(mac_key, ad, &buf[0..8]);
    let stored = blake3::Hash::from_bytes(buf[FILE_SIZE..AUTH_FILE_SIZE].try_into().ok()?);
    // blake3::Hash equality is constant-time.
    (expected == stored).then_some((level, round))
}

/// Keyed MAC over `ad ‖ level_round` (the record's first 8 bytes).
fn mac(mac_key: &[u8; 32], ad: &[u8], level_round: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(ad);
    hasher.update(level_round);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAC_KEY: [u8; 32] = [7u8; 32];
    const TEST_AD: &[u8] = b"chain-id-associated-data";

    #[test]
    fn authenticated_roundtrip() {
        let buf = encode_authenticated(&TEST_MAC_KEY, TEST_AD, 1_595_535, 3);
        assert_eq!(
            decode_authenticated(&TEST_MAC_KEY, TEST_AD, &buf),
            Some((1_595_535, 3))
        );
    }

    #[test]
    fn authenticated_rejects_wrong_key() {
        let buf = encode_authenticated(&TEST_MAC_KEY, TEST_AD, 100, 0);
        let wrong = [8u8; 32];
        assert_eq!(decode_authenticated(&wrong, TEST_AD, &buf), None);
    }

    #[test]
    fn authenticated_rejects_wrong_ad() {
        let buf = encode_authenticated(&TEST_MAC_KEY, TEST_AD, 100, 0);
        assert_eq!(
            decode_authenticated(&TEST_MAC_KEY, b"different-chain", &buf),
            None
        );
    }

    #[test]
    fn authenticated_rejects_flipped_mac_byte() {
        let mut buf = encode_authenticated(&TEST_MAC_KEY, TEST_AD, 100, 0);
        buf[AUTH_FILE_SIZE - 1] ^= 0xFF;
        assert_eq!(decode_authenticated(&TEST_MAC_KEY, TEST_AD, &buf), None);
    }

    #[test]
    fn authenticated_rejects_flipped_prefix_byte() {
        let mut buf = encode_authenticated(&TEST_MAC_KEY, TEST_AD, 100, 0);
        buf[0] ^= 0xFF;
        assert_eq!(decode_authenticated(&TEST_MAC_KEY, TEST_AD, &buf), None);
    }

    #[test]
    fn authenticated_prefix_reads_under_keyless_decode() {
        let buf = encode_authenticated(&TEST_MAC_KEY, TEST_AD, 200_000, 5);
        let prefix: &[u8; FILE_SIZE] = buf[0..FILE_SIZE].try_into().unwrap();
        assert_eq!(decode(prefix), Some((200_000, 5)));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let buf = encode(12345, 67);
        let (level, round) = decode(&buf).expect("Should decode valid entry");
        assert_eq!(level, 12345);
        assert_eq!(round, 67);
    }

    #[test]
    fn encode_decode_zero() {
        let buf = encode(0, 0);
        let (level, round) = decode(&buf).expect("Should decode zero entry");
        assert_eq!(level, 0);
        assert_eq!(round, 0);
    }

    #[test]
    fn encode_decode_max_values() {
        let buf = encode(u32::MAX, u32::MAX);
        let (level, round) = decode(&buf).expect("Should decode max entry");
        assert_eq!(level, u32::MAX);
        assert_eq!(round, u32::MAX);
    }

    #[test]
    fn corrupted_hash_returns_none() {
        let mut buf = encode(100, 5);
        buf[39] ^= 0xFF;
        assert!(decode(&buf).is_none(), "Bad hash should be rejected");
    }
}
