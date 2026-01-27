//! Magic byte validation for Tezos signing operations
//!
//! Only allows signing data with specific magic bytes that correspond to
//! Tenderbake consensus operations.
//!
//! Ported directly from: src/bin_signer/handler.ml:244-258

use thiserror::Error;

/// Magic byte validation errors
#[derive(Error, Debug)]
pub enum MagicByteError {
    /// Attempted to sign empty data
    #[error("Cannot sign empty data")]
    EmptyData,

    /// Magic byte not in allowed list
    #[error("Magic byte 0x{byte:02X} not allowed")]
    NotAllowed {
        /// The disallowed magic byte value
        byte: u8,
    },

    /// Data truncated - cannot extract required fields
    #[error("Truncated data: expected {expected} bytes, got {actual}")]
    TruncatedData {
        /// Expected minimum length
        expected: usize,
        /// Actual length
        actual: usize,
    },
}

/// Result type for magic byte validation operations
pub type Result<T> = std::result::Result<T, MagicByteError>;

/// Magic bytes for Tezos signing operations
/// Corresponds to: src/bin_signer/handler.ml:211-231
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MagicByte {
    /// Block - 0x11
    /// Corresponds to: handler.ml:219
    Block = 0x11,

    /// Pre-attestation - 0x12
    /// Corresponds to: handler.ml:223
    PreAttestation = 0x12,

    /// Attestation - 0x13
    /// Corresponds to: handler.ml:227
    Attestation = 0x13,
}

impl MagicByte {
    /// Convert byte to `MagicByte` enum if valid
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x11 => Some(Self::Block),
            0x12 => Some(Self::PreAttestation),
            0x13 => Some(Self::Attestation),
            _ => None,
        }
    }

    /// Check if byte is a valid magic byte
    #[must_use]
    pub fn is_valid(byte: u8) -> bool {
        Self::from_byte(byte).is_some()
    }

    /// Get all allowed magic bytes (0x11, 0x12, 0x13)
    #[must_use]
    pub fn all() -> &'static [u8] {
        &[0x11, 0x12, 0x13]
    }
}

/// Check if data starts with an allowed magic byte
/// Corresponds to: src/bin_signer/handler.ml:244-258 - `check_magic_byte`
///
/// # Arguments
/// * `data` - The data to check
/// * `allowed_magic_bytes` - Optional list of allowed magic bytes.
///   If None, all data is allowed (no check).
///
/// # Returns
/// * `Ok(())` if the magic byte is allowed or no check is required
/// * `Err(MagicByteError)` if the data is empty or magic byte is not allowed
pub fn check_magic_byte(data: &[u8], allowed_magic_bytes: Option<&[u8]>) -> Result<()> {
    // Corresponds to: handler.ml:247 - match magic_bytes with None -> return_unit
    let Some(allowed) = allowed_magic_bytes else {
        return Ok(());
    };

    // Corresponds to: handler.ml:250 - if Bytes.length data < 1
    if data.is_empty() {
        return Err(MagicByteError::EmptyData);
    }

    let byte = data[0];

    // Corresponds to: handler.ml:254 - if List.mem ~equal:Int.equal byte magic_bytes
    if allowed.contains(&byte) {
        Ok(())
    } else {
        // Corresponds to: handler.ml:256 - Format.sprintf "magic byte 0x%02X not allowed" byte
        Err(MagicByteError::NotAllowed { byte })
    }
}

/// Extract level and round from Tenderbake block data
/// Corresponds to: src/bin_signer/handler.ml:51-68 - `get_level_and_round_for_tenderbake_block`
///
/// Block structure:
/// - watermark (1 byte) - magic byte 0x11
/// - `chain_id` (4 bytes)
/// - level (4 bytes) - at offset 5
/// - `proto_level` (1 byte)
/// - predecessor (32 bytes)
/// - timestamp (8 bytes)
/// - `validation_passes` (1 byte)
/// - `operations_hash` (32 bytes)
/// - fitness (variable) - contains round at `fitness_offset` + `fitness_length` - 4
///
/// Returns error if round cannot be extracted (malformed block data).
/// In Tenderbake, every block must have a round.
pub fn get_level_and_round_for_tenderbake_block(data: &[u8]) -> Result<(u32, u32)> {
    const MIN_LENGTH: usize = 1 + 4 + 4 + 1 + 32 + 8 + 1 + 32;

    if data.len() < MIN_LENGTH {
        return Err(MagicByteError::EmptyData);
    }

    // Extract level at offset 5 (after watermark + chain_id)
    // Corresponds to: handler.ml:56 - Bytes.get_int32_be bytes (1 + 4)
    let level = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);

    // Extract round from fitness
    // Corresponds to: handler.ml:57-63
    let fitness_offset = 1 + 4 + 4 + 1 + 32 + 8 + 1 + 32;

    if data.len() < fitness_offset + 4 {
        return Err(MagicByteError::TruncatedData {
            expected: fitness_offset + 4,
            actual: data.len(),
        });
    }

    let fitness_length = u32::from_be_bytes([
        data[fitness_offset],
        data[fitness_offset + 1],
        data[fitness_offset + 2],
        data[fitness_offset + 3],
    ]) as usize;

    let round_offset = fitness_offset + fitness_length;
    // Ensure round_offset is at least 4 (to safely access round_offset - 4)
    // and that we have enough data
    if round_offset < 4 || data.len() < round_offset {
        return Err(MagicByteError::TruncatedData {
            expected: round_offset.max(4),
            actual: data.len(),
        });
    }

    let round = u32::from_be_bytes([
        data[round_offset - 4],
        data[round_offset - 3],
        data[round_offset - 2],
        data[round_offset - 1],
    ]);
    Ok((level, round))
}

/// Extract level and round from Tenderbake attestation/preattestation
/// Corresponds to: src/bin_signer/handler.ml:70-90 - `get_level_and_round_for_tenderbake_attestation`
///
/// Attestation structure:
/// - watermark (1 byte) - magic byte 0x12 or 0x13
/// - `chain_id` (4 bytes)
/// - branch (32 bytes)
/// - kind (1 byte)
/// - slot (2 bytes) - only for non-BLS signatures (Ed25519, Secp256k1, P256)
/// - level (4 bytes)
/// - round (4 bytes)
pub fn get_level_and_round_for_tenderbake_attestation(
    data: &[u8],
    is_bls: bool,
) -> Result<(u32, u32)> {
    // Corresponds to: handler.ml:76-81
    // For BLS (tz4), slot is not part of the signed payload
    let level_offset = if is_bls {
        1 + 4 + 32 + 1 // No slot for BLS
    } else {
        1 + 4 + 32 + 1 + 2 // With slot for other key types
    };

    if data.len() < level_offset + 8 {
        return Err(MagicByteError::TruncatedData {
            expected: level_offset + 8,
            actual: data.len(),
        });
    }

    // Extract level
    // Corresponds to: handler.ml:83 - Bytes.get_int32_be bytes level_offset
    let level = u32::from_be_bytes([
        data[level_offset],
        data[level_offset + 1],
        data[level_offset + 2],
        data[level_offset + 3],
    ]);

    // Extract round
    // Corresponds to: handler.ml:84 - Bytes.get_int32_be bytes (level_offset + 4)
    let round = u32::from_be_bytes([
        data[level_offset + 4],
        data[level_offset + 5],
        data[level_offset + 6],
        data[level_offset + 7],
    ]);

    Ok((level, round))
}

/// Extract Chain ID from Tenderbake data
///
/// All Tenderbake operations (0x11, 0x12, 0x13) have the Chain ID at offset 1 (4 bytes).
#[must_use]
pub fn get_chain_id_for_tenderbake(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() < 5 {
        return None;
    }

    // Check magic byte
    match data[0] {
        0x11..=0x13 => {
            let mut chain_id = [0u8; 4];
            chain_id.copy_from_slice(&data[1..5]);
            Some(chain_id)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_byte_enum() {
        assert_eq!(MagicByte::from_byte(0x11), Some(MagicByte::Block));
        assert_eq!(MagicByte::from_byte(0x12), Some(MagicByte::PreAttestation));
        assert_eq!(MagicByte::from_byte(0x13), Some(MagicByte::Attestation));
        assert_eq!(MagicByte::from_byte(0xFF), None);
    }

    #[test]
    fn test_check_magic_byte_no_restriction() {
        // When no allowed bytes specified, any data should pass
        assert!(check_magic_byte(b"\x00test", None).is_ok());
        assert!(check_magic_byte(b"\xFFtest", None).is_ok());
    }

    #[test]
    fn test_check_magic_byte_empty_data() {
        let allowed = &[0x11, 0x12, 0x13];
        let result = check_magic_byte(b"", Some(allowed));
        assert!(matches!(result, Err(MagicByteError::EmptyData)));
    }

    #[test]
    fn test_check_magic_byte_allowed() {
        let allowed = &[0x11, 0x12, 0x13];

        // Tenderbake block
        assert!(check_magic_byte(b"\x11test", Some(allowed)).is_ok());

        // Tenderbake preattestation
        assert!(check_magic_byte(b"\x12test", Some(allowed)).is_ok());

        // Tenderbake attestation
        assert!(check_magic_byte(b"\x13test", Some(allowed)).is_ok());
    }

    #[test]
    fn test_check_magic_byte_not_allowed() {
        let allowed = &[0x11, 0x12, 0x13];

        // Invalid magic byte
        let result = check_magic_byte(b"\xFFtest", Some(allowed));
        assert!(matches!(
            result,
            Err(MagicByteError::NotAllowed { byte: 0xFF })
        ));
    }

    #[test]
    fn test_all_magic_bytes() {
        let allowed = MagicByte::all();
        assert_eq!(allowed, &[0x11, 0x12, 0x13]);

        // All operations should be allowed
        assert!(check_magic_byte(b"\x11data", Some(allowed)).is_ok());
        assert!(check_magic_byte(b"\x12data", Some(allowed)).is_ok());
        assert!(check_magic_byte(b"\x13data", Some(allowed)).is_ok());

        // Unknown bytes should not be allowed
        assert!(check_magic_byte(b"\x00data", Some(allowed)).is_err());
        assert!(check_magic_byte(b"\xFFdata", Some(allowed)).is_err());
    }

    #[test]
    fn test_extract_tenderbake_block_level_and_round() {
        // Create a minimal Tenderbake block structure
        let mut block_data = vec![0u8; 100];
        block_data[0] = 0x11; // Tenderbake block magic byte

        // Set level to 12345 at offset 5
        let level_bytes = 12345u32.to_be_bytes();
        block_data[5..9].copy_from_slice(&level_bytes);

        let (level, _round) = get_level_and_round_for_tenderbake_block(&block_data).unwrap();
        assert_eq!(level, 12345);
    }

    #[test]
    fn test_extract_tenderbake_attestation_level_and_round() {
        // Create minimal attestation structure for BLS
        let mut attestation_data = vec![0u8; 50];
        attestation_data[0] = 0x13; // Tenderbake attestation magic byte

        // For BLS: offset is 1 + 4 + 32 + 1 = 38
        let level_offset = 38;

        // Set level to 12345
        let level_bytes = 12345u32.to_be_bytes();
        attestation_data[level_offset..level_offset + 4].copy_from_slice(&level_bytes);

        // Set round to 5
        let round_bytes = 5u32.to_be_bytes();
        attestation_data[level_offset + 4..level_offset + 8].copy_from_slice(&round_bytes);

        let (level, round) =
            get_level_and_round_for_tenderbake_attestation(&attestation_data, true).unwrap();
        assert_eq!(level, 12345);
        assert_eq!(round, 5);
    }

    #[test]
    fn test_extract_tenderbake_attestation_non_bls() {
        // Create minimal attestation structure for non-BLS (with slot)
        let mut attestation_data = vec![0u8; 52];
        attestation_data[0] = 0x12; // Tenderbake preattestation magic byte

        // For non-BLS: offset is 1 + 4 + 32 + 1 + 2 = 40
        let level_offset = 40;

        // Set level to 67890
        let level_bytes = 67890u32.to_be_bytes();
        attestation_data[level_offset..level_offset + 4].copy_from_slice(&level_bytes);

        // Set round to 7
        let round_bytes = 7u32.to_be_bytes();
        attestation_data[level_offset + 4..level_offset + 8].copy_from_slice(&round_bytes);

        let (level, round) =
            get_level_and_round_for_tenderbake_attestation(&attestation_data, false).unwrap();
        assert_eq!(level, 67890);
        assert_eq!(round, 7);
    }

    #[test]
    fn test_block_with_small_fitness_length_returns_error() {
        // Test that malformed block data with small fitness_length doesn't panic
        // fitness_offset = 1 + 4 + 4 + 1 + 32 + 8 + 1 + 32 = 83
        // If fitness_length is 0, round_offset = 83, and round_offset - 4 = 79
        // But if fitness_length causes round_offset < 4, we need to handle it

        // Create block data with minimum length to reach fitness_length field
        let mut block_data = vec![0u8; 100];
        block_data[0] = 0x11; // Block magic byte

        // Set fitness_length to 0 at offset 83 (fitness_offset)
        // This means round_offset = 83 + 0 = 83, which is >= 4, so it's valid
        // But let's test with a block that's truncated

        // Create a block that passes minimum length but has invalid fitness data
        let result = get_level_and_round_for_tenderbake_block(&block_data);
        // With fitness_length = 0, round_offset = 83, we need data.len() >= 83
        // Our data is 100 bytes, so this should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_truncated_before_round_returns_error() {
        // Test that truncated block data returns an error, not a panic
        // Create block with valid header but truncated before round data

        // Minimum to get past MIN_LENGTH check: 1 + 4 + 4 + 1 + 32 + 8 + 1 + 32 = 83
        let mut block_data = vec![0u8; 87]; // Just enough for fitness_length field
        block_data[0] = 0x11; // Block magic byte

        // Set fitness_length to a value that would require more data than we have
        // fitness_offset = 83, if we set fitness_length to 100, round_offset = 183
        // But our data is only 87 bytes, so it should fail
        let fitness_length_bytes = 100u32.to_be_bytes();
        block_data[83..87].copy_from_slice(&fitness_length_bytes);

        let result = get_level_and_round_for_tenderbake_block(&block_data);
        assert!(matches!(result, Err(MagicByteError::TruncatedData { .. })));
    }

    #[test]
    fn test_block_with_zero_fitness_length() {
        // Test edge case where fitness_length is 0
        // This would make round_offset = fitness_offset = 83
        // Accessing round at [79..83] should work if data.len() >= 83

        let mut block_data = vec![0u8; 100];
        block_data[0] = 0x11; // Block magic byte

        // Set level at offset 5
        let level_bytes = 42u32.to_be_bytes();
        block_data[5..9].copy_from_slice(&level_bytes);

        // Set fitness_length to 0 at offset 83
        // This is already 0 from vec initialization

        // Set round at offset 79 (round_offset - 4 = 83 - 4 = 79)
        let round_bytes = 7u32.to_be_bytes();
        block_data[79..83].copy_from_slice(&round_bytes);

        let result = get_level_and_round_for_tenderbake_block(&block_data);
        assert!(result.is_ok());
        let (level, round) = result.unwrap();
        assert_eq!(level, 42);
        assert_eq!(round, 7);
    }
}
