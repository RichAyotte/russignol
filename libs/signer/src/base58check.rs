//! `Base58Check` encoding/decoding for Tezos
//!
//! Tezos uses a custom base58check format similar to Bitcoin's,
//! but with specific prefixes for different key types.

use sha2::{Digest, Sha256};

/// Encode data with base58check (double SHA256 checksum)
#[must_use]
pub fn encode(prefix: &[u8], data: &[u8]) -> String {
    let mut payload = Vec::with_capacity(prefix.len() + data.len() + 4);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(data);

    // Compute double SHA256 checksum
    let checksum = compute_checksum(&payload);
    payload.extend_from_slice(&checksum[..4]);

    bs58::encode(&payload).into_string()
}

/// Decode base58check encoded string
pub fn decode(s: &str, prefix: &[u8]) -> Result<Vec<u8>, String> {
    let decoded = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("Base58 decode error: {e}"))?;

    if decoded.len() < prefix.len() + 4 {
        return Err("Invalid length".to_string());
    }

    // Verify prefix
    if &decoded[..prefix.len()] != prefix {
        return Err("Invalid prefix".to_string());
    }

    // Verify checksum
    let data_end = decoded.len() - 4;
    let data_with_prefix = &decoded[..data_end];
    let checksum = &decoded[data_end..];

    let computed_checksum = compute_checksum(data_with_prefix);
    if checksum != &computed_checksum[..4] {
        return Err("Invalid checksum".to_string());
    }

    // Return data without prefix and checksum
    Ok(decoded[prefix.len()..data_end].to_vec())
}

/// Compute double SHA256 checksum (first 4 bytes)
fn compute_checksum(data: &[u8]) -> [u8; 32] {
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(first_hash);
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&second_hash);
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let prefix = &[0x06, 0xa1, 0xa4]; // tz4 prefix
        let data = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        let encoded = encode(prefix, data);
        let decoded = decode(&encoded, prefix).unwrap();

        assert_eq!(data, &decoded[..]);
    }

    #[test]
    fn test_invalid_checksum() {
        let encoded = "tz4InvalidChecksum";
        let prefix = &[0x06, 0xa1, 0xa4];
        let result = decode(encoded, prefix);
        assert!(result.is_err());
    }
}
