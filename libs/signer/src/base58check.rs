//! `Base58Check` encoding/decoding for Tezos
//!
//! Tezos uses a custom base58check format similar to Bitcoin's,
//! but with specific prefixes for different key types.

use sha2::{Digest, Sha256};

use crate::base58;

/// Encode data with base58check (double SHA256 checksum)
#[must_use]
pub fn encode(prefix: &[u8], data: &[u8]) -> String {
    let mut payload = Vec::with_capacity(prefix.len() + data.len() + 4);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(data);

    let checksum = compute_checksum(&payload);
    payload.extend_from_slice(&checksum[..4]);

    base58::encode(&payload)
}

/// Decode base58check encoded string
///
/// # Errors
///
/// Returns an error if the value is not base58, its checksum does not hold, or
/// it does not carry `prefix`.
pub fn decode(s: &str, prefix: &[u8]) -> Result<Vec<u8>, String> {
    decode_tagged(s, &[(prefix, ())])?
        .map(|((), data)| data)
        .ok_or_else(|| "Invalid prefix".to_string())
}

/// Decode a base58check string whose prefix is one of several candidates.
///
/// `Ok(None)` means the value is well-formed base58check but carries a prefix
/// none of the candidates names, which is a different failure from a corrupt
/// value and the caller reports it as one. Decoding happens once rather than
/// once per candidate, so a secret is never materialized more than necessary.
///
/// # Errors
///
/// Returns an error if the value is not base58 or its checksum does not hold.
pub fn decode_tagged<T: Copy>(
    s: &str,
    candidates: &[(&[u8], T)],
) -> Result<Option<(T, Vec<u8>)>, String> {
    let decoded = base58::decode(s).map_err(|e| format!("Base58 decode error: {e}"))?;

    if decoded.len() < 4 {
        return Err("Invalid length".to_string());
    }

    let data_end = decoded.len() - 4;
    let computed_checksum = compute_checksum(&decoded[..data_end]);
    if decoded[data_end..] != computed_checksum[..4] {
        return Err("Invalid checksum".to_string());
    }

    Ok(candidates
        .iter()
        .find(|(prefix, _)| decoded[..data_end].starts_with(prefix))
        .map(|(prefix, tag)| (*tag, decoded[prefix.len()..data_end].to_vec())))
}

/// The double SHA256 of `data`, whose first four bytes are the base58check
/// checksum.
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

    /// Corrupts the checksum of a value that is otherwise well-formed, so the
    /// rejection cannot come from the alphabet, the length, or the prefix.
    #[test]
    fn test_invalid_checksum() {
        let prefix: &[u8] = &[0x06, 0xa1, 0xa4];
        let encoded = encode(prefix, &[7u8; 20]);

        let mut raw = bs58::decode(&encoded).into_vec().unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let corrupted = bs58::encode(&raw).into_string();

        assert_eq!(decode(&encoded, prefix).unwrap(), vec![7u8; 20]);
        assert_eq!(
            decode(&corrupted, prefix),
            Err("Invalid checksum".to_string())
        );
    }

    /// A well-formed value under a prefix no candidate names is a different
    /// answer from a corrupt one, and the caller reports it differently.
    #[test]
    fn test_decode_tagged_separates_an_unknown_prefix_from_a_corrupt_value() {
        const TZ4: &[u8] = &[0x06, 0xa1, 0xa4];
        const TZ6: &[u8] = &[0x06, 0xa1, 0xab];

        let tz6 = encode(TZ6, &[9u8; 20]);
        assert_eq!(
            decode_tagged(&tz6, &[(TZ4, 0u8)]).unwrap(),
            None,
            "tz6 carries no tz4 prefix"
        );
        assert_eq!(
            decode_tagged(&tz6, &[(TZ4, 0u8), (TZ6, 1u8)]).unwrap(),
            Some((1u8, vec![9u8; 20]))
        );
        assert!(decode_tagged("not base58 at all!", &[(TZ4, 0u8)]).is_err());
    }
}
