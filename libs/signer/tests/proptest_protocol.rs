//! Property-based tests for protocol parsing using proptest
//!
//! These tests verify that the protocol parser:
//! 1. Never panics on any input (crash safety)
//! 2. Correctly roundtrips valid messages
//! 3. Properly rejects malformed input
//!
//! Unlike cargo-fuzz (which requires nightly), proptest works on stable Rust
//! and integrates with normal test infrastructure.

use proptest::prelude::*;
use russignol_signer_lib::bls::{PublicKeyHash, generate_key};
use russignol_signer_lib::magic_bytes::{
    MagicByte, get_chain_id_for_tenderbake, get_level_and_round_for_tenderbake_attestation,
    get_level_and_round_for_tenderbake_block,
};
use russignol_signer_lib::protocol::SignerRequest;
use russignol_signer_lib::protocol::encoding::{decode_request, decode_response, encode_request};

// ============================================================================
// Protocol Parsing - Crash Safety
// ============================================================================

proptest! {
    /// Test that decode_request never panics on arbitrary bytes
    #[test]
    fn decode_request_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        // This should ALWAYS return Ok or Err, never panic
        let _ = decode_request(&data);
    }

    /// Test with various message sizes, including edge cases
    #[test]
    fn decode_request_handles_edge_sizes(
        data in prop::collection::vec(any::<u8>(), 0..65536)
    ) {
        let _ = decode_request(&data);
    }

    /// Test decode_response with various request types
    #[test]
    fn decode_response_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..1024),
        request_tag in 0u8..=7u8
    ) {
        // Create a dummy request to provide context
        // Note: Sign, DeterministicNonce, DeterministicNonceHash use VersionedPublicKeyHash = (PublicKeyHash, u8)
        let request = match request_tag {
            0 => SignerRequest::Sign {
                pkh: create_versioned_pkh(42),
                data: vec![0x11],
                signature: None,
            },
            1 => SignerRequest::PublicKey {
                pkh: create_test_pkh(42),
            },
            2 => SignerRequest::AuthorizedKeys,
            3 => SignerRequest::DeterministicNonce {
                pkh: create_versioned_pkh(42),
                data: vec![],
                signature: None,
            },
            4 => SignerRequest::DeterministicNonceHash {
                pkh: create_versioned_pkh(42),
                data: vec![],
                signature: None,
            },
            5 => SignerRequest::SupportsDeterministicNonces {
                pkh: create_test_pkh(42),
            },
            6 => SignerRequest::KnownKeys,
            _ => SignerRequest::BlsProveRequest {
                pkh: create_test_pkh(42),
                override_pk: None,
            },
        };

        let _ = decode_response(&data, &request);
    }
}

// ============================================================================
// Magic Bytes - Crash Safety
// ============================================================================

proptest! {
    /// Test magic byte parsing never panics
    #[test]
    fn magic_byte_parsing_never_panics(data in prop::collection::vec(any::<u8>(), 0..256)) {
        // None of these should panic
        let _ = get_chain_id_for_tenderbake(&data);
        let _ = get_level_and_round_for_tenderbake_block(&data);
        let _ = get_level_and_round_for_tenderbake_attestation(&data, true);
        let _ = get_level_and_round_for_tenderbake_attestation(&data, false);

        if !data.is_empty() {
            let _ = MagicByte::from_byte(data[0]);
        }
    }

    /// Test with block-like data structures
    #[test]
    fn magic_byte_block_parsing(
        magic in prop::sample::select(vec![0x11u8, 0x12, 0x13, 0x00, 0xFF]),
        chain_id in prop::array::uniform4(any::<u8>()),
        level in any::<u32>(),
        padding in prop::collection::vec(any::<u8>(), 0..200)
    ) {
        let mut data = vec![magic];
        data.extend_from_slice(&chain_id);
        data.extend_from_slice(&level.to_be_bytes());
        data.extend_from_slice(&padding);

        // Should not panic regardless of content
        let _ = get_level_and_round_for_tenderbake_block(&data);
        let _ = get_chain_id_for_tenderbake(&data);
    }
}

// ============================================================================
// Protocol Roundtrip Tests
// ============================================================================

proptest! {
    /// Test that valid Sign requests roundtrip correctly
    #[test]
    fn sign_request_roundtrips(
        seed in prop::array::uniform32(any::<u8>()),
        payload in prop::collection::vec(any::<u8>(), 1..1000),
        version in any::<u8>()
    ) {
        // Skip seeds that produce invalid BLS keys
        let Some(pkh) = try_create_pkh(&seed) else {
            return Ok(());
        };

        let original = SignerRequest::Sign {
            pkh: (pkh, version),
            data: payload,
            signature: None,
        };

        let encoded = encode_request(&original).unwrap();
        let decoded = decode_request(&encoded).unwrap();

        // Verify roundtrip
        match decoded {
            SignerRequest::Sign { pkh: d_pkh, data: d_data, signature: d_sig } => {
                prop_assert_eq!(original_versioned_pkh_bytes(&original), versioned_pkh_bytes(&d_pkh));
                prop_assert_eq!(original_data(&original), d_data);
                prop_assert!(d_sig.is_none());
            }
            _ => prop_assert!(false, "Expected Sign request after roundtrip"),
        }
    }

    /// Test AuthorizedKeys request roundtrips
    #[test]
    fn authorized_keys_roundtrips(_dummy: u8) {
        let original = SignerRequest::AuthorizedKeys;
        let encoded = encode_request(&original).unwrap();
        let decoded = decode_request(&encoded).unwrap();

        prop_assert!(matches!(decoded, SignerRequest::AuthorizedKeys));
    }

    /// Test KnownKeys request roundtrips
    #[test]
    fn known_keys_roundtrips(_dummy: u8) {
        let original = SignerRequest::KnownKeys;
        let encoded = encode_request(&original).unwrap();
        let decoded = decode_request(&encoded).unwrap();

        prop_assert!(matches!(decoded, SignerRequest::KnownKeys));
    }
}

// ============================================================================
// Edge Cases - Length Fields
// ============================================================================

proptest! {
    /// Test handling of malicious length prefixes
    #[test]
    fn handles_malicious_length_prefix(
        tag in 0u8..=7u8,
        length_bytes in prop::array::uniform4(any::<u8>()),
        extra in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        // Craft a message with potentially malicious length field
        let mut data = vec![tag];

        // For Sign request (tag 0), add PKH header then length
        if tag == 0 {
            // Version byte + tag + 20 bytes PKH
            data.push(0x00); // version
            data.push(0x03); // BLS PKH tag
            data.extend_from_slice(&[0u8; 20]); // dummy PKH
            // Now the length field for the data payload
            data.extend_from_slice(&length_bytes);
        }

        data.extend_from_slice(&extra);

        // Should handle gracefully, never panic
        let _ = decode_request(&data);
    }

    /// Test truncated messages at various points
    #[test]
    fn handles_truncated_messages(
        full_data in prop::collection::vec(any::<u8>(), 1..100),
        truncate_at in 0usize..100
    ) {
        let truncated: Vec<u8> = full_data.into_iter().take(truncate_at).collect();
        // Should return an error for truncated data, not panic
        let _ = decode_request(&truncated);
    }
}

// ============================================================================
// Base58 Parsing
// ============================================================================

proptest! {
    /// Test base58 parsing with random strings
    #[test]
    fn base58_parsing_never_panics(s in "\\PC*") {
        // Random printable strings should not panic when parsed
        let _ = PublicKeyHash::from_b58check(&s);
    }

    /// Test with strings that look like Tezos addresses
    #[test]
    fn tezos_like_addresses(
        prefix in prop::sample::select(vec!["tz1", "tz2", "tz3", "tz4", "KT1", ""]),
        suffix in "[A-Za-z0-9]{1,50}"
    ) {
        let address = format!("{prefix}{suffix}");
        // Should not panic, just return error for invalid addresses
        let _ = PublicKeyHash::from_b58check(&address);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_pkh(seed_byte: u8) -> PublicKeyHash {
    let seed = [seed_byte; 32];
    let (pkh, _, _) = generate_key(Some(&seed)).unwrap();
    pkh
}

fn create_versioned_pkh(seed_byte: u8) -> (PublicKeyHash, u8) {
    (create_test_pkh(seed_byte), 0)
}

fn try_create_pkh(seed: &[u8; 32]) -> Option<PublicKeyHash> {
    generate_key(Some(seed)).ok().map(|(pkh, _, _)| pkh)
}

fn original_versioned_pkh_bytes(req: &SignerRequest) -> Vec<u8> {
    match req {
        SignerRequest::Sign { pkh, .. } => {
            let mut bytes = pkh.0.to_bytes().to_vec();
            bytes.push(pkh.1);
            bytes
        }
        _ => vec![],
    }
}

fn versioned_pkh_bytes(pkh: &(PublicKeyHash, u8)) -> Vec<u8> {
    let mut bytes = pkh.0.to_bytes().to_vec();
    bytes.push(pkh.1);
    bytes
}

fn original_data(req: &SignerRequest) -> Vec<u8> {
    match req {
        SignerRequest::Sign { data, .. } => data.clone(),
        _ => vec![],
    }
}

// ============================================================================
// Specific Vulnerability Tests
// ============================================================================

/// Test for integer overflow in length calculations
#[test]
fn test_length_overflow_protection() {
    // Craft a message with maximum u32 length
    let mut data = vec![0x00]; // Sign tag
    data.push(0x00); // version
    data.push(0x03); // BLS PKH tag
    data.extend_from_slice(&[0u8; 20]); // dummy PKH

    // Add u32::MAX as length - should be rejected, not cause OOM
    data.extend_from_slice(&0xFFFF_FFFF_u32.to_be_bytes());
    data.extend_from_slice(&[0u8; 10]); // some extra bytes

    let result = decode_request(&data);
    assert!(result.is_err(), "Should reject huge length prefix");
}

/// Test for PKH tag validation
#[test]
fn test_invalid_pkh_tags() {
    // Sign request with invalid PKH tag (not 0x03 for BLS)
    for tag in [0x00, 0x01, 0x02, 0x04, 0xFF] {
        let mut data = vec![0x00]; // Sign tag
        data.push(0x00); // version
        data.push(tag); // Invalid PKH type tag
        data.extend_from_slice(&[0u8; 20]); // dummy PKH
        data.extend_from_slice(&0u32.to_be_bytes()); // data length
        // No signature

        let result = decode_request(&data);
        // Should either succeed (if tag is valid in some context) or error
        // but should NEVER panic
        let _ = result;
    }
}

/// Test empty and minimal inputs
#[test]
fn test_minimal_inputs() {
    // Empty input
    assert!(decode_request(&[]).is_err());

    // Just a tag byte
    for tag in 0..=255u8 {
        let _ = decode_request(&[tag]);
    }

    // Two bytes
    for tag in 0..=7u8 {
        for second in [0x00, 0x01, 0x02, 0x03, 0xFF] {
            let _ = decode_request(&[tag, second]);
        }
    }
}
