//! Test utilities for creating Tezos operation data
//!
//! These functions generate properly formatted binary data for testing
//! watermark protection and signing operations. The formats follow the
//! Tenderbake consensus protocol specifications.

use crate::bls::PublicKeyHash;
use crate::high_watermark::ChainId;
use crate::protocol::encoding::{decode_response, encode_request};
use crate::protocol::{SignerRequest, SignerResponse};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

/// Create Tenderbake block data for testing
///
/// Format follows the Tezos block header structure:
/// - watermark (1 byte): 0x11
/// - `chain_id` (4 bytes): network identifier
/// - level (4 bytes): block height (big-endian)
/// - proto (1 byte): protocol version
/// - predecessor (32 bytes): previous block hash
/// - timestamp (8 bytes): block timestamp
/// - `validation_pass` (1 byte): validation pass number
/// - `operations_hash` (32 bytes): merkle root of operations
/// - `fitness_length` (4 bytes): length of fitness data
/// - round (4 bytes): consensus round (big-endian)
#[must_use]
pub fn create_block_data(level: u32, round: u32) -> Vec<u8> {
    create_block_data_with_chain(&[0, 0, 0, 1], level, round)
}

/// Create Tenderbake block data with a specific chain ID
#[must_use]
pub fn create_block_data_with_chain(chain_id: &[u8; 4], level: u32, round: u32) -> Vec<u8> {
    let mut data = vec![0x11]; // Block magic byte
    data.extend_from_slice(chain_id); // chain_id (4 bytes)
    data.extend_from_slice(&level.to_be_bytes()); // level (4 bytes)
    data.push(0); // proto (1 byte)
    data.extend_from_slice(&[0u8; 32]); // predecessor (32 bytes)
    data.extend_from_slice(&[0u8; 8]); // timestamp (8 bytes)
    data.push(0); // validation_pass (1 byte)
    data.extend_from_slice(&[0u8; 32]); // operations_hash (32 bytes)

    // Fitness with round at the end
    let fitness_length = 8u32;
    data.extend_from_slice(&fitness_length.to_be_bytes());
    data.extend_from_slice(&round.to_be_bytes()); // round (4 bytes)

    data
}

/// Create Tenderbake attestation data for testing (BLS format)
///
/// Format for BLS attestations:
/// - watermark (1 byte): 0x13
/// - `chain_id` (4 bytes): network identifier
/// - branch (32 bytes): branch block hash
/// - kind (1 byte): 0x15 for attestation
/// - level (4 bytes): attestation level (big-endian)
/// - round (4 bytes): consensus round (big-endian)
///
/// Note: BLS signatures do NOT include the slot field
#[must_use]
pub fn create_attestation_data(level: u32, round: u32) -> Vec<u8> {
    create_attestation_data_with_chain(&[0, 0, 0, 1], level, round)
}

/// Create Tenderbake attestation data with a specific chain ID
#[must_use]
pub fn create_attestation_data_with_chain(chain_id: &[u8; 4], level: u32, round: u32) -> Vec<u8> {
    let mut data = vec![0x13]; // Attestation magic byte
    data.extend_from_slice(chain_id); // chain_id (4 bytes)
    data.extend_from_slice(&[0u8; 32]); // branch (32 bytes)
    data.push(0x15); // kind byte for attestation
    data.extend_from_slice(&level.to_be_bytes()); // level (4 bytes)
    data.extend_from_slice(&round.to_be_bytes()); // round (4 bytes)
    data
}

/// Create Tenderbake preattestation data for testing (BLS format)
///
/// Format for BLS preattestations:
/// - watermark (1 byte): 0x12
/// - `chain_id` (4 bytes): network identifier
/// - branch (32 bytes): branch block hash
/// - kind (1 byte): 0x14 for preattestation
/// - level (4 bytes): preattestation level (big-endian)
/// - round (4 bytes): consensus round (big-endian)
#[must_use]
pub fn create_preattestation_data(level: u32, round: u32) -> Vec<u8> {
    create_preattestation_data_with_chain(&[0, 0, 0, 1], level, round)
}

/// Create Tenderbake preattestation data with a specific chain ID
#[must_use]
pub fn create_preattestation_data_with_chain(
    chain_id: &[u8; 4],
    level: u32,
    round: u32,
) -> Vec<u8> {
    let mut data = vec![0x12]; // Preattestation magic byte
    data.extend_from_slice(chain_id); // chain_id (4 bytes)
    data.extend_from_slice(&[0u8; 32]); // branch (32 bytes)
    data.push(0x14); // kind byte for preattestation
    data.extend_from_slice(&level.to_be_bytes()); // level (4 bytes)
    data.extend_from_slice(&round.to_be_bytes()); // round (4 bytes)
    data
}

/// Create a `ChainId` from 4-byte chain identifier
///
/// The chain ID is padded to 32 bytes as required by the internal representation.
#[must_use]
pub fn create_chain_id(chain_id_bytes: &[u8; 4]) -> ChainId {
    let mut full_id = [0u8; 32];
    full_id[0..4].copy_from_slice(chain_id_bytes);
    ChainId::from_bytes(&full_id)
}

/// Default test chain ID (used when no specific chain is needed)
#[must_use]
pub fn default_test_chain_id() -> ChainId {
    create_chain_id(&[0, 0, 0, 1])
}

/// Tezos Mainnet chain ID bytes
pub const MAINNET_CHAIN_ID: [u8; 4] = [0x7a, 0x06, 0xa7, 0x70];

/// Tezos Ghostnet (testnet) chain ID bytes
pub const GHOSTNET_CHAIN_ID: [u8; 4] = [0x1c, 0xaa, 0xa9, 0xcd];

/// Create Mainnet chain ID
#[must_use]
pub fn mainnet_chain_id() -> ChainId {
    create_chain_id(&MAINNET_CHAIN_ID)
}

/// Create Ghostnet (testnet) chain ID
#[must_use]
pub fn ghostnet_chain_id() -> ChainId {
    create_chain_id(&GHOSTNET_CHAIN_ID)
}

/// Pre-initialize watermark files for testing
///
/// Creates watermark files with an initial level/round for all three operation types
/// (block, attestation, preattestation). This is required because the watermark system
/// enforces mandatory initialization - signing attempts without pre-initialized
/// watermarks are rejected.
///
/// # Arguments
/// * `base_dir` - Directory where watermark files will be created
/// * `chain_id` - The chain ID to initialize watermarks for
/// * `pkh` - The public key hash of the baker
/// * `level` - The initial watermark level (signing will only succeed above this level)
pub fn preinit_watermarks(base_dir: &Path, chain_id: ChainId, pkh: &PublicKeyHash, level: u32) {
    let chain_id_b58 = chain_id.to_b58check();
    let pkh_b58 = pkh.to_b58check();

    let wm_entry = serde_json::json!({
        "level": level,
        "round": 0,
        "hash": "",
        "signature": ""
    });

    for filename in &[
        "block_high_watermark",
        "attestation_high_watermark",
        "preattestation_high_watermark",
    ] {
        let path = base_dir.join(filename);
        let mut content: serde_json::Value = if path.exists() {
            let existing = fs::read_to_string(&path).unwrap();
            serde_json::from_str(&existing).unwrap_or_else(|_| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        if !content.as_object().unwrap().contains_key(&chain_id_b58) {
            content[&chain_id_b58] = serde_json::json!({});
        }
        content[&chain_id_b58][&pkh_b58] = wm_entry.clone();

        fs::write(&path, serde_json::to_string_pretty(&content).unwrap()).unwrap();
    }
}

/// Send a request over a TCP stream and receive the response
///
/// This helper handles the length-prefixed protocol used by the signer TCP server:
/// - Writes 2-byte big-endian length prefix
/// - Writes encoded request
/// - Reads 2-byte big-endian response length
/// - Reads and decodes response
///
/// # Errors
/// Returns an error if encoding, I/O, or decoding fails.
pub fn send_request(
    stream: &mut TcpStream,
    request: &SignerRequest,
) -> Result<SignerResponse, Box<dyn std::error::Error>> {
    let request_data = encode_request(request)?;
    let len = u16::try_from(request_data.len())
        .map_err(|_| "Request data exceeds 64KB limit")?
        .to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&request_data)?;
    stream.flush()?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    let mut response_data = vec![0u8; response_len];
    stream.read_exact(&mut response_data)?;

    // The decode_response function needs to know what was requested to decode the
    // correct payload type.
    Ok(decode_response(&response_data, request)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_data_format() {
        let data = create_block_data(100, 5);

        // Check magic byte
        assert_eq!(data[0], 0x11);

        // Check level at offset 5 (after magic + chain_id)
        let level = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
        assert_eq!(level, 100);

        // Round is at the end (last 4 bytes)
        let round_offset = data.len() - 4;
        let round = u32::from_be_bytes([
            data[round_offset],
            data[round_offset + 1],
            data[round_offset + 2],
            data[round_offset + 3],
        ]);
        assert_eq!(round, 5);
    }

    #[test]
    fn test_attestation_data_format() {
        let data = create_attestation_data(200, 3);

        // Check magic byte
        assert_eq!(data[0], 0x13);

        // Check kind byte at offset 37 (after magic + chain_id + branch)
        assert_eq!(data[37], 0x15);

        // Level at offset 38
        let level = u32::from_be_bytes([data[38], data[39], data[40], data[41]]);
        assert_eq!(level, 200);

        // Round at offset 42
        let round = u32::from_be_bytes([data[42], data[43], data[44], data[45]]);
        assert_eq!(round, 3);
    }

    #[test]
    fn test_preattestation_data_format() {
        let data = create_preattestation_data(150, 2);

        // Check magic byte
        assert_eq!(data[0], 0x12);

        // Check kind byte
        assert_eq!(data[37], 0x14);

        // Level
        let level = u32::from_be_bytes([data[38], data[39], data[40], data[41]]);
        assert_eq!(level, 150);

        // Round
        let round = u32::from_be_bytes([data[42], data[43], data[44], data[45]]);
        assert_eq!(round, 2);
    }

    #[test]
    fn test_chain_id_creation() {
        let chain_id = create_chain_id(&MAINNET_CHAIN_ID);
        let bytes = chain_id.as_bytes();

        assert_eq!(bytes[0..4], MAINNET_CHAIN_ID);
        // Rest should be zeros
        assert!(bytes[4..].iter().all(|&b| b == 0));
    }
}
