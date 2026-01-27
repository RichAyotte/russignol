//! TCP Client Test
//!
//! This example tests the TCP signer by connecting as a client and sending requests.
//! First start the server with: cargo run --example `tcp_server_demo`
//! Then run this: cargo run --example `tcp_client_test`

use russignol_signer_lib::{
    bls::{PublicKeyHash, generate_key},
    protocol::encoding::{decode_response, encode_request},
    protocol::{SignerRequest, SignerResponse},
};
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔌 Octez Signer TCP Client Test\n");

    // Generate the same test keys as the server
    let seed1 = [1u8; 32];
    let (pkh1, _pk1, _sk1) = generate_key(Some(&seed1))?;

    println!("📝 Using test key: {}\n", pkh1.to_b58check());

    // Connect to server
    println!("🌐 Connecting to 127.0.0.1:8080...");
    let mut stream = TcpStream::connect("127.0.0.1:8080")?;
    println!("  ✓ Connected!\n");

    run_public_key_test(&mut stream, pkh1)?;
    run_known_keys_test(&mut stream)?;
    run_signing_test(&mut stream, pkh1, 100, "TEST 3", true)?;
    run_signing_test(&mut stream, pkh1, 99, "TEST 4", false)?;
    run_signing_test(&mut stream, pkh1, 101, "TEST 5", true)?;
    run_nonce_support_test(&mut stream, pkh1)?;

    println!("✅ All tests completed!\n");

    Ok(())
}

fn run_public_key_test(
    stream: &mut TcpStream,
    pkh: PublicKeyHash,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("TEST 1: Get Public Key");
    println!("  Requesting public key for {}", pkh.to_b58check());
    let request = SignerRequest::PublicKey { pkh };
    let response = send_request(stream, &request)?;
    match response {
        SignerResponse::PublicKey(pk) => {
            println!("  ✓ Received public key: {}", pk.to_b58check());
        }
        SignerResponse::Error(e) => {
            println!("  ✗ Error: {e}");
        }
        _ => {
            println!("  ✗ Unexpected response");
        }
    }
    println!();
    Ok(())
}

fn run_known_keys_test(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("TEST 2: Get Known Keys");
    let request = SignerRequest::KnownKeys;
    let response = send_request(stream, &request)?;
    match response {
        SignerResponse::KnownKeys(keys) => {
            println!("  ✓ Server has {} keys:", keys.len());
            for key in keys {
                println!("    - {}", key.to_b58check());
            }
        }
        SignerResponse::Error(e) => {
            println!("  ✗ Error: {e}");
        }
        _ => {
            println!("  ✗ Unexpected response");
        }
    }
    println!();
    Ok(())
}

fn run_signing_test(
    stream: &mut TcpStream,
    pkh: PublicKeyHash,
    level: u32,
    test_name: &str,
    expect_success: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if expect_success {
        println!("{test_name}: Sign Tenderbake Block (Level {level}, Round 0)");
    } else {
        println!("{test_name}: Try to Sign at Level {level} (Should Fail - Watermark)");
    }
    let block_data = create_block_data(level, 0);
    if expect_success {
        println!("  Block data: {} bytes", block_data.len());
    }
    let request = SignerRequest::Sign {
        pkh: (pkh, 0),
        data: block_data,
        signature: None,
    };
    let response = send_request(stream, &request)?;
    match response {
        SignerResponse::Signature(sig) => {
            if expect_success {
                println!("  ✓ Signed successfully!");
                println!("  Signature (hex): {}", hex::encode(sig.to_bytes()));
            } else {
                println!("  ✗ UNEXPECTED: Signature should have been rejected!");
            }
        }
        SignerResponse::Error(e) => {
            if expect_success {
                println!("  ✗ Error: {e}");
            } else {
                println!("  ✓ Correctly rejected: {e}");
            }
        }
        _ => {
            println!("  ✗ Unexpected response");
        }
    }
    println!();
    Ok(())
}

fn run_nonce_support_test(
    stream: &mut TcpStream,
    pkh: PublicKeyHash,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("TEST 6: Check Deterministic Nonce Support");
    let request = SignerRequest::SupportsDeterministicNonces { pkh };
    let response = send_request(stream, &request)?;
    match response {
        SignerResponse::Bool(supported) => {
            println!("  ✓ Deterministic nonces supported: {supported}");
        }
        SignerResponse::Error(e) => {
            println!("  ✗ Error: {e}");
        }
        _ => {
            println!("  ✗ Unexpected response");
        }
    }
    println!();
    Ok(())
}

/// Send a request and receive response
fn send_request(
    stream: &mut TcpStream,
    request: &SignerRequest,
) -> Result<SignerResponse, Box<dyn std::error::Error>> {
    // Encode request
    let request_data = encode_request(request)?;

    // Send length-prefixed message (2-bytes u16)
    let len = u16::try_from(request_data.len())
        .map_err(|_| "Request data exceeds 64KB limit")?
        .to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&request_data)?;
    stream.flush()?;

    // Read response length (2-bytes u16)
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    // Read response data
    let mut response_data = vec![0u8; response_len];
    stream.read_exact(&mut response_data)?;

    // Decode response
    let response = decode_response(&response_data, request)?;

    Ok(response)
}

/// Create Tenderbake block data for testing
fn create_block_data(level: u32, round: u32) -> Vec<u8> {
    let mut data = vec![0x11]; // Block magic byte
    data.extend_from_slice(&[0, 0, 0, 1]); // chain_id
    data.extend_from_slice(&level.to_be_bytes()); // level
    data.push(0); // proto
    data.extend_from_slice(&[0u8; 32]); // predecessor
    data.extend_from_slice(&[0u8; 8]); // timestamp
    data.push(0); // validation_pass
    data.extend_from_slice(&[0u8; 32]); // operations_hash
    data.extend_from_slice(&8u32.to_be_bytes()); // fitness_length
    data.extend_from_slice(&round.to_be_bytes()); // round
    data
}
