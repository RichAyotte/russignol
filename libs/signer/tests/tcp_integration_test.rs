//! TCP Server Integration Tests
//!
//! These tests verify the TCP server works correctly with real network connections.

use russignol_signer_lib::{
    MagicByte, RequestHandler, ServerKeyManager, SignatureVersion,
    high_watermark::ChainId,
    protocol::{SignerRequest, SignerResponse},
    server, signer,
    test_utils::{create_block_data, new_watermark, preinit_watermarks, send_request},
};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Connect once the server has actually bound.
///
/// Polling the condition rather than waiting a fixed span means a slow bind is
/// not a flake and a server that never binds fails here rather than further on.
fn connect_when_listening(addr: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(stream) => return stream,
            Err(e) => {
                assert!(Instant::now() < deadline, "server never bound {addr}: {e}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[test]
fn test_tcp_server_public_key_request() {
    // Setup
    let seed = [42u8; 32];
    let signer = signer::Unencrypted::generate(Some(&seed)).unwrap();
    let pkh = *signer.public_key_hash();
    let pk = signer.public_key().clone();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(signer, "test_key".to_string());

    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        None,
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    // Start server in background thread
    std::thread::spawn(move || {
        let _ = server.run();
    });

    // Connect and test
    let mut stream = connect_when_listening(addr);
    let request = SignerRequest::PublicKey { pkh };
    let response = send_request(&mut stream, &request).unwrap();

    match response {
        SignerResponse::PublicKey(returned_pk) => {
            assert_eq!(returned_pk, pk);
        }
        r => panic!("Expected PublicKey response, got {r:?}"),
    }
}

#[test]
fn test_tcp_server_known_keys() {
    // Setup with multiple keys
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    let signer1 = signer::Unencrypted::generate(Some(&seed1)).unwrap();
    let signer2 = signer::Unencrypted::generate(Some(&seed2)).unwrap();
    let consensus_pkh = *signer1.public_key_hash();
    let companion_pkh = *signer2.public_key_hash();

    let mut key_mgr = ServerKeyManager::new();
    // Insert companion first to prove ordering is by role, not insertion order
    key_mgr.add_signer(
        signer2,
        russignol_signer_lib::DeviceKey::Bls(russignol_signer_lib::KeyRole::Companion)
            .device_alias()
            .to_string(),
    );
    key_mgr.add_signer(
        signer1,
        russignol_signer_lib::DeviceKey::Bls(russignol_signer_lib::KeyRole::Consensus)
            .device_alias()
            .to_string(),
    );

    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        None,
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18081".parse().unwrap();
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    std::thread::spawn(move || {
        let _ = server.run();
    });

    let mut stream = connect_when_listening(addr);
    let request = SignerRequest::KnownKeys;
    let response = send_request(&mut stream, &request).unwrap();

    match response {
        SignerResponse::KnownKeys(keys) => {
            assert_eq!(keys.len(), 2);
            assert_eq!(keys[0], consensus_pkh);
            assert_eq!(keys[1], companion_pkh);
        }
        r => panic!("Expected KnownKeys response, got {r:?}"),
    }
}

#[test]
fn test_tcp_server_sign_with_watermark() {
    let temp_dir = TempDir::new().unwrap();
    let seed = [42u8; 32];
    let signer = signer::Unencrypted::generate(Some(&seed)).unwrap();
    let pkh = *signer.public_key_hash();

    // Create chain_id matching the one used in block data ([0, 0, 0, 1])
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
    let _chain_id = ChainId::from_bytes(&chain_id_bytes);

    // Pre-initialize watermarks BEFORE creating HighWatermark
    preinit_watermarks(temp_dir.path(), &pkh, 99);

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(signer, "test_key".to_string());

    let watermark = new_watermark(temp_dir.path(), &[pkh]).unwrap();

    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        Some(Arc::new(RwLock::new(watermark))),
        Some(MagicByte::all()),
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18082".parse().unwrap();
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    std::thread::spawn(move || {
        let _ = server.run();
    });

    let mut stream = connect_when_listening(addr);

    let data = create_block_data(100, 0);

    // Sign at level 100 - should succeed
    let request = SignerRequest::Sign {
        pkh: (pkh, SignatureVersion::V4),
        data: data.clone(),
        signature: None,
    };
    let response = send_request(&mut stream, &request).unwrap();
    assert!(matches!(response, SignerResponse::Signature(_)));

    // Try to sign at level 99 - should fail
    let data_low = create_block_data(99, 0);

    let request_low = SignerRequest::Sign {
        pkh: (pkh, SignatureVersion::V4),
        data: data_low,
        signature: None,
    };

    // Create a new stream for the second request, as the server might close the connection on error
    let mut stream2 = connect_when_listening(addr);
    let response_low = send_request(&mut stream2, &request_low).unwrap();

    assert!(matches!(response_low, SignerResponse::Error(_)));
}

#[test]
fn test_tcp_server_magic_byte_filtering() {
    let seed = [42u8; 32];
    let signer = signer::Unencrypted::generate(Some(&seed)).unwrap();
    let pkh = *signer.public_key_hash();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(signer, "test_key".to_string());

    // Only allow Tenderbake blocks (0x11)
    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        Some(&[0x11]), // Only blocks
        true,          // allow_list_known_keys
        true,          // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18083".parse().unwrap();
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    std::thread::spawn(move || {
        let _ = server.run();
    });

    let mut stream = connect_when_listening(addr);

    // Try to sign attestation (0x13) - should fail
    let mut data = vec![0x13]; // Attestation magic byte
    data.extend_from_slice(&[0, 0, 0, 1]);
    data.extend_from_slice(&[0u8; 32]);
    data.push(0x15);
    data.extend_from_slice(&100u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());

    let request = SignerRequest::Sign {
        pkh: (pkh, SignatureVersion::V4),
        data,
        signature: None,
    };
    let response = send_request(&mut stream, &request).unwrap();
    assert!(matches!(response, SignerResponse::Error(_)));
}

#[test]
fn test_tcp_server_concurrent_connections() {
    let seed = [42u8; 32];
    let signer = signer::Unencrypted::generate(Some(&seed)).unwrap();
    let public_key_hash = *signer.public_key_hash();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(signer, "test_key".to_string());

    let request_handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        None,
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18084".parse().unwrap();
    let server = server::Server::new(
        addr,
        Arc::new(request_handler),
        Some(Duration::from_secs(5)),
    )
    .with_max_connections(10); // Allow 10 connections for this test

    std::thread::spawn(move || {
        let _ = server.run();
    });

    // Create 5 concurrent connections
    let mut thread_handles = vec![];
    for _i in 0..5 {
        // Clone variables before moving into thread
        let addr_copy = addr;
        let pkh_copy = public_key_hash;
        let join_handle = std::thread::spawn(move || {
            let mut stream = connect_when_listening(addr_copy);
            let request = SignerRequest::PublicKey { pkh: pkh_copy };
            let response = send_request(&mut stream, &request).unwrap();
            matches!(response, SignerResponse::PublicKey(_))
        });
        thread_handles.push(join_handle);
    }

    // All should succeed
    for join_handle in thread_handles {
        assert!(join_handle.join().unwrap());
    }
}

/// The cap counts connections being served, so a test whose connections have
/// closed proves nothing about it. Each held connection's guard lives for as
/// long as its handler thread blocks on the next request, and an answered
/// request is what establishes that the thread is there to hold it.
#[test]
fn a_connection_past_the_limit_is_refused() {
    let signer = signer::Unencrypted::generate(Some(&[43u8; 32])).unwrap();
    let pkh = *signer.public_key_hash();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(signer, "test_key".to_string());

    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        None,
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18085".parse().unwrap();
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(30)))
        .with_max_connections(2);

    std::thread::spawn(move || {
        let _ = server.run();
    });

    let held: Vec<TcpStream> = (0..2)
        .map(|_| {
            let mut stream = connect_when_listening(addr);
            let response = send_request(&mut stream, &SignerRequest::PublicKey { pkh }).unwrap();
            assert!(matches!(response, SignerResponse::PublicKey(_)));
            stream
        })
        .collect();

    let mut over = connect_when_listening(addr);
    assert!(
        send_request(&mut over, &SignerRequest::PublicKey { pkh }).is_err(),
        "a third connection was answered under a limit of two"
    );

    drop(held);
}
