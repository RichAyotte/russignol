//! TCP Server Integration Tests
//!
//! These tests verify the TCP server works correctly with real network connections.

use russignol_signer_lib::{
    HighWatermark, RequestHandler, ServerKeyManager, SignerServer, UnencryptedSigner,
    bls::generate_key,
    high_watermark::ChainId,
    protocol::{SignerRequest, SignerResponse},
    test_utils::{preinit_watermarks, send_request},
};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn test_tcp_server_public_key_request() {
    // Setup
    let seed = [42u8; 32];
    let (pkh, pk, _sk) = generate_key(Some(&seed)).unwrap();
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(pkh, signer, "test_key".to_string());

    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        None,
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let server = SignerServer::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    // Start server in background thread
    std::thread::spawn(move || {
        let _ = server.run();
    });

    // Give server time to start and bind
    std::thread::sleep(Duration::from_millis(500));

    // Connect and test
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
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
    let (pkh1, _pk1, _sk1) = generate_key(Some(&seed1)).unwrap();
    let (pkh2, _pk2, _sk2) = generate_key(Some(&seed2)).unwrap();

    let signer1 = UnencryptedSigner::generate(Some(&seed1)).unwrap();
    let signer2 = UnencryptedSigner::generate(Some(&seed2)).unwrap();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(pkh1, signer1, "key1".to_string());
    key_mgr.add_signer(pkh2, signer2, "key2".to_string());

    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        None,
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18081".parse().unwrap();
    let server = SignerServer::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    std::thread::spawn(move || {
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_millis(500));

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    let request = SignerRequest::KnownKeys;
    let response = send_request(&mut stream, &request).unwrap();

    match response {
        SignerResponse::KnownKeys(keys) => {
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&pkh1));
            assert!(keys.contains(&pkh2));
        }
        r => panic!("Expected KnownKeys response, got {r:?}"),
    }
}

#[test]
fn test_tcp_server_sign_with_watermark() {
    let temp_dir = TempDir::new().unwrap();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

    // Create chain_id matching the one used in block data ([0, 0, 0, 1])
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[..4].copy_from_slice(&[0, 0, 0, 1]);
    let chain_id = ChainId::from_bytes(&chain_id_bytes);

    // Pre-initialize watermarks at level 99 (below 100 we'll sign)
    preinit_watermarks(temp_dir.path(), chain_id, &pkh, 99);

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(pkh, signer, "test_key".to_string());

    let watermark = HighWatermark::new(temp_dir.path()).unwrap();

    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        Some(Arc::new(RwLock::new(watermark))),
        Some(vec![0x11, 0x12, 0x13]),
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18082".parse().unwrap();
    let server = SignerServer::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    std::thread::spawn(move || {
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_millis(500));

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();

    // Create block at level 100
    let mut data = vec![0x11];
    data.extend_from_slice(&[0, 0, 0, 1]);
    data.extend_from_slice(&100u32.to_be_bytes());
    data.push(0);
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(&[0u8; 8]);
    data.push(0);
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(&8u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());

    // Sign at level 100 - should succeed
    let request = SignerRequest::Sign {
        pkh: (pkh, 0),
        data: data.clone(),
        signature: None,
    };
    let response = send_request(&mut stream, &request).unwrap();
    assert!(matches!(response, SignerResponse::Signature(_)));

    // Try to sign at level 99 - should fail
    let mut data_low = vec![0x11];
    data_low.extend_from_slice(&[0, 0, 0, 1]);
    data_low.extend_from_slice(&99u32.to_be_bytes());
    data_low.push(0);
    data_low.extend_from_slice(&[0u8; 32]);
    data_low.extend_from_slice(&[0u8; 8]);
    data_low.push(0);
    data_low.extend_from_slice(&[0u8; 32]);
    data_low.extend_from_slice(&8u32.to_be_bytes());
    data_low.extend_from_slice(&0u32.to_be_bytes());

    let request_low = SignerRequest::Sign {
        pkh: (pkh, 0),
        data: data_low,
        signature: None,
    };

    // Create a new stream for the second request, as the server might close the connection on error
    let mut stream2 = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    let response_low = send_request(&mut stream2, &request_low).unwrap();

    assert!(matches!(response_low, SignerResponse::Error(_)));
}

#[test]
fn test_tcp_server_magic_byte_filtering() {
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(pkh, signer, "test_key".to_string());

    // Only allow Tenderbake blocks (0x11)
    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        Some(vec![0x11]), // Only blocks
        true,             // allow_list_known_keys
        true,             // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18083".parse().unwrap();
    let server = SignerServer::new(addr, Arc::new(handler), Some(Duration::from_secs(5)));

    std::thread::spawn(move || {
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_millis(500));

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();

    // Try to sign attestation (0x13) - should fail
    let mut data = vec![0x13]; // Attestation magic byte
    data.extend_from_slice(&[0, 0, 0, 1]);
    data.extend_from_slice(&[0u8; 32]);
    data.push(0x15);
    data.extend_from_slice(&100u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());

    let request = SignerRequest::Sign {
        pkh: (pkh, 0),
        data,
        signature: None,
    };
    let response = send_request(&mut stream, &request).unwrap();
    assert!(matches!(response, SignerResponse::Error(_)));
}

#[test]
fn test_tcp_server_concurrent_connections() {
    let seed = [42u8; 32];
    let (public_key_hash, _public_key, _secret_key) = generate_key(Some(&seed)).unwrap();
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();

    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(public_key_hash, signer, "test_key".to_string());

    let request_handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        None,
        None,
        true, // allow_list_known_keys
        true, // allow_prove_possession
    );

    let addr: SocketAddr = "127.0.0.1:18084".parse().unwrap();
    let server = SignerServer::new(
        addr,
        Arc::new(request_handler),
        Some(Duration::from_secs(5)),
    )
    .with_max_connections(10); // Allow 10 connections for this test

    std::thread::spawn(move || {
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_millis(500));

    // Create 5 concurrent connections
    let mut thread_handles = vec![];
    for _i in 0..5 {
        // Clone variables before moving into thread
        let addr_copy = addr;
        let pkh_copy = public_key_hash;
        let join_handle = std::thread::spawn(move || {
            let mut stream =
                TcpStream::connect_timeout(&addr_copy, Duration::from_secs(5)).unwrap();
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
