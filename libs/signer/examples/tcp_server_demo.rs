//! TCP Server Demo
//!
//! This example demonstrates the TCP signer server in action.
//! Run with: cargo run --example `tcp_server_demo`

use russignol_signer_lib::{
    ChainId, HighWatermark, RequestHandler, ServerKeyManager,
    bls::{generate_key, watermark_mac_key},
    high_watermark::seed_watermarks,
    server, signer,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Octez Signer TCP Server Demo\n");

    // 1. Generate test keys
    println!("📝 Generating test keys...");
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];

    let (pkh1, _pk1, _sk1) = generate_key(Some(&seed1))?;
    let (pkh2, _pk2, _sk2) = generate_key(Some(&seed2))?;

    let signer1 = signer::Unencrypted::generate(Some(&seed1))?;
    let signer2 = signer::Unencrypted::generate(Some(&seed2))?;

    let mac1 = watermark_mac_key(signer1.secret_key());
    let mac2 = watermark_mac_key(signer2.secret_key());
    let demo_chain = ChainId::from_bytes(&[0u8; 32]);

    println!("  ✓ Key 1: {}", pkh1.to_b58check());
    println!("  ✓ Key 2: {}", pkh2.to_b58check());

    // 2. Setup key manager
    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(pkh1, signer1, "key1".to_string());
    key_mgr.add_signer(pkh2, signer2, "key2".to_string());
    println!("  ✓ Keys loaded into manager\n");

    // 3. Setup high watermark
    // Watermarks must exist before the first signature, so seed level 0 for
    // both keys; signing then succeeds at any level >= 1.
    let temp_dir = TempDir::new()?;
    seed_watermarks(temp_dir.path(), &pkh1, 0, &mac1, demo_chain)?;
    seed_watermarks(temp_dir.path(), &pkh2, 0, &mac2, demo_chain)?;
    let mac_keys = HashMap::from([(pkh1, mac1), (pkh2, mac2)]);
    let watermark = HighWatermark::new(temp_dir.path(), &[pkh1, pkh2], mac_keys, demo_chain)?;
    println!("📊 High watermark protection enabled");
    println!("  Storage: {}\n", temp_dir.path().display());

    // 4. Create request handler
    let handler = RequestHandler::new(
        Arc::new(RwLock::new(key_mgr)),
        Some(Arc::new(RwLock::new(watermark))),
        Some(vec![0x11, 0x12, 0x13]), // Tenderbake only
        true,                         // allow_list_known_keys
        true,                         // allow_prove_possession
    );

    // 5. Start TCP server
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let server = server::Server::new(addr, Arc::new(handler), Some(Duration::from_secs(30)));

    println!("🌐 Starting TCP server on {addr}");
    println!("📡 Waiting for connections...\n");
    println!("Press Ctrl+C to stop\n");

    println!("💡 Test with:");
    println!("   nc 127.0.0.1 8080");
    println!("   or use the tcp_client_test example\n");

    // Run server
    server.run()?;

    Ok(())
}
