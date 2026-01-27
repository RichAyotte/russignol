//! TCP Server Demo
//!
//! This example demonstrates the TCP signer server in action.
//! Run with: cargo run --example `tcp_server_demo`

use russignol_signer_lib::{
    HighWatermark, RequestHandler, ServerKeyManager, SignerServer, UnencryptedSigner,
    bls::generate_key,
};
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

    let signer1 = UnencryptedSigner::generate(Some(&seed1))?;
    let signer2 = UnencryptedSigner::generate(Some(&seed2))?;

    println!("  ✓ Key 1: {}", pkh1.to_b58check());
    println!("  ✓ Key 2: {}", pkh2.to_b58check());

    // 2. Setup key manager
    let mut key_mgr = ServerKeyManager::new();
    key_mgr.add_signer(pkh1, signer1, "key1".to_string());
    key_mgr.add_signer(pkh2, signer2, "key2".to_string());
    println!("  ✓ Keys loaded into manager\n");

    // 3. Setup high watermark
    let temp_dir = TempDir::new()?;
    let watermark = HighWatermark::new(temp_dir.path())?;
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
    let server = SignerServer::new(addr, Arc::new(handler), Some(Duration::from_secs(30)));

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
