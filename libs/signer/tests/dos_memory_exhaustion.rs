//! Security Test: Watermark File Validation
//!
//! These tests verify that the watermark system properly rejects
//! invalid or corrupt files and only accepts valid 40-byte binary entries.

use russignol_signer_lib::bls::generate_key;
use russignol_signer_lib::high_watermark::{ChainId, HighWatermark};
use russignol_signer_lib::test_utils::{create_block_data, preinit_watermarks};
use tempfile::TempDir;

fn chain_id_from_index(n: u32) -> ChainId {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&n.to_be_bytes());
    ChainId::from_bytes(&bytes)
}

/// Verify that oversized watermark files are rejected at load time
#[test]
fn test_large_watermark_file_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    // Create per-key dir with an oversized watermark file (not 40 bytes)
    let key_dir = temp_dir.path().join(pkh.to_b58check());
    std::fs::create_dir_all(&key_dir).unwrap();
    let large_content = "x".repeat(70 * 1024); // 70KB
    std::fs::write(key_dir.join("block_watermark"), large_content).unwrap();

    // Corrupt watermark file must cause a load failure
    let Err(err) = HighWatermark::new(temp_dir.path(), &[pkh]) else {
        panic!("expected error for oversized watermark file");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    println!("✓ Oversized watermark file rejected at load time");
}

/// Verify corrupt data (bad hash) is rejected at load time
#[test]
fn test_corrupt_watermark_file_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    // Create per-key dir with 40 bytes containing a bad Blake3 hash
    let key_dir = temp_dir.path().join(pkh.to_b58check());
    std::fs::create_dir_all(&key_dir).unwrap();
    let mut buf = [0u8; 40];
    buf[0..4].copy_from_slice(&100u32.to_be_bytes()); // level
    buf[4..8].copy_from_slice(&5u32.to_be_bytes()); // round
    buf[8..40].fill(0xFF); // bad hash
    std::fs::write(key_dir.join("block_watermark"), buf).unwrap();

    // Corrupt watermark file must cause a load failure
    let Err(err) = HighWatermark::new(temp_dir.path(), &[pkh]) else {
        panic!("expected error for corrupt watermark file");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    println!("✓ Corrupt hash rejected at load time");
}

/// Verify valid watermark files work correctly
#[test]
fn test_valid_watermark_accepted() {
    let temp_dir = TempDir::new().unwrap();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
    let chain_id = chain_id_from_index(1);

    preinit_watermarks(temp_dir.path(), &pkh, 99);
    let mut hwm = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();

    let data = create_block_data(100, 0);
    let result = hwm.check_and_update(chain_id, &pkh, &data);
    assert!(result.is_ok(), "Valid watermark should allow signing");
    println!("✓ Valid watermark accepted correctly");
}
