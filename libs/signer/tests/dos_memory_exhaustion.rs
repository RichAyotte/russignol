//! Security Test: Watermark File Validation
//!
//! These tests verify that the watermark system properly rejects
//! invalid or corrupt files and only accepts valid 40-byte binary entries.

use russignol_signer_lib::bls::generate_key;
use russignol_signer_lib::high_watermark::{ChainId, HighWatermark, WatermarkError};
use russignol_signer_lib::test_utils::{create_block_data, preinit_watermarks};
use tempfile::TempDir;

fn chain_id_from_index(n: u32) -> ChainId {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&n.to_be_bytes());
    ChainId::from_bytes(&bytes)
}

/// Verify that oversized watermark files are rejected
#[test]
fn test_large_watermark_file_rejected() {
    let temp_dir = TempDir::new().unwrap();

    // Create an oversized watermark file (not 40 bytes)
    let watermark_file = temp_dir.path().join("block_watermark");
    let large_content = "x".repeat(70 * 1024); // 70KB
    std::fs::write(&watermark_file, large_content).unwrap();

    // HighWatermark should handle large file gracefully (entry will be None)
    let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    let chain_id = chain_id_from_index(1);
    let data = create_block_data(100, 0);
    let result = hwm.check_and_update(chain_id, &pkh, &data);

    assert!(
        matches!(result.unwrap_err(), WatermarkError::NotInitialized { .. }),
        "Should return NotInitialized when watermark file is invalid"
    );
    println!("✓ Oversized watermark file rejected, signing blocked correctly");
}

/// Verify corrupt data (bad hash) is rejected
#[test]
fn test_corrupt_watermark_file_rejected() {
    let temp_dir = TempDir::new().unwrap();

    // Write 40 bytes with bad Blake3 hash
    let watermark_file = temp_dir.path().join("block_watermark");
    let mut buf = [0u8; 40];
    buf[0..4].copy_from_slice(&100u32.to_be_bytes()); // level
    buf[4..8].copy_from_slice(&5u32.to_be_bytes()); // round
    buf[8..40].fill(0xFF); // bad hash
    std::fs::write(&watermark_file, &buf).unwrap();

    let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
    let chain_id = chain_id_from_index(1);
    let data = create_block_data(100, 0);
    let result = hwm.check_and_update(chain_id, &pkh, &data);

    assert!(
        matches!(result.unwrap_err(), WatermarkError::NotInitialized { .. }),
        "Should return NotInitialized when hash is invalid"
    );
    println!("✓ Corrupt hash rejected correctly");
}

/// Verify valid watermark files work correctly
#[test]
fn test_valid_watermark_accepted() {
    let temp_dir = TempDir::new().unwrap();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();
    let chain_id = chain_id_from_index(1);

    preinit_watermarks(temp_dir.path(), 99);
    let mut hwm = HighWatermark::new(temp_dir.path()).unwrap();

    let data = create_block_data(100, 0);
    let result = hwm.check_and_update(chain_id, &pkh, &data);
    assert!(result.is_ok(), "Valid watermark should allow signing");
    println!("✓ Valid watermark accepted correctly");
}
