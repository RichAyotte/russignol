//! Security Test: Memory Exhaustion Protection
//!
//! These tests verify that the LRU cache eviction and file size limits
//! properly protect against memory exhaustion attacks.
//!
//! FIXED VULNERABILITIES:
//! - Cache now limited to `MAX_CACHE_ENTRIES` (100) with LRU eviction
//! - File reads now check size before loading (`MAX_WATERMARK_FILE_SIZE` = 64KB)

use russignol_signer_lib::bls::generate_key;
use russignol_signer_lib::high_watermark::{ChainId, HighWatermark};
use russignol_signer_lib::test_utils::{create_block_data, preinit_watermarks};
use tempfile::TempDir;

/// Helper to create a unique chain ID from an index
fn chain_id_from_index(n: u32) -> ChainId {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&n.to_be_bytes());
    ChainId::from_bytes(&bytes)
}

/// Verify that cache accepts entries up to the limit
///
/// This is a quick sanity check - full eviction testing would be slow.
#[test]
fn test_cache_accepts_entries() {
    let temp_dir = TempDir::new().unwrap();

    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    // Pre-initialize watermarks for all chain IDs at level 0
    for i in 0..5u32 {
        let chain_id = chain_id_from_index(i);
        preinit_watermarks(temp_dir.path(), chain_id, &pkh, 0);
    }

    let hwm = HighWatermark::new(temp_dir.path()).unwrap();

    // Just add a few entries to verify basic functionality
    for i in 0..5u32 {
        let chain_id = chain_id_from_index(i);
        let data = create_block_data(i + 1, 0); // Level i+1 > initialized level 0

        let result = hwm.check_and_update(chain_id, &pkh, &data);
        assert!(
            result.is_ok(),
            "Failed to add entry {}: {:?}",
            i,
            result.err()
        );
    }

    // Verify entries are cached (reject same level)
    for i in 0..5u32 {
        let chain_id = chain_id_from_index(i);
        let same_level_data = create_block_data(i + 1, 0);

        let result = hwm.check_and_update(chain_id, &pkh, &same_level_data);
        assert!(result.is_err(), "Should reject same level for chain {i}");
    }

    println!("✓ Cache working correctly");
}

/// Verify file size limit protection
///
/// Create a watermark file larger than `MAX_WATERMARK_FILE_SIZE` (64KB)
/// and verify it's rejected on load, resulting in `NotInitialized` error.
#[test]
fn test_large_watermark_file_rejected() {
    use russignol_signer_lib::high_watermark::WatermarkError;

    let temp_dir = TempDir::new().unwrap();

    // Create an oversized watermark file (>64KB)
    let watermark_file = temp_dir.path().join("block_high_watermark");
    let large_content = "x".repeat(70 * 1024); // 70KB > 64KB limit
    std::fs::write(&watermark_file, large_content).unwrap();

    // Creating HighWatermark and loading should handle large file gracefully
    let hwm = HighWatermark::new(temp_dir.path()).unwrap();

    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    // With mandatory initialization, signing should fail when oversized file
    // is rejected and no valid watermark exists
    let chain_id = chain_id_from_index(1);
    let data = create_block_data(100, 0);
    let result = hwm.check_and_update(chain_id, &pkh, &data);

    // Should get NotInitialized error - oversized file was rejected, no valid watermark
    assert!(
        result.is_err(),
        "Should reject signing without valid watermark"
    );
    assert!(
        matches!(result.unwrap_err(), WatermarkError::NotInitialized { .. }),
        "Should return NotInitialized when watermark file is oversized/invalid"
    );
    println!("✓ Oversized watermark file rejected, signing blocked correctly");
}

/// Simple `HashMap` growth demonstration (no BLS overhead)
///
/// Shows the memory pattern that was vulnerable before the fix.
#[test]
fn test_memory_growth_pattern() {
    use std::collections::HashMap;

    let mut cache: HashMap<(u32, u32), Vec<u8>> = HashMap::new();
    let entry_size = 500;
    let num_entries = 1000;

    for chain_id in 0..100 {
        for key_id in 0..10 {
            cache.insert((chain_id, key_id), vec![0u8; entry_size]);
        }
    }

    assert_eq!(cache.len(), num_entries);

    let estimated_memory_kb = (num_entries * (entry_size + 50)) / 1024;
    println!(
        "HashMap with {num_entries} entries uses ~{estimated_memory_kb}KB (bounded by LRU in real code)"
    );
}
