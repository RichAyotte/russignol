//! Security Test: Watermark File Validation
//!
//! These tests verify that an invalid, corrupt, or forged watermark file is
//! never trusted as a signing floor. Rather than aborting at load (which would
//! brick a healthy device), such a mark loads as uninitialized so signing fails
//! closed and the on-device recovery re-establishes an authenticated floor.

use russignol_signer_lib::bls::generate_key;
use russignol_signer_lib::high_watermark::{ChainId, WatermarkError, seed_watermarks};
use russignol_signer_lib::test_utils::{
    create_block_data, default_test_chain_id, new_watermark, preinit_watermarks,
};
use tempfile::TempDir;

fn chain_id_from_index(n: u32) -> ChainId {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&n.to_be_bytes());
    ChainId::from_bytes(&bytes)
}

/// Assert `pkh` has no usable floor: no in-memory level, and signing is refused
/// with `NotInitialized` so the missing-watermark recovery takes over.
fn assert_not_trusted(
    hwm: &mut russignol_signer_lib::high_watermark::HighWatermark,
    pkh: &russignol_signer_lib::bls::PublicKeyHash,
) {
    assert!(
        hwm.get_max_level(pkh).is_none(),
        "an unusable mark must not present a floor"
    );
    let data = create_block_data(100, 0);
    let err = hwm
        .check_and_update(default_test_chain_id(), pkh, &data)
        .expect_err("signing must be refused without a valid floor");
    assert!(matches!(err, WatermarkError::NotInitialized { .. }));
}

/// An oversized watermark file is not trusted as a floor.
#[test]
fn test_large_watermark_file_not_trusted() {
    let temp_dir = TempDir::new().unwrap();
    let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

    let key_dir = temp_dir.path().join(pkh.to_b58check());
    std::fs::create_dir_all(&key_dir).unwrap();
    std::fs::write(key_dir.join("block_watermark"), "x".repeat(70 * 1024)).unwrap();

    let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
    assert_not_trusted(&mut hwm, &pkh);
}

/// A 40-byte record with a bad Blake3 checksum is not trusted as a floor.
#[test]
fn test_corrupt_watermark_file_not_trusted() {
    let temp_dir = TempDir::new().unwrap();
    let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

    let key_dir = temp_dir.path().join(pkh.to_b58check());
    std::fs::create_dir_all(&key_dir).unwrap();
    let mut buf = [0u8; 40];
    buf[0..4].copy_from_slice(&100u32.to_be_bytes());
    buf[4..8].copy_from_slice(&5u32.to_be_bytes());
    buf[8..40].fill(0xFF); // bad checksum
    std::fs::write(key_dir.join("block_watermark"), buf).unwrap();

    let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
    assert_not_trusted(&mut hwm, &pkh);
}

/// A well-formed authenticated record signed under the wrong MAC key (a forgery
/// by a card thief without the PIN) is not trusted as a floor.
#[test]
fn test_forged_mac_not_trusted() {
    let temp_dir = TempDir::new().unwrap();
    let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();

    // Seed a valid 72-byte record, but under a MAC key the loader does not hold.
    let wrong_key = [0u8; 32];
    seed_watermarks(
        temp_dir.path(),
        &pkh,
        500,
        &wrong_key,
        default_test_chain_id(),
    )
    .unwrap();

    let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();
    assert_not_trusted(&mut hwm, &pkh);
}

/// A valid authenticated watermark is accepted and gates signing.
#[test]
fn test_valid_watermark_accepted() {
    let temp_dir = TempDir::new().unwrap();
    let (pkh, _pk, _sk) = generate_key(Some(&[42u8; 32])).unwrap();
    let chain_id = chain_id_from_index(1);

    preinit_watermarks(temp_dir.path(), &pkh, 99);
    let mut hwm = new_watermark(temp_dir.path(), &[pkh]).unwrap();

    let data = create_block_data(100, 0);
    assert!(
        hwm.check_and_update(chain_id, &pkh, &data).is_ok(),
        "Valid watermark should allow signing"
    );
}
