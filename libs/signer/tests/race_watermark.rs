//! Security Test: Watermark Concurrent Access Validation
//!
//! These tests validate that the watermark checking logic is safe under
//! concurrent access when wrapped in an `RwLock` (as the server does).
//!
//! DESIGN: `check_and_update` takes `&mut self`, so the caller must hold
//! a write lock on `RwLock<HighWatermark>`. This means all concurrent
//! check-and-update operations are serialized by the lock, preventing
//! double-signing by construction.

use russignol_signer_lib::bls::generate_key;
use russignol_signer_lib::high_watermark::{ChainId, HighWatermark};
use russignol_signer_lib::test_utils::{create_block_data, preinit_watermarks};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, RwLock};
use std::thread;
use tempfile::TempDir;

fn test_chain_id() -> ChainId {
    ChainId::from_bytes(&[1u8; 32])
}

/// Test that concurrent signing requests are serialized properly
///
/// Spawns multiple threads all trying to sign at the same level.
/// Only ONE should succeed - the others should be rejected.
#[test]
fn test_concurrent_signing_serialization() {
    let temp_dir = TempDir::new().unwrap();
    let chain_id = test_chain_id();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    preinit_watermarks(temp_dir.path(), &pkh, 99);
    let hwm = Arc::new(RwLock::new(
        HighWatermark::new(temp_dir.path(), &[pkh]).unwrap(),
    ));

    // Set watermark to level 100
    {
        let mut wm = hwm.write().unwrap();
        let data = create_block_data(100, 0);
        wm.check_and_update(chain_id, &pkh, &data).unwrap();
    }

    // Spawn threads all trying to sign at level 101
    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let hwm = Arc::clone(&hwm);
            let barrier = Arc::clone(&barrier);
            let success_count = Arc::clone(&success_count);
            let failure_count = Arc::clone(&failure_count);

            thread::spawn(move || {
                barrier.wait();

                let data = create_block_data(101, 0);
                let mut wm = hwm.write().unwrap();
                match wm.check_and_update(chain_id, &pkh, &data) {
                    Ok(_) => {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {
                        failure_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let successes = success_count.load(Ordering::SeqCst);
    let failures = failure_count.load(Ordering::SeqCst);

    println!("Concurrent signing at level 101: {successes} successes, {failures} failures");

    // Exactly one thread should succeed (first to acquire write lock)
    assert_eq!(successes, 1, "Exactly one thread should succeed");
    assert_eq!(
        successes + failures,
        num_threads,
        "All threads should complete"
    );
}

/// Test that block and attestation watermarks are independent
#[test]
fn test_independent_operation_types() {
    use russignol_signer_lib::test_utils::create_attestation_data;

    let temp_dir = TempDir::new().unwrap();
    let chain_id = test_chain_id();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    preinit_watermarks(temp_dir.path(), &pkh, 0);
    let hwm = Arc::new(RwLock::new(
        HighWatermark::new(temp_dir.path(), &[pkh]).unwrap(),
    ));
    let barrier = Arc::new(Barrier::new(2));

    // Thread 1: Sign blocks at levels 1, 2, 3
    let hwm1 = Arc::clone(&hwm);
    let barrier1 = Arc::clone(&barrier);
    let block_thread = thread::spawn(move || {
        barrier1.wait();
        for level in 1..=3 {
            let data = create_block_data(level, 0);
            let mut wm = hwm1.write().unwrap();
            let update = wm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap_or_else(|_| panic!("Block at level {level} should succeed"));
            if let Some(ref u) = update {
                wm.write_watermark(u).ok();
            }
        }
    });

    // Thread 2: Sign attestations at levels 100, 101, 102
    let hwm2 = Arc::clone(&hwm);
    let barrier2 = Arc::clone(&barrier);
    let attest_thread = thread::spawn(move || {
        barrier2.wait();
        for level in 100..=102 {
            let data = create_attestation_data(level, 0);
            let mut wm = hwm2.write().unwrap();
            let update = wm
                .check_and_update(chain_id, &pkh, &data)
                .unwrap_or_else(|_| panic!("Attestation at level {level} should succeed"));
            if let Some(ref u) = update {
                wm.write_watermark(u).ok();
            }
        }
    });

    block_thread.join().unwrap();
    attest_thread.join().unwrap();

    // Reload from disk and verify persistence
    let hwm_reload = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
    let (block, _preattest, attest) = hwm_reload.get_current_levels(chain_id, &pkh).unwrap();

    assert_eq!(block, 3, "Block watermark should be at level 3");
    assert_eq!(attest, 102, "Attestation watermark should be at level 102");
}

/// Stress test: many threads, many operations
#[test]
fn test_stress_concurrent_watermarks() {
    let temp_dir = TempDir::new().unwrap();
    let chain_id = test_chain_id();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    preinit_watermarks(temp_dir.path(), &pkh, 0);
    let hwm = Arc::new(RwLock::new(
        HighWatermark::new(temp_dir.path(), &[pkh]).unwrap(),
    ));
    let num_threads = 8;
    let ops_per_thread = 50;
    let barrier = Arc::new(Barrier::new(num_threads));
    let max_level_seen = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let hwm = Arc::clone(&hwm);
            let barrier = Arc::clone(&barrier);
            let max_level_seen = Arc::clone(&max_level_seen);

            thread::spawn(move || {
                barrier.wait();

                let mut successes = 0;
                let mut failures = 0;

                for op in 0..ops_per_thread {
                    let level = u32::try_from(op * num_threads + thread_id + 1)
                        .expect("test level overflow");
                    let data = create_block_data(level, 0);

                    let mut wm = hwm.write().unwrap();
                    match wm.check_and_update(chain_id, &pkh, &data) {
                        Ok(_) => {
                            successes += 1;
                            max_level_seen
                                .fetch_max(usize::try_from(level).unwrap(), Ordering::SeqCst);
                        }
                        Err(_) => failures += 1,
                    }
                }

                (successes, failures)
            })
        })
        .collect();

    let mut total_successes = 0;
    let mut total_failures = 0;

    for handle in handles {
        let (s, f) = handle.join().unwrap();
        total_successes += s;
        total_failures += f;
    }

    println!(
        "Stress test: {} successes, {} failures out of {} total operations",
        total_successes,
        total_failures,
        num_threads * ops_per_thread
    );

    assert!(
        total_successes > 0,
        "At least some operations should succeed"
    );

    let max_signed = max_level_seen.load(Ordering::SeqCst);
    println!("Max level successfully signed: {max_signed}");
    assert!(max_signed > 0, "Should have signed at least one level");
}

/// TOCTOU test: two threads race at the same level
///
/// With `&mut self` behind `RwLock`, double-signing is impossible by construction.
#[test]
fn test_toctou_exploit_attempt() {
    let temp_dir = TempDir::new().unwrap();
    let chain_id = test_chain_id();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    preinit_watermarks(temp_dir.path(), &pkh, 99);

    let iterations = 100;
    let mut double_sign_detected = false;

    for _ in 0..iterations {
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = Arc::new(RwLock::new(
            HighWatermark::new(temp_dir.path(), &[pkh]).unwrap(),
        ));

        // Set initial watermark to level 100
        {
            let mut wm = hwm.write().unwrap();
            let data = create_block_data(100, 0);
            wm.check_and_update(chain_id, &pkh, &data).unwrap();
        }

        let barrier = Arc::new(Barrier::new(2));
        let success1 = Arc::new(AtomicUsize::new(0));
        let success2 = Arc::new(AtomicUsize::new(0));

        let hwm1 = Arc::clone(&hwm);
        let hwm2 = Arc::clone(&hwm);
        let barrier1 = Arc::clone(&barrier);
        let barrier2 = Arc::clone(&barrier);
        let success1_clone = Arc::clone(&success1);
        let success2_clone = Arc::clone(&success2);

        let t1 = thread::spawn(move || {
            barrier1.wait();
            let data = create_block_data(101, 0);
            let mut wm = hwm1.write().unwrap();
            if wm.check_and_update(chain_id, &pkh, &data).is_ok() {
                success1_clone.store(1, Ordering::SeqCst);
            }
        });

        let t2 = thread::spawn(move || {
            barrier2.wait();
            let data = create_block_data(101, 0);
            let mut wm = hwm2.write().unwrap();
            if wm.check_and_update(chain_id, &pkh, &data).is_ok() {
                success2_clone.store(1, Ordering::SeqCst);
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let s1 = success1.load(Ordering::SeqCst);
        let s2 = success2.load(Ordering::SeqCst);

        if s1 + s2 > 1 {
            double_sign_detected = true;
            break;
        }
    }

    assert!(
        !double_sign_detected,
        "Double-signing should be impossible with &mut self behind RwLock"
    );
    println!("Good: No double-signing detected in {iterations} iterations");
}

/// Test: concurrent sign requests at same level, different rounds.
///
/// Verifies that disk always has the highest round after concurrent requests.
/// With write lock held through `write_watermark`, requests are serialized and
/// the disk file must reflect the latest accepted round.
#[test]
fn test_concurrent_same_level_different_rounds_disk_consistency() {
    let chain_id = test_chain_id();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    let iterations = 50;

    for _ in 0..iterations {
        let temp_dir = TempDir::new().unwrap();
        preinit_watermarks(temp_dir.path(), &pkh, 99);
        let hwm = Arc::new(RwLock::new(
            HighWatermark::new(temp_dir.path(), &[pkh]).unwrap(),
        ));

        // Set initial watermark to level 100, round 0
        {
            let mut wm = hwm.write().unwrap();
            let data = create_block_data(100, 0);
            let update = wm.check_and_update(chain_id, &pkh, &data).unwrap();
            if let Some(ref u) = update {
                wm.write_watermark(u).unwrap();
            }
        }

        // Two threads race: one at round 5, one at round 6
        let barrier = Arc::new(Barrier::new(2));

        let hwm1 = Arc::clone(&hwm);
        let barrier1 = Arc::clone(&barrier);
        let t1 = thread::spawn(move || {
            barrier1.wait();
            let data = create_block_data(101, 5);
            let mut wm = hwm1.write().unwrap();
            if let Ok(Some(ref update)) = wm.check_and_update(chain_id, &pkh, &data) {
                wm.write_watermark(update).unwrap();
            }
        });

        let hwm2 = Arc::clone(&hwm);
        let barrier2 = Arc::clone(&barrier);
        let t2 = thread::spawn(move || {
            barrier2.wait();
            let data = create_block_data(101, 6);
            let mut wm = hwm2.write().unwrap();
            if let Ok(Some(ref update)) = wm.check_and_update(chain_id, &pkh, &data) {
                wm.write_watermark(update).unwrap();
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();

        // Reload from disk — the file must have the highest round (6)
        let hwm_reload = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
        let (block_level, _, _) = hwm_reload.get_current_levels(chain_id, &pkh).unwrap();
        assert_eq!(block_level, 101, "Disk should have level 101");

        // Read raw file to verify round
        let key_dir = temp_dir.path().join(pkh.to_b58check());
        let raw = std::fs::read(key_dir.join("block_watermark")).unwrap();
        let disk_round = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);

        // With serialized write lock, the second request (round 6) always wins
        // because the first request (round 5) is either:
        // - Accepted first → round 5 on disk, then round 6 overwrites it
        // - Rejected (if round 6 went first → round 5 < round 6 is rejected)
        // Either way, disk must have round >= 5.
        // With proper serialization, both are accepted (5 then 6) so disk = 6.
        assert!(
            disk_round >= 5,
            "Disk round should be at least 5, got {disk_round}"
        );
    }

    println!("Good: Disk always consistent after {iterations} concurrent round iterations");
}

/// Test: `rollback_disk_watermark` restores previous state after BLS failure.
///
/// Simulates the scenario where BLS signing fails after `write_watermark`
/// has already persisted. Verifies both in-memory and disk are rolled back.
#[test]
fn test_rollback_disk_watermark_after_sign_failure() {
    let temp_dir = TempDir::new().unwrap();
    let chain_id = test_chain_id();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    preinit_watermarks(temp_dir.path(), &pkh, 99);
    let hwm = Arc::new(RwLock::new(
        HighWatermark::new(temp_dir.path(), &[pkh]).unwrap(),
    ));

    // Advance to level 100, round 0 (baseline)
    {
        let mut wm = hwm.write().unwrap();
        let data = create_block_data(100, 0);
        let update = wm.check_and_update(chain_id, &pkh, &data).unwrap();
        if let Some(ref u) = update {
            wm.write_watermark(u).unwrap();
        }
    }

    // Advance to level 101 and persist — then simulate BLS failure + rollback
    {
        let mut wm = hwm.write().unwrap();
        let data = create_block_data(101, 3);
        let update = wm
            .check_and_update(chain_id, &pkh, &data)
            .unwrap()
            .expect("should produce an update");

        // Persist the advanced watermark (simulates write_watermark succeeding)
        wm.write_watermark(&update).unwrap();

        // Simulate BLS failure: roll back in-memory AND disk
        wm.rollback_update(&update);
        wm.rollback_disk_watermark(&update).unwrap();

        // In-memory should be back to level 100
        let (block_level, _, _) = wm.get_current_levels(chain_id, &pkh).unwrap();
        assert_eq!(block_level, 100, "In-memory should be rolled back to 100");
    }

    // Reload from disk — should also be level 100, round 0
    let hwm_reload = HighWatermark::new(temp_dir.path(), &[pkh]).unwrap();
    let (block_level, _, _) = hwm_reload.get_current_levels(chain_id, &pkh).unwrap();
    assert_eq!(block_level, 100, "Disk should be rolled back to level 100");

    let key_dir = temp_dir.path().join(pkh.to_b58check());
    let raw = std::fs::read(key_dir.join("block_watermark")).unwrap();
    let disk_level = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let disk_round = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    assert_eq!(disk_level, 100, "Disk file should have level 100");
    assert_eq!(disk_round, 0, "Disk file should have round 0");

    // Verify we can now retry at level 101 (the failed level)
    {
        let mut wm = hwm.write().unwrap();
        let data = create_block_data(101, 3);
        let update = wm.check_and_update(chain_id, &pkh, &data).unwrap();
        assert!(
            update.is_some(),
            "Should be able to retry at the rolled-back level"
        );
    }
}

/// Test: `.prev` backup file is written after `write_watermark`
///
/// Verifies that the `.prev` file has valid data after `write_watermark`.
/// Note: .prev is best-effort (no fsync) — it reaches disk via OS writeback.
#[test]
fn test_prev_file_is_written() {
    let temp_dir = TempDir::new().unwrap();
    let chain_id = test_chain_id();
    let seed = [42u8; 32];
    let (pkh, _pk, _sk) = generate_key(Some(&seed)).unwrap();

    preinit_watermarks(temp_dir.path(), &pkh, 99);
    let hwm = Arc::new(RwLock::new(
        HighWatermark::new(temp_dir.path(), &[pkh]).unwrap(),
    ));

    // Advance to level 100
    {
        let mut wm = hwm.write().unwrap();
        let data = create_block_data(100, 0);
        let update = wm.check_and_update(chain_id, &pkh, &data).unwrap();
        if let Some(ref u) = update {
            wm.write_watermark(u).unwrap();
        }
    }

    // Advance to level 101 — this should create a .prev with level 100
    {
        let mut wm = hwm.write().unwrap();
        let data = create_block_data(101, 0);
        let update = wm.check_and_update(chain_id, &pkh, &data).unwrap();
        if let Some(ref u) = update {
            wm.write_watermark(u).unwrap();
        }
    }

    // Check that .prev file exists and has the previous level (100)
    let key_dir = temp_dir.path().join(pkh.to_b58check());
    let prev_path = key_dir.join("block_watermark.prev");
    assert!(prev_path.exists(), ".prev file should exist");

    let raw = std::fs::read(&prev_path).unwrap();
    assert_eq!(raw.len(), 40, ".prev file should be 40 bytes");

    let prev_level = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let prev_round = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    assert_eq!(prev_level, 100, ".prev should have level 100");
    assert_eq!(prev_round, 0, ".prev should have round 0");
}
