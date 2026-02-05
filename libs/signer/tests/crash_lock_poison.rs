//! Security Test: Lock Poisoning Crash Vulnerability
//!
//! This test demonstrates that the current `HighWatermark` implementation
//! will CRASH the entire application if any thread panics while holding
//! the cache lock.
//!
//! VULNERABILITY: Using `.unwrap()` on `RwLock` operations means that if
//! the lock becomes "poisoned" (a thread panicked while holding it),
//! all subsequent lock acquisitions will panic, crashing the signer.
//!
//! IMPACT: An attacker who can trigger a panic in the signing path
//! (e.g., via malformed data that causes an assertion failure) could
//! render the signer permanently unusable until restart.

use std::sync::{Arc, RwLock};
use std::thread;

/// Test that demonstrates what SHOULD happen with proper error handling
///
/// This test PASSES because it shows how to handle poisoned locks properly.
/// The fix should convert .`unwrap()` to this pattern.
#[test]
fn test_proper_poison_handling_recovers() {
    let lock = Arc::new(RwLock::new(42));
    let lock_clone = Arc::clone(&lock);

    // Thread that panics while holding write lock
    let handle = thread::spawn(move || {
        let _guard = lock_clone.write().unwrap();
        panic!("Panic while holding lock!");
    });

    let _ = handle.join();

    // With PROPER handling, we can recover instead of crashing:
    match lock.read() {
        Ok(_guard) => {
            panic!("Should not succeed - lock is poisoned");
        }
        Err(poisoned) => {
            // We can STILL access the data via into_inner()!
            let guard = poisoned.into_inner();
            assert_eq!(*guard, 42);
            // The signer should continue working, not crash!
        }
    }
}

/// Test showing data integrity is preserved even after poisoning
#[test]
fn test_poisoned_lock_data_is_recoverable() {
    let lock = Arc::new(RwLock::new(vec![1, 2, 3]));
    let lock_clone = Arc::clone(&lock);

    // Poison the lock after modifying data
    let handle = thread::spawn(move || {
        let mut guard = lock_clone.write().unwrap();
        guard.push(4); // Modify data before panic
        panic!("Oops!");
    });

    let _ = handle.join();

    // Even after poisoning, we can recover the data
    let result = lock.read();
    assert!(result.is_err(), "Lock should be poisoned");

    if let Err(poisoned) = result {
        let data = poisoned.into_inner();
        // The push(4) completed before the panic
        assert_eq!(*data, vec![1, 2, 3, 4]);
    }
}

/// Test that shows the cascading failure pattern
///
/// When one thread poisons a lock, ALL other threads that use .`unwrap()`
/// will crash when they try to access it.
#[test]
fn test_poison_affects_multiple_callers() {
    let lock = Arc::new(RwLock::new(0));
    let lock_clone = Arc::clone(&lock);

    // Poison the lock
    let handle = thread::spawn(move || {
        let _guard = lock_clone.write().unwrap();
        panic!("Poisoning!");
    });
    let _ = handle.join();

    // Multiple attempts to read all fail
    for i in 0..5 {
        let result = lock.read();
        assert!(
            result.is_err(),
            "Attempt {i} should fail - lock is poisoned"
        );
    }

    // Multiple attempts to write all fail too
    for i in 0..5 {
        let result = lock.write();
        assert!(
            result.is_err(),
            "Write attempt {i} should fail - lock is poisoned"
        );
    }
}

/// Demonstrates the exact pattern used in `high_watermark.rs` that should be fixed
///
/// Current code (VULNERABLE):
/// ```ignore
/// let cache = self.cache.write().unwrap();  // PANICS if poisoned!
/// ```
///
/// Fixed code (SAFE):
/// ```ignore
/// let cache = self.cache.write()
///     .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {}", e)))?;
/// ```
///
/// Or for recovery without error:
/// ```ignore
/// let cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
/// ```
#[test]
fn test_recommended_fix_pattern() {
    let lock = Arc::new(RwLock::new(100));
    let lock_clone = Arc::clone(&lock);

    // Poison it
    let handle = thread::spawn(move || {
        let _g = lock_clone.write().unwrap();
        panic!("poison");
    });
    let _ = handle.join();

    // Pattern 1: Return error (recommended for most cases)
    let result: Result<i32, String> = lock
        .read()
        .map(|guard| *guard)
        .map_err(|e| format!("Lock poisoned: {e}"));

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("poisoned"));

    // Pattern 2: Recover data anyway (for shutdown/cleanup scenarios)
    let value = lock
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(*value, 100);
}

// ============================================================================
// Note on HighWatermark implementation
// ============================================================================

// The tests above demonstrate the lock poisoning behavior with `.unwrap()`.
//
// The HighWatermark implementation has been fixed to handle lock poisoning
// properly using `.map_err()` to convert poisoned locks to WatermarkError::Internal.
// For example:
//
//   let mut cache = self.cache.write()
//       .map_err(|e| WatermarkError::Internal(format!("Lock poisoned: {e}")))?;
//
// This allows the signer to return an error instead of crashing if a lock
// becomes poisoned.
