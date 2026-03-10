# Probability Analysis: Watermark Crash-Induced Double-Signing

## Context

The old watermark design (before commit 6ddac3d) returned the signature over TCP before
persisting the watermark to disk, and never called fsync. A power loss could therefore
leave the on-disk watermark stale, theoretically allowing a re-request at the same level
to be granted.

This analysis examines the probability that this vulnerability could have been exploited,
and describes how the redesign eliminated it.

## The Old Signing Flow (pre-6ddac3d)

Traced from the old `server.rs` and `high_watermark.rs`:

```
handle_connection() loop:
  1. process_request()
     a. Decode request
     b. handle_sign():
        i.   check_and_update() -> in-memory watermark check + advance (no disk I/O)
        ii.  BLS sign -> signature generated
        iii. update_signature() -> store signature string in-memory cache
     c. Encode response
     d. TCP write -> signature sent to baker           <- BAKER HAS SIGNATURE
     e. Return sign_info (pkh, chain_id)
  2. flush_watermark_if_needed(sign_info)              <- DISK WRITE HAPPENS HERE
     a. flush_to_disk() -> save_watermark()
        i.   Read existing JSON from disk
        ii.  serde_json parse
        iii. Update JSON structure
        iv.  serde_json pretty-print
        v.   fs::write() (NO fsync!)                   <- DATA IN PAGE CACHE ONLY
```

## The Vulnerabilities

**V1: Signature returned before disk write**

- The TCP write (step 1d) sends the signature to the baker
- The disk write (step 2) happens AFTER the TCP response
- **Critical window**: from TCP write until fs::write completes
- Duration: ~1-5ms (JSON serialization + fs::write)

**V2: No fsync -- data may never reach stable storage**

- `fs::write()` writes to the OS page cache, NOT to the SD card
- Without fsync, dirty pages are flushed by the kernel writeback thread
- No custom `dirty_writeback_centisecs`/`dirty_expire_centisecs` in kernel config, so
  Linux defaults apply: writeback runs every 5s, dirty pages expire after 30s
- Note: `fsync_mode=strict` IS set on the data partition (both hardened init and dev
  fstab), but this only makes fsync calls more thorough when they ARE made -- it does
  not add automatic fsync. Since the old code never calls fsync, this setting is
  irrelevant.
- **Effective critical window**: from TCP write until kernel writeback -- potentially
  **5-30 seconds**

**NOT a vulnerability: Corrupt JSON handling**

- On LOAD: `load_operation_watermark()` returns `None` when JSON is corrupt or empty
- `check_and_update_operation()` checks:
  `let Some(current_wm) = wm.get(op_type) else { return Err(WatermarkError::NotInitialized) }`
- **Corrupt files BLOCK signing** -- the signer refuses to sign, not silently accepts
- The `serde_json::json!({})` reinitialization in `save_operation_watermark()` only
  applies during WRITING (it rebuilds the file structure before inserting the current
  watermark value), not during the safety-critical LOADING path

## Crash Recovery Scenarios

What happens to the watermark file after a crash (power loss during/after `fs::write`)?

| Scenario | File state after recovery | Signing behavior |
|----------|--------------------------|-----------------|
| Power loss before `fs::write` | Old content (previous level M) | **Re-signing allowed** (M < N) |
| Power loss during `fs::write` (truncate flushed, data not) | Empty (0 bytes) | Signing **blocked** (NotInitialized) |
| Power loss during `fs::write` (partial data) | Corrupt JSON | Signing **blocked** (NotInitialized) |
| Power loss after `fs::write`, before writeback | Old content (page cache lost) | **Re-signing allowed** (M < N) |
| Power loss after writeback | New content (level N) | Safe |

The exploitable cases are 1 and 4: the file retains the old watermark, and the signer
loads the old level M, accepting a new signing request at level N (since M < N).

## The Event Chain Required for Double-Signing

For a crash to lead to double-signing, ALL of these must happen:

1. Crash occurs in the critical window (after signature returned to baker, before
   watermark persisted to stable storage)
2. Baker publishes the block using that signature
3. Device reboots and signer becomes ready
4. Same baker requests the same level/round again
5. Signer accepts (watermark reverted to pre-crash value)
6. All within the 6-second Tezos block window

## Link-by-Link Probability Analysis

### Link 1: P(crash in critical window) -- NON-ZERO

The old design had a real vulnerability window.

**Minimum window** (between TCP write and fs::write completion): ~1-5ms

**Maximum window** (between TCP write and OS writeback): ~5-30 seconds

Using the conservative minimum window of 1ms:

- 1 crash/month = 1 crash per 2,592,000,000 ms
- Signing events per month: ~3 sigs/block x ~100 blocks = ~300 signing events
- P(crash during 1ms window per event) = 1 / 2,592,000,000
- P(crash in any signing window in a month) = 300 / 2,592,000,000 = **1.16 x 10^-7**

Using the realistic window (no fsync, ~5 seconds until writeback):

- P(crash during 5s window per event) = 5,000 / 2,592,000,000
- P(crash in any signing window in a month) = 300 x 5,000 / 2,592,000,000 =
  **5.79 x 10^-4**

**P(crash in critical window) ~ 10^-7 to 10^-4 per month** (depending on writeback
timing)

### Link 2: P(reboot + key derivation + ready within 6s) = 0

The minimum reboot time far exceeds the block window:

| Phase | Duration |
|-------|----------|
| Kernel boot (minimal Buildroot, Pi Zero 2W) | ~1s |
| Init + mount + PIN screen ready | ~2.8s |
| Scrypt key derivation (log_n=18, r=8, p=4, 256MB) | **8-10s** |
| Watermark load + TCP listen | <1s |
| **Total minimum** | **~12-14s** |

The 6-second Tezos block window expires ~2x over before the signer is ready.

**P(device ready within 6s) = 0** -- physically impossible on this hardware.

This single link breaks the chain entirely.

### Link 3: P(baker re-requests same level) ~ 0

Even ignoring the reboot time:

- The baker connects via USB gadget ethernet (169.254.1.1:7732)
- USB connection drops on reboot -- baker must re-establish link-local TCP
- Baker software (Octez) would have moved to the next level
- The original block at level N was already published and attested
- A malicious baker would need to independently construct a different block at (N, R)

**P ~ 0** for legitimate baker; requires malicious/compromised baker software.

### Link 4: P(stale watermark enables re-signing) ~ 0.5-0.9

If the crash leaves the file with OLD content (not corrupt/empty):

- Signer loads old level M < N -> accepts signing at level N -> **re-signing allowed**
- **P ~ 1.0** if file reverts to old content

If the crash leaves the file corrupt or empty:

- `load_operation_watermark()` returns `None` -> `NotInitialized` error -> **signing
  blocked**
- **P = 0** (safe, but causes liveness issue)

The most likely case (crash before writeback flushes dirty pages) leaves old content on
disk -- the exploitable scenario.

## Combined Probability

P(double-sign) = P(crash in window) x P(ready in 6s) x P(re-request)
x P(stale enables re-sign)

= **~6 x 10^-4** x **0** x **~0** x **~0.7**

= **0** (saved by reboot time alone)

## Why the Old Design Was Still Safe in Practice

Despite having a real vulnerability window (V1 + V2), double-signing was prevented by
a single accidental defense: **the device takes 12-14 seconds to reboot**, far exceeding
the 6-second Tezos block window.

This is defense by coincidence, not by design:

- The scrypt key derivation (8-10s) is the dominant factor
- It exists for brute-force resistance, not crash safety
- A faster device or weaker KDF parameters would eliminate this protection

Note: Corrupt/empty watermark files were handled safely --
`load_operation_watermark()` returns `None`, causing
`WatermarkError::NotInitialized` which blocks signing entirely.

### Without the Reboot Defense

If we hypothetically remove the reboot time barrier (instant reboot), the probability
per month would have been:

- **~5.79 x 10^-4** (crash in writeback window) x **~0.7** (stale file, not corrupt)
  = **~4 x 10^-4 per month**
- That's roughly **once per 208 years** of continuous operation

---

## How the Redesign Fixed It (6ddac3d)

| Aspect | Old Design | New Design (6ddac3d) |
|--------|-----------|---------------------|
| Signature returned | **Before** disk write | **After** fdatasync |
| Fsync | **Never called** (fsync_mode=strict irrelevant) | fdatasync on every write |
| Critical window | **~1ms to 30s** (real) | **0** (by construction) |
| File format | JSON (variable size, complex parse) | 40-byte binary (fixed, atomic pwrite) |
| Corruption handling | Returns `None` -> blocks signing | Fatal error + halt |
| Integrity check | JSON parse only | Blake3 hash |
| Concurrency | Separate check/sign/write steps | Write lock held check -> sign -> persist |
| Double-sign safety | Relies on 12-14s reboot time | Guaranteed by write ordering |

The redesign eliminated the vulnerability at the source:

**Slow path** (no ceiling on disk -- e.g., first sign after boot):

- BLS sign and `write_watermark()` run in parallel via `thread::scope`
- If watermark write fails, signature is **refused** -- never returned
- Signature only returned after both threads join successfully
- `fdatasync` completes **before** the signature reaches the baker
- **Critical window: 0**

**Fast path** (ceiling on disk covers the update):

- Only BLS sign runs, no disk I/O
- `ceiling_covers()` only returns true if the disk already has a value **strictly
  higher** than the signed level (ceilings are written as `(level+1, u32::MAX)`)
- On crash: disk loads the ceiling which blocks the signed level and below
- **Critical window: 0** (disk already has a safe value)

**Corruption handling:**

- `load_entry_strict()`: size != 40 or Blake3 hash mismatch -> `InvalidData` error
- Signer **refuses to boot** -- no signing until manual re-initialization

The current design's safety does not depend on boot time, hardware speed, or any
external factor. P(double-sign) = 0 by construction.
