//! Latency and key-generation measurements for the XMSS wrapper.
//!
//! Standalone and dependency-free so the same binary runs on the host, under
//! `qemu-aarch64`, and on the device.
//!
//! Usage: `bench sign <log2_range> <signatures>` | `bench keygen <log2_range>...`
//!        | `bench rebuild <samples> <log2_range>...`
//!        | `bench contend <samples> <sign_log2_range> <keygen_log2_range>`

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use russignol_xmss::{Epoch, SecretKey};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map_or("help", String::as_str) {
        "sign" => sign_latency(log2_range(args.get(1), 12), count(args.get(2), 200)),
        "keygen" => {
            for range in log2_ranges(&args[1..], &[10, 12, 14]) {
                keygen_cost(range);
            }
        }
        "rebuild" => {
            let samples = count(args.get(1), 60);
            for range in log2_ranges(&args[2..], &[14, 16]) {
                subtree_rebuild(range, samples);
            }
        }
        "contend" => keygen_contention(
            count(args.get(1), 100),
            log2_range(args.get(2), 14),
            log2_range(args.get(3), 24),
        ),
        _ => {
            eprintln!(
                "usage: bench sign <log2_range> <signatures> | bench keygen <log2_range>... \
                 | bench rebuild <samples> <log2_range>... \
                 | bench contend <samples> <sign_log2_range> <keygen_log2_range>"
            );
        }
    }
}

/// The base-2 log of a key's epoch count, and how many signatures a mode
/// takes. Distinct kinds because the modes read them in opposite orders —
/// `sign <log2_range> <signatures>` against `rebuild <samples> <log2_range>` —
/// so one integer type for both puts a transposition one argument away and
/// leaves the run reporting a range it never generated.
#[derive(Clone, Copy)]
struct Log2Range(u32);

#[derive(Clone, Copy)]
struct Count(NonZeroU32);

impl Log2Range {
    /// Largest range this bench can generate a key for. [`last_epoch`] computes
    /// `(1 << n) - 1` in [`Epoch`]'s own width and [`sign_latency`] takes
    /// `last + 1`, so a larger `n` wraps — in a release build silently, which
    /// is a run reporting a range it never generated.
    const MAX: u32 = 31;

    fn new(log2_range: u32) -> Option<Self> {
        (1..=Self::MAX)
            .contains(&log2_range)
            .then_some(Self(log2_range))
    }
}

impl core::fmt::Display for Log2Range {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl core::fmt::Display for Count {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// One range from the command line, or `fallback` where the argument is absent.
fn log2_range(arg: Option<&String>, fallback: u32) -> Log2Range {
    arg.map_or_else(
        || Log2Range::new(fallback).expect("a default range"),
        |value| {
            value
                .parse()
                .ok()
                .and_then(Log2Range::new)
                .unwrap_or_else(|| panic!("{value} is not a range in 1..={}", Log2Range::MAX))
        },
    )
}

/// Every range named on the command line, or `fallback` where none were.
///
/// A named range that will not parse ends the run rather than dropping out of
/// the list: running the defaults over what is left reports a measurement of
/// something other than what was asked for.
fn log2_ranges(args: &[String], fallback: &[u32]) -> Vec<Log2Range> {
    if args.is_empty() {
        return fallback
            .iter()
            .map(|n| Log2Range::new(*n).expect("a default range"))
            .collect();
    }
    args.iter()
        .map(|arg| {
            arg.parse()
                .ok()
                .and_then(Log2Range::new)
                .unwrap_or_else(|| panic!("{arg} is not a range in 1..={}", Log2Range::MAX))
        })
        .collect()
}

/// A sample count from the command line, or `fallback` where absent.
fn count(arg: Option<&String>, fallback: u32) -> Count {
    Count(arg.map_or_else(
        || NonZeroU32::new(fallback).expect("a default count"),
        |value| {
            value
                .parse()
                .ok()
                .and_then(NonZeroU32::new)
                .unwrap_or_else(|| panic!("{value} is not a sample count of 1 or more"))
        },
    ))
}

fn last_epoch(log2_range: Log2Range) -> Epoch {
    (1 << log2_range.0) - 1
}

/// Per-leaf cost is measured rather than derived from an assumed hash count,
/// so it can be multiplied out to any range without carrying an estimate.
fn keygen_cost(log2_range: Log2Range) {
    let last = last_epoch(log2_range);
    let leaves = f64::from(last) + 1.0;

    let start = Instant::now();
    let (sk, _) = SecretKey::generate([11u8; 32], 0, last).expect("valid range");
    let elapsed = start.elapsed();

    println!(
        "keygen 2^{log2_range:<2} leaves={:<9} wall={:>9.3}s  key={:>7}B  {:>7.1}us/leaf",
        leaves,
        elapsed.as_secs_f64(),
        sk.to_bytes().len(),
        elapsed.as_secs_f64() * 1e6 / leaves,
    );
}

fn sign_latency(log2_range: Log2Range, count: Count) {
    let last = last_epoch(log2_range);
    let gen_start = Instant::now();
    let (sk, pk) = SecretKey::generate([13u8; 32], 0, last).expect("valid range");
    println!(
        "sign 2^{log2_range} range, {count} signatures (keygen took {:.3}s)",
        gen_start.elapsed().as_secs_f64()
    );

    let payload = [0x42u8; 96];
    let mut samples: Vec<(Epoch, Duration)> = Vec::with_capacity(count.0.get() as usize);
    for epoch in 0..count.0.get().min(last + 1) {
        let start = Instant::now();
        let sig = sk.sign(epoch, Some(b"\x13"), &payload).expect("in range");
        samples.push((epoch, start.elapsed()));
        pk.verify(&sig, Some(b"\x13"), &payload)
            .expect("its own signature verifies");
    }

    let mut sorted: Vec<Duration> = samples.iter().map(|(_, d)| *d).collect();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    println!(
        "  p50={:>8.1}ms  p90={:>8.1}ms  p99={:>8.1}ms  max={:>8.1}ms  min={:>8.1}ms",
        ms(median),
        ms(sorted[sorted.len() * 90 / 100]),
        ms(sorted[sorted.len() * 99 / 100]),
        ms(sorted[sorted.len() - 1]),
        ms(sorted[0]),
    );

    // The bottom-subtree cache is rebuilt when an epoch crosses a subtree, so
    // the slow signatures should be evenly spaced. Report the spacing observed
    // rather than the split level, which upstream keeps private.
    let slow: Vec<Epoch> = samples
        .iter()
        .filter(|(_, d)| *d > median * 3)
        .map(|(e, _)| *e)
        .collect();
    if slow.is_empty() {
        println!("  no signature exceeded 3x the median");
    } else {
        let spacing: Vec<u32> = slow.windows(2).map(|w| w[1] - w[0]).collect();
        println!(
            "  {} slow signatures (>3x median) at epochs {:?}, spacing {:?}",
            slow.len(),
            &slow[..slow.len().min(8)],
            &spacing[..spacing.len().min(8)],
        );
    }
}

/// Isolate the bottom-subtree rebuild from the grinding tail it hides in.
///
/// Signing cost is a rebuild — paid only when the epoch's subtree is not one the
/// cache holds (`xmss.rs:357-369`) — plus a grinding loop whose latency is
/// geometrically distributed. Two sets drawn from one key separate them: every
/// signature in `crossing` rebuilds, no signature in `within` does, and both
/// draw the same grinding distribution. The minima are the sharp estimator, a
/// run of luck at the grinder leaving the rebuild alone standing.
fn subtree_rebuild(log2_range: Log2Range, samples: Count) {
    let last = last_epoch(log2_range);
    let gen_start = Instant::now();
    let (sk, pk) = SecretKey::generate([17u8; 32], 0, last).expect("valid range");
    let keygen = gen_start.elapsed();
    let width = sk.subtree_width();

    // `within` spends one subtree; `crossing` spends a fresh subtree per sample
    // and revisits none, so each of its signatures misses however many subtrees
    // the cache holds (`xmss.rs:39-40`) and pays the rebuild. A set that
    // revisits a subtree measures the rebuild only while the cache is smaller
    // than the set it revisits, which is a premise the cache's size can move.
    assert!(
        u64::from(samples.0.get()) < u64::from(width)
            && (u64::from(samples.0.get()) + 1) * u64::from(width) <= u64::from(last) + 1,
        "2^{log2_range} holds neither {samples} epochs under one subtree nor {samples} subtrees above it"
    );

    let payload = [0x42u8; 96];
    let sign = |epoch: Epoch| {
        let start = Instant::now();
        let sig = sk.sign(epoch, Some(b"\x13"), &payload).expect("in range");
        let elapsed = start.elapsed();
        pk.verify(&sig, Some(b"\x13"), &payload)
            .expect("its own signature verifies");
        elapsed
    };

    sign(0);
    let within = Samples::draw(samples, &sign);

    let crossing = Samples::draw(samples, |i| sign(i * width));

    // Printed beside the paired sets because it is the reading that looks like a
    // measurement and is not: a lone crossing sits among neighbours drawing the
    // same grinding distribution, which is several times the rebuild.
    let walk_start = width - 3;
    sign(walk_start - 1);
    let walk: Vec<(Epoch, Duration)> = (0..7)
        .map(|i| {
            let epoch = walk_start + i;
            (epoch, sign(epoch))
        })
        .collect();

    println!(
        "rebuild 2^{log2_range:<2} split={:<2} width={width:<5} n={samples} (keygen {:.3}s)",
        width.trailing_zeros(),
        keygen.as_secs_f64(),
    );
    let within = report("  within  ", &within);
    let crossing = report("  crossing", &crossing);
    println!(
        "  rebuild = {:>8.1}ms by min, {:>8.1}ms by p50, {:>8.1}ms by mean",
        crossing.min - within.min,
        crossing.p50 - within.p50,
        crossing.mean - within.mean,
    );
    println!(
        "  walk across the boundary at {}: {:?}",
        width,
        walk.iter()
            .map(|(e, d)| format!("{e}:{:.1}ms", ms(*d)))
            .collect::<Vec<_>>()
    );
}

/// One drawn set, held sorted and non-empty by construction: the order every
/// estimator below wants is taken once, and none of them is asked for a
/// statistic of nothing.
struct Samples(Vec<Duration>);

impl Samples {
    /// Draw one timing per epoch in `1..=count`, which `at` maps to the epoch
    /// it signs at.
    fn draw(count: Count, at: impl FnMut(u32) -> Duration) -> Self {
        let mut drawn: Vec<Duration> = (1..=count.0.get()).map(at).collect();
        drawn.sort_unstable();
        Self(drawn)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn min(&self) -> Duration {
        self.0[0]
    }

    fn p50(&self) -> Duration {
        self.0[self.0.len() / 2]
    }

    fn max(&self) -> Duration {
        self.0[self.0.len() - 1]
    }

    fn mean_ms(&self) -> f64 {
        let n = u32::try_from(self.0.len()).expect("a count drawn from a u32 fits one");
        self.0.iter().map(|d| ms(*d)).sum::<f64>() / f64::from(n)
    }
}

/// The three estimators a pair of sets is differenced on, returned rather than
/// left for the difference to take a second time: the rebuild is the gap between
/// the printed lines, so a change to how one of them is estimated has to move
/// both together.
struct Stats {
    min: f64,
    p50: f64,
    mean: f64,
}

/// What a key generation running beside a signer costs that signer.
///
/// Generation fans out over the worker pool, whose threads sit in the OS
/// background class, but the thread that opens a dispatch keeps its own — Linux
/// gives an unprivileged thread no way back out of `SCHED_IDLE` — so one core's
/// share runs at the signer's own weight. Shared-L2 pollution answers to no
/// scheduling class at all, which is why this is measured rather than argued.
///
/// Paired sets from one key: the same signing distribution drawn alone and
/// drawn under the generation, so the difference is the contention. The second
/// set is only a measurement while the generation outlasts it, which is what
/// `still_running` reads — a generation that finished early leaves part of the
/// set uncontended and understates the cost.
fn keygen_contention(samples: Count, signing: Log2Range, generating: Log2Range) {
    russignol_xmss::deprioritize_key_generation();

    let last = last_epoch(signing);
    let highest_drawn = u64::from(samples.0.get()) * 2;
    assert!(
        highest_drawn <= u64::from(last),
        "2^{signing} holds no epoch {highest_drawn}, which the second set draws"
    );

    let gen_start = Instant::now();
    let (sk, pk) = SecretKey::generate([23u8; 32], 0, last).expect("valid range");
    println!(
        "contend sign 2^{signing} keygen 2^{generating} n={samples} (signing key took {:.3}s)",
        gen_start.elapsed().as_secs_f64(),
    );

    let payload = [0x42u8; 96];
    let sign = |epoch: Epoch| {
        let start = Instant::now();
        let sig = sk.sign(epoch, Some(b"\x13"), &payload).expect("in range");
        let elapsed = start.elapsed();
        pk.verify(&sig, Some(b"\x13"), &payload)
            .expect("its own signature verifies");
        elapsed
    };

    let alone = Samples::draw(samples, &sign);

    let finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let start = Instant::now();
            let outcome = SecretKey::generate([29u8; 32], 0, last_epoch(generating));
            finished.store(true, Ordering::Release);
            let ran = start.elapsed().as_secs_f64();
            match outcome {
                Ok(_) => println!("  the generation ran {ran:.1}s and finished on its own"),
                // Aborts the run rather than leaving it to be read: the panic
                // reaches the parent when the scope joins, and the load the two
                // sets were to be compared under never existed.
                Err(e) => panic!("the generation failed after {ran:.1}s: {e}"),
            }
        });

        let contended = Samples::draw(samples, |i| sign(samples.0.get() + i));
        let still_running = !finished.load(Ordering::Acquire);

        // Reported here rather than past the scope, which does not return until
        // the generation does: both sets are drawn by now, and holding their
        // numbers back for the rest of a generation measured in tens of minutes
        // is a wait for nothing either of them is still waiting on.
        let alone = report("  alone   ", &alone);
        let contended = report("  contended", &contended);
        println!(
            "  contention = {:>8.1}ms by min, {:>8.1}ms by p50, {:>8.1}ms by mean",
            contended.min - alone.min,
            contended.p50 - alone.p50,
            contended.mean - alone.mean,
        );
        if !still_running {
            println!(
                "  INVALID: the generation was no longer running when the contended set \
                 ended, so part of that set was drawn against an idle machine"
            );
        }
    });
}

fn report(label: &str, samples: &Samples) -> Stats {
    let stats = Stats {
        min: ms(samples.min()),
        p50: ms(samples.p50()),
        mean: samples.mean_ms(),
    };
    println!(
        "{label} n={:<4} min={:>8.1}ms  p50={:>8.1}ms  mean={:>8.1}ms  max={:>8.1}ms",
        samples.len(),
        stats.min,
        stats.p50,
        stats.mean,
        ms(samples.max()),
    );
    stats
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}
