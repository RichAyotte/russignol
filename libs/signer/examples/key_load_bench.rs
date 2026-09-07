//! Where a key's load at unlock spends its time.
//!
//! `Unencrypted::from_b58check` runs on every entry of the store between the
//! PIN and the signer listening, and a tz6 entry is hundreds of thousands of
//! characters where a tz4 one is 58. The phases inside it are timed apart —
//! the base58 decode, the checksum, the deserialize — so a figure says which
//! of them the load is rather than that it is slow.
//!
//! Usage: `key_load_bench write <log2_range> <path>`
//!        | `key_load_bench read <path>...`
//!
//! `write` generates a key from a fixed seed and puts its `xmsk` value in a
//! file, and `read` times the load of the value a file holds, so a device that
//! takes 41 minutes to generate a 2^24 key loads one the host wrote. The value
//! is key material only in shape: the seed is a constant, and nothing signs
//! under it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use russignol_signer_lib::signer::Unencrypted;
use russignol_signer_lib::xmss::{Epoch, SecretKey as XmssSecretKey, XMSK_PREFIX};
use russignol_signer_lib::{SecretKey, base58};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// The base-2 log of a key's epoch count, in `1..=31`: [`Self::last_epoch`]
/// computes `(1 << n) - 1` in [`Epoch`]'s own width, and a larger `n` wraps.
#[derive(Clone, Copy)]
struct Log2Range(u32);

impl Log2Range {
    const MAX: u32 = 31;

    fn parse(arg: &str) -> Option<Self> {
        arg.parse()
            .ok()
            .filter(|n| (1..=Self::MAX).contains(n))
            .map(Self)
    }

    fn last_epoch(self) -> Epoch {
        (1 << self.0) - 1
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match (args.first().map(String::as_str), &args[1.min(args.len())..]) {
        (Some("write"), [log2_range, path]) => match Log2Range::parse(log2_range) {
            Some(log2_range) => write(log2_range, path),
            None => usage(),
        },
        (Some("read"), paths) if !paths.is_empty() => {
            for path in paths {
                read(path);
            }
        }
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: key_load_bench write <log2_range in 1..={}> <path> | key_load_bench read <path>...",
        Log2Range::MAX
    );
    std::process::exit(2)
}

fn write(log2_range: Log2Range, path: &str) {
    let start = Instant::now();
    let (secret, _) =
        XmssSecretKey::generate([31u8; 32], 0, log2_range.last_epoch()).expect("valid range");
    let xmsk = Zeroizing::new(SecretKey::Xmss(Arc::new(secret)).to_b58check());
    std::fs::write(path, xmsk.as_bytes()).expect("the path is writable");
    println!(
        "wrote 2^{} key of {} chars to {path} (keygen {:.3}s)",
        log2_range.0,
        xmsk.len(),
        start.elapsed().as_secs_f64(),
    );
}

/// Time the load of the value at `path`, then each phase of it on its own.
///
/// The phases are what `Unencrypted::from_b58check` does in order: the base58
/// decode into bytes, the double-SHA256 checksum over them, the `bincode`
/// deserialize of the payload, and the public key and its hash off the result.
/// Each is run again outside the load rather than read out of it, the load
/// having no seam to time at. The encode of the loaded key is timed last: it
/// is not on the load path, but provisioning pays it once to write the store.
fn read(path: &str) {
    let xmsk = Zeroizing::new(std::fs::read_to_string(path).expect("the path is readable"));
    let chars = u32::try_from(xmsk.len()).expect("a base58 value shorter than 2^32");

    let (signer, whole) =
        timed(|| Unencrypted::from_b58check(&xmsk).expect("a value write put down"));
    let SecretKey::Xmss(secret) = signer.secret_key() else {
        panic!("{path} holds no xmsk value");
    };

    let (decoded, decode) = timed(|| base58::decode(&xmsk).expect("base58"));
    let bytes = u32::try_from(decoded.len()).expect("fewer bytes than characters");
    let body = &decoded[..decoded.len() - 4];
    let (_, checksum) = timed(|| std::hint::black_box(Sha256::digest(Sha256::digest(body))));
    let (_, deserialize) = timed(|| {
        std::hint::black_box(
            XmssSecretKey::from_bytes(&body[XMSK_PREFIX.len()..]).expect("the bytes the load read"),
        )
    });
    let (_, derive) = timed(|| std::hint::black_box(secret.public_key().hash()));
    let (_, encode) = timed(|| Zeroizing::new(signer.secret_key().to_b58check()));

    // A base conversion touches every limb produced so far once per group of
    // digits, so the decode is normalized by the product of the two lengths;
    // a figure holding across ranges says nothing else in it grows faster.
    let pairs = f64::from(chars) * f64::from(bytes);

    println!("load {path}: chars={chars} bytes={bytes}");
    println!("  whole       = {:>10.1}ms", ms(whole));
    println!(
        "  decode      = {:>10.1}ms  {:5.1}% of the load, {:.3}ns per character-byte pair",
        ms(decode),
        share(decode, whole),
        decode.as_secs_f64() * 1e9 / pairs,
    );
    println!("  checksum    = {:>10.1}ms", ms(checksum));
    println!("  deserialize = {:>10.1}ms", ms(deserialize));
    println!("  derive      = {:>10.1}ms", ms(derive));
    println!(
        "  residual    = {:>10.1}ms",
        ms(whole) - ms(decode) - ms(checksum) - ms(deserialize) - ms(derive),
    );
    println!(
        "  encode      = {:>10.1}ms  off the load path; what writing the store pays",
        ms(encode)
    );
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let value = f();
    (value, start.elapsed())
}

fn share(part: Duration, whole: Duration) -> f64 {
    part.as_secs_f64() / whole.as_secs_f64() * 100.0
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}
