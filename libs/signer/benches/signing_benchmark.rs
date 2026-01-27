//! Performance benchmarks for russignol-signer
//!
//! These benchmarks target Raspberry Pi Zero 2W (ARM Cortex-A53) performance
//! characteristics, focusing on:
//! - BLS12-381 signing latency
//! - Key generation performance
//! - Deterministic nonce computation
//! - Base58check encoding/decoding overhead

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use russignol_signer_lib::{SignerHandler, UnencryptedSigner};
use std::hint::black_box;

/// Benchmark BLS12-381 signing performance
fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLS12-381 Signing");

    // Create test signer
    let seed = [42u8; 32];
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();
    let handler = SignerHandler::new_tenderbake_only(signer);

    // Benchmark different message sizes
    for size in &[32, 64, 128, 256, 512, 1024, 2048] {
        let mut data = vec![0x11u8; *size]; // Tenderbake block magic byte + data
        data[0] = 0x11;

        group.bench_with_input(BenchmarkId::new("sign", size), size, |b, _| {
            b.iter(|| handler.sign(black_box(&data), None, None).unwrap());
        });
    }

    group.finish();
}

/// Benchmark signature verification performance
fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLS12-381 Verification");

    let seed = [42u8; 32];
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();
    let handler = SignerHandler::new_tenderbake_only(signer);

    for size in &[32, 64, 128, 256, 512, 1024, 2048] {
        let mut data = vec![0x11u8; *size];
        data[0] = 0x11;

        let sig = handler.sign(&data, None, None).unwrap();
        let pk = handler.public_key();

        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| {
                russignol_signer_lib::bls::verify(
                    black_box(pk),
                    black_box(&sig),
                    black_box(&data),
                    None,
                )
            });
        });
    }

    group.finish();
}

/// Benchmark key generation
fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("BLS12-381 key generation", |b| {
        b.iter(|| UnencryptedSigner::generate(black_box(None)).unwrap());
    });
}

/// Benchmark proof of possession generation
fn bench_proof_of_possession(c: &mut Criterion) {
    let seed = [42u8; 32];
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();
    let handler = SignerHandler::new_tenderbake_only(signer);

    c.bench_function("BLS12-381 proof of possession", |b| {
        b.iter(|| handler.bls_prove_possession(black_box(None)).unwrap());
    });
}

/// Benchmark deterministic nonce computation
fn bench_deterministic_nonce(c: &mut Criterion) {
    let seed = [42u8; 32];
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();
    let handler = SignerHandler::new_tenderbake_only(signer);

    let mut group = c.benchmark_group("Deterministic Nonce");

    for size in &[32, 64, 128, 256, 512, 1024] {
        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("compute_nonce", size), size, |b, _| {
            b.iter(|| handler.deterministic_nonce(black_box(&data)));
        });

        group.bench_with_input(
            BenchmarkId::new("compute_nonce_hash", size),
            size,
            |b, _| {
                b.iter(|| handler.deterministic_nonce_hash(black_box(&data)));
            },
        );
    }

    group.finish();
}

/// Benchmark base58check encoding/decoding
fn bench_base58check(c: &mut Criterion) {
    let seed = [42u8; 32];
    let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();
    let bench_handler = SignerHandler::new_tenderbake_only(signer);

    let mut group = c.benchmark_group("Base58Check Encoding");

    // Public key hash (tz4)
    let public_key_hash = bench_handler.public_key_hash();
    group.bench_function("encode_pkh", |b| {
        b.iter(|| black_box(public_key_hash).to_b58check());
    });

    let hash_b58 = public_key_hash.to_b58check();
    group.bench_function("decode_pkh", |b| {
        b.iter(|| {
            russignol_signer_lib::PublicKeyHash::from_b58check(black_box(&hash_b58)).unwrap()
        });
    });

    // Public key (BLpk)
    let public_key = bench_handler.public_key();
    group.bench_function("encode_pk", |b| {
        b.iter(|| black_box(public_key).to_b58check());
    });

    let pubkey_b58 = public_key.to_b58check();
    group.bench_function("decode_pk", |b| {
        b.iter(|| russignol_signer_lib::PublicKey::from_b58check(black_box(&pubkey_b58)).unwrap());
    });

    // Secret key (BLsk)
    let sk = bench_handler.signer.secret_key();
    group.bench_function("encode_sk", |b| {
        b.iter(|| black_box(sk).to_b58check());
    });

    group.finish();
}

/// Benchmark magic byte checking
fn bench_magic_byte_check(c: &mut Criterion) {
    use russignol_signer_lib::magic_bytes::check_magic_byte;

    let allowed = &[0x11u8, 0x12, 0x13];
    let data_allowed = b"\x11block data";
    let data_not_allowed = b"\x01block data";

    let mut group = c.benchmark_group("Magic Byte Validation");

    group.bench_function("check_allowed", |b| {
        b.iter(|| check_magic_byte(black_box(data_allowed), black_box(Some(allowed))).unwrap());
    });

    group.bench_function("check_not_allowed", |b| {
        b.iter(|| {
            let _ = check_magic_byte(black_box(data_not_allowed), black_box(Some(allowed)));
        });
    });

    group.bench_function("check_no_restriction", |b| {
        b.iter(|| check_magic_byte(black_box(data_allowed), black_box(None)).unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_signing,
    bench_verification,
    bench_key_generation,
    bench_proof_of_possession,
    bench_deterministic_nonce,
    bench_base58check,
    bench_magic_byte_check
);

criterion_main!(benches);
