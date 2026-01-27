//! BLS12-381 cryptographic primitives for Tezos signer
//!
//! This module implements BLS12-381 signatures using the `MinPk` variant
//! (minimized public keys) with proof-of-possession.
//!
//! Ported directly from: `src/lib_crypto/bls.ml`
//!
//! ## Important Compatibility Note: Out-of-Range Secret Keys
//!
//! The BLST library strictly validates that secret keys must be in the range
//! `[0, r)` where `r` is the BLS12-381 scalar field order:
//! ```text
//! r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
//! ```
//!
//! However, the OCaml implementation (`russignol-signer`) accepts secret keys with
//! values >= r and automatically reduces them modulo r. This is necessary for
//! compatibility with existing Tezos key files that may contain out-of-range keys.
//!
//! **Example**: A key like `BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x`
//! decodes to bytes starting with `0xb5...` which is > `0x73...` (the first byte
//! of r). The OCaml signer loads this key successfully by reducing it modulo r.
//!
//! This implementation matches the OCaml behavior by performing modular reduction
//! when BLST rejects a key with `BLST_BAD_ENCODING`. This ensures that:
//! - Existing Tezos key files can be read without errors
//! - The same keys work in both OCaml and Rust implementations
//! - The cryptographic properties remain correct (reduction preserves the key's
//!   equivalence class modulo r)

use crate::base58check;
use blake2::digest::consts::U20;
use blake2::{Blake2b, Digest};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
type Blake2b20 = Blake2b<U20>;

/// BLS signature errors
#[derive(Error, Debug)]
pub enum BlsError {
    /// Invalid secret key error
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Invalid public key error
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature error
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Base58 encoding/decoding error
    #[error("Base58 encoding error: {0}")]
    Base58Error(String),

    /// Invalid key length error
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length in bytes
        actual: usize,
    },

    /// Attempted to perform BLS-specific operation on non-BLS key
    #[error("Proof of possession can only be requested for BLS keys")]
    NonBlsKey,

    /// BLST library error
    #[error("BLST error: {0}")]
    BlstError(String),

    /// Key generation error
    #[error("Key generation error: {0}")]
    KeyGeneration(String),
}

/// Result type for BLS operations
pub type Result<T> = std::result::Result<T, BlsError>;

// Base58Check prefixes from OCaml code
// src/lib_crypto/base58.ml:385 - let bls12_381_public_key_hash = "\006\161\166" (* tz4(36) *)
const TZ4_PREFIX: &[u8] = &[0x06, 0xa1, 0xa6]; // "tz4" prefix (3 bytes)

// src/lib_crypto/base58.ml:455 - let bls12_381_public_key = "\006\149\135\204" (* BLpk(76) *)
const BLPK_PREFIX: &[u8] = &[0x06, 0x95, 0x87, 0xcc]; // "BLpk" prefix (4 bytes)

// src/lib_crypto/base58.ml:458 - let bls12_381_secret_key = "\003\150\192\040" (* BLsk(54) *)
const BLSK_PREFIX: &[u8] = &[0x03, 0x96, 0xc0, 0x28]; // "BLsk" prefix (4 bytes)

// src/lib_crypto/base58.ml:452 - let bls12_381_signature = "\040\171\064\207" (* BLsig(142) *)
const BLSIG_PREFIX: &[u8] = &[0x28, 0x79, 0x34, 0xcf]; // "BLsig" prefix (4 bytes)

// BLS12-381 MinPk with Pop ciphersuite ID for regular signatures
// Used for signing with Proof of Possession scheme as per Tezos protocol
const POP_CIPHERSUITE_ID: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// BLS12-381 MinPk with Pop ciphersuite ID for proof-of-possession
// Used specifically for `pop_prove` and `pop_verify`
const POP_PROVE_CIPHERSUITE_ID: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// BLS12-381 secret key (32 bytes)
/// Corresponds to: src/lib_crypto/bls.ml:136-238
#[derive(Clone)]
pub struct SecretKey {
    sk: blst::min_pk::SecretKey,
}

impl SecretKey {
    /// Size of secret key in bytes
    /// Corresponds to: `src/lib_crypto/bls.ml:152`
    pub const SIZE: usize = 32;

    /// Create secret key from 32 bytes
    ///
    /// Corresponds to: `src/lib_crypto/bls.ml:158` - `of_bytes_opt`
    ///
    /// # OCaml Compatibility: Modular Reduction
    ///
    /// Unlike strict BLST validation (which rejects keys >= curve order with
    /// `BLST_BAD_ENCODING`), this function matches OCaml's lenient behavior by
    /// automatically reducing out-of-range keys modulo r.
    ///
    /// **Why this is needed:**
    /// - Existing Tezos key files may contain keys with values >= r
    /// - The OCaml `russignol-signer` accepts such keys via reduction
    /// - Without this, valid OCaml keys would fail to load in the Rust implementation
    ///
    /// **Implementation:**
    /// 1. First attempts strict validation (fast path)
    /// 2. On `BLST_BAD_ENCODING`, performs: `key_reduced = key mod r` using `BigUint`
    /// 3. Creates secret key from reduced bytes (guaranteed to be < r)
    ///
    /// **Security note:** Modular reduction is cryptographically safe as it preserves
    /// the equivalence class of the secret key in the scalar field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(BlsError::InvalidKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        // BLS12-381 secret keys are little-endian scalars, but BLST expects big-endian bytes
        // So we need to reverse the bytes before passing to BLST
        let mut reversed_bytes = bytes.to_vec();
        reversed_bytes.reverse();

        // Try strict validation first
        match blst::min_pk::SecretKey::from_bytes(&reversed_bytes) {
            Ok(sk) => Ok(Self { sk }),
            Err(blst::BLST_ERROR::BLST_BAD_ENCODING) => {
                // Key is out of range - reduce it modulo the curve order
                // This matches OCaml's behavior which accepts out-of-range keys

                // BLS12-381 scalar field order (r)
                // This is the order of the scalar field for BLS12-381
                let r = BigUint::parse_bytes(
                    b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
                    16,
                )
                .expect("Failed to parse curve order");

                // Convert bytes to BigUint (little-endian per BLS12-381 spec)
                let key_int = BigUint::from_bytes_le(bytes);

                // Reduce modulo r
                let reduced_int = key_int % &r;

                // Convert back to bytes
                // BLST expects big-endian bytes, but the value was little-endian
                let mut reduced_bytes = reduced_int.to_bytes_be();

                // Pad with leading zeros if necessary (big-endian padding for BLST)
                if reduced_bytes.len() < Self::SIZE {
                    let mut padded = vec![0u8; Self::SIZE - reduced_bytes.len()];
                    padded.extend_from_slice(&reduced_bytes);
                    reduced_bytes = padded;
                }

                // Now it should be in range
                let sk = blst::min_pk::SecretKey::from_bytes(&reduced_bytes)
                    .map_err(|e| BlsError::InvalidSecretKey(format!("After reduction: {e:?}")))?;

                Ok(Self { sk })
            }
            Err(e) => Err(BlsError::InvalidSecretKey(format!("{e:?}"))),
        }
    }

    /// Convert to bytes (OCaml-compatible little-endian format)
    /// Corresponds to: `src/lib_crypto/bls.ml:154` - `to_bytes`
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        // BLST returns big-endian bytes, but OCaml uses little-endian
        // So we need to reverse them for compatibility
        let blst_bytes = self.sk.to_bytes();
        let mut result = blst_bytes;
        result.reverse();
        result
    }

    /// Derive public key from secret key
    /// Corresponds to: `src/lib_crypto/bls.ml:162` - `to_public_key`
    #[must_use]
    pub fn to_public_key(&self) -> PublicKey {
        let pk = self.sk.sk_to_pk();
        PublicKey { pk }
    }

    /// Encode to base58check
    /// Corresponds to: `src/lib_crypto/bls.ml:193` - `to_b58check`
    #[must_use]
    pub fn to_b58check(&self) -> String {
        let bytes = self.to_bytes();
        base58check::encode(BLSK_PREFIX, &bytes)
    }

    /// Decode from base58check
    /// Corresponds to: `src/lib_crypto/bls.ml:184-191` - `of_b58check`
    pub fn from_b58check(s: &str) -> Result<Self> {
        let decoded = base58check::decode(s, BLSK_PREFIX).map_err(BlsError::Base58Error)?;
        Self::from_bytes(&decoded)
    }
}

/// BLS12-381 public key (48 bytes, compressed G1 point)
/// Corresponds to: src/lib_crypto/bls.ml:47-134
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    pk: blst::min_pk::PublicKey,
}

impl PublicKey {
    /// Size of public key in bytes
    /// Corresponds to: `src/lib_crypto/bls.ml:66` - `pk_size_in_bytes`
    pub const SIZE: usize = 48;

    /// Create from bytes
    /// Corresponds to: `src/lib_crypto/bls.ml:60` - `of_bytes_opt`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(BlsError::InvalidKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let pk = blst::min_pk::PublicKey::from_bytes(bytes)
            .map_err(|e| BlsError::InvalidPublicKey(format!("{e:?}")))?;

        Ok(Self { pk })
    }

    /// Convert to bytes
    /// Corresponds to: `src/lib_crypto/bls.ml:56` - `to_bytes`
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.pk.to_bytes()
    }

    /// Compute public key hash (tz4 address)
    /// Corresponds to: `src/lib_crypto/bls.ml:80` - `hash`
    #[must_use]
    pub fn hash(&self) -> PublicKeyHash {
        PublicKeyHash::hash_bytes(&[self.to_bytes().as_ref()])
    }

    /// Encode to base58check
    /// Corresponds to: `src/lib_crypto/bls.ml:128` - `to_b58check`
    #[must_use]
    pub fn to_b58check(&self) -> String {
        let bytes = self.to_bytes();
        base58check::encode(BLPK_PREFIX, &bytes)
    }

    /// Decode from base58check
    /// Corresponds to: `src/lib_crypto/bls.ml:122-126` - `of_b58check`
    pub fn from_b58check(s: &str) -> Result<Self> {
        let decoded = base58check::decode(s, BLPK_PREFIX).map_err(BlsError::Base58Error)?;
        Self::from_bytes(&decoded)
    }
}

/// BLS12-381 public key hash (20 bytes, `Blake2B` hash)
/// Corresponds to: `src/lib_crypto/bls.ml:26-43`
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKeyHash {
    hash: [u8; 20],
}

impl PublicKeyHash {
    /// Size of public key hash in bytes
    pub const SIZE: usize = 20;

    /// Hash bytes using `Blake2B`
    /// Corresponds to: `src/lib_crypto/bls.ml:80` - `hash_bytes`
    #[must_use]
    pub fn hash_bytes(data: &[&[u8]]) -> Self {
        let mut hasher = Blake2b20::new();
        for bytes in data {
            hasher.update(bytes);
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&result);
        Self { hash }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(BlsError::InvalidKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(bytes);
        Ok(Self { hash })
    }

    /// Convert to bytes
    #[must_use]
    pub fn to_bytes(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Encode to base58check (tz4 address)
    /// Corresponds to: `src/lib_crypto/bls.ml:45` - `Base58.check_encoded_prefix` "tz4" 36
    #[must_use]
    pub fn to_b58check(&self) -> String {
        base58check::encode(TZ4_PREFIX, &self.hash)
    }

    /// Decode from base58check
    pub fn from_b58check(s: &str) -> Result<Self> {
        let decoded = base58check::decode(s, TZ4_PREFIX).map_err(BlsError::Base58Error)?;
        Self::from_bytes(&decoded)
    }
}

/// BLS12-381 signature (96 bytes, G2 point)
/// Corresponds to: src/lib_crypto/bls.ml:240-322
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    sig: blst::min_pk::Signature,
}

impl Signature {
    /// Size of signature in bytes
    /// Corresponds to: `src/lib_crypto/bls.ml:248`
    pub const SIZE: usize = 96;

    /// Create from bytes
    /// Corresponds to: `src/lib_crypto/bls.ml:252-255` - `of_bytes_opt`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(BlsError::InvalidKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let sig = blst::min_pk::Signature::from_bytes(bytes)
            .map_err(|e| BlsError::InvalidSignature(format!("{e:?}")))?;

        Ok(Self { sig })
    }

    /// Convert to bytes
    /// Corresponds to: `src/lib_crypto/bls.ml:250` - `to_bytes`
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.sig.to_bytes()
    }

    /// Encode to base58check
    /// Corresponds to: `src/lib_crypto/bls.ml:317` - `to_b58check`
    #[must_use]
    pub fn to_b58check(&self) -> String {
        let bytes = self.to_bytes();
        base58check::encode(BLSIG_PREFIX, &bytes)
    }

    /// Decode from base58check
    /// Corresponds to: `src/lib_crypto/bls.ml:311-315` - `of_b58check`
    pub fn from_b58check(s: &str) -> Result<Self> {
        let decoded = base58check::decode(s, BLSIG_PREFIX).map_err(BlsError::Base58Error)?;
        Self::from_bytes(&decoded)
    }
}

/// Sign a message with optional watermark prefix
/// Corresponds to: `src/lib_crypto/bls.ml:329-333` - `sign`
/// Uses MinPk.Pop scheme (Proof of Possession) as per Tezos
#[must_use]
pub fn sign(sk: &SecretKey, msg: &[u8], watermark: Option<&[u8]>) -> Signature {
    let msg_to_sign = match watermark {
        Some(prefix) => {
            let mut combined = Vec::with_capacity(prefix.len() + msg.len());
            combined.extend_from_slice(prefix);
            combined.extend_from_slice(msg);
            combined
        }
        None => msg.to_vec(),
    };

    // Tezos uses MinPk.Pop (Proof of Possession) scheme
    // This requires signing with the ciphersuite ID as DST
    // For BLS12-381 MinPk with Pop: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    let sig = sk.sk.sign(&msg_to_sign, POP_CIPHERSUITE_ID, &[]);
    Signature { sig }
}

/// Verify a signature
/// Corresponds to: `src/lib_crypto/bls.ml:347-351` - `check`
#[must_use]
pub fn verify(pk: &PublicKey, sig: &Signature, msg: &[u8], watermark: Option<&[u8]>) -> bool {
    let msg_to_verify = match watermark {
        Some(prefix) => {
            let mut combined = Vec::with_capacity(prefix.len() + msg.len());
            combined.extend_from_slice(prefix);
            combined.extend_from_slice(msg);
            combined
        }
        None => msg.to_vec(),
    };

    sig.sig
        .verify(true, &msg_to_verify, POP_CIPHERSUITE_ID, &[], &pk.pk, true)
        == blst::BLST_ERROR::BLST_SUCCESS
}

/// Generate proof of possession
/// Corresponds to: `src/lib_crypto/bls.ml:353` - `pop_prove`
#[must_use]
pub fn pop_prove(sk: &SecretKey, msg: Option<&[u8]>) -> Signature {
    let msg_bytes = msg.unwrap_or(&[]);
    let sig = sk.sk.sign(msg_bytes, POP_PROVE_CIPHERSUITE_ID, &[]);
    Signature { sig }
}

/// Verify proof of possession
/// Corresponds to: `src/lib_crypto/bls.ml:355` - `pop_verify`
#[must_use]
pub fn pop_verify(pk: &PublicKey, proof: &Signature, msg: Option<&[u8]>) -> bool {
    let msg_bytes = msg.unwrap_or(&[]);
    proof
        .sig
        .verify(true, msg_bytes, POP_PROVE_CIPHERSUITE_ID, &[], &pk.pk, true)
        == blst::BLST_ERROR::BLST_SUCCESS
}

/// Generate a new keypair from seed
/// Corresponds to: `src/lib_crypto/bls.ml:359-371` - `generate_key`
///
/// # Arguments
/// * `seed` - Optional 32-byte seed. If None, uses random bytes.
pub fn generate_key(seed: Option<&[u8; 32]>) -> Result<(PublicKeyHash, PublicKey, SecretKey)> {
    let seed_bytes = if let Some(s) = seed {
        *s
    } else {
        // Generate random 32 bytes (same as OCaml: Hacl.Rand.gen 32)
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| BlsError::KeyGeneration(format!("Random generation failed: {e}")))?;
        seed
    };

    let sk = SecretKey::from_bytes(&seed_bytes)?;
    let pk = sk.to_public_key();
    let pkh = pk.hash();

    Ok((pkh, pk, sk))
}

/// Compute deterministic nonce using HMAC-SHA256
/// Corresponds to: `src/lib_crypto/bls.ml:373-375` - `deterministic_nonce`
#[must_use]
pub fn deterministic_nonce(sk: &SecretKey, msg: &[u8]) -> [u8; 32] {
    let key = sk.to_bytes();
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(msg);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&bytes);
    nonce
}

/// Compute deterministic nonce hash using `Blake2B`
/// Corresponds to: `src/lib_crypto/bls.ml:377-378` - `deterministic_nonce_hash`
#[must_use]
pub fn deterministic_nonce_hash(sk: &SecretKey, msg: &[u8]) -> [u8; 32] {
    let nonce = deterministic_nonce(sk, msg);
    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    hasher.update(nonce);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let seed = [42u8; 32];
        let (pkh, pk, sk) = generate_key(Some(&seed)).unwrap();

        // Verify public key derived from secret key matches
        let derived_pk = sk.to_public_key();
        assert_eq!(pk, derived_pk);

        // Verify public key hash
        let computed_pkh = pk.hash();
        assert_eq!(pkh, computed_pkh);
    }

    #[test]
    fn test_sign_verify() {
        let seed = [1u8; 32];
        let (_pkh, pk, sk) = generate_key(Some(&seed)).unwrap();

        let msg = b"Hello, Tezos!";
        let sig = sign(&sk, msg, None);

        assert!(verify(&pk, &sig, msg, None));
        assert!(!verify(&pk, &sig, b"Wrong message", None));
    }

    #[test]
    fn test_sign_verify_with_watermark() {
        let seed = [2u8; 32];
        let (_pkh, pk, sk) = generate_key(Some(&seed)).unwrap();

        let watermark = &[0x11u8]; // Tenderbake block magic byte
        let msg = b"Block data";
        let sig = sign(&sk, msg, Some(watermark));

        assert!(verify(&pk, &sig, msg, Some(watermark)));
        assert!(!verify(&pk, &sig, msg, None)); // Wrong watermark
    }

    #[test]
    fn test_proof_of_possession() {
        let seed = [3u8; 32];
        let (_pkh, pk, sk) = generate_key(Some(&seed)).unwrap();

        let proof = pop_prove(&sk, None);
        assert!(pop_verify(&pk, &proof, None));

        let proof_with_msg = pop_prove(&sk, Some(b"test"));
        assert!(pop_verify(&pk, &proof_with_msg, Some(b"test")));
        assert!(!pop_verify(&pk, &proof_with_msg, None));
    }

    #[test]
    fn test_deterministic_nonce() {
        let seed = [4u8; 32];
        let (_pkh, _pk, sk) = generate_key(Some(&seed)).unwrap();

        let msg = b"Test message";
        let nonce1 = deterministic_nonce(&sk, msg);
        let nonce2 = deterministic_nonce(&sk, msg);

        // Should be deterministic
        assert_eq!(nonce1, nonce2);

        // Different message should produce different nonce
        let nonce3 = deterministic_nonce(&sk, b"Different message");
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_base58_encoding() {
        let seed = [5u8; 32];
        let (public_key_hash, public_key, secret_key) = generate_key(Some(&seed)).unwrap();

        // Test public key hash (tz4)
        let hash_b58 = public_key_hash.to_b58check();
        eprintln!("PKH base58: {hash_b58}");
        eprintln!("PKH first 3 chars: {}", &hash_b58[..3.min(hash_b58.len())]);
        assert!(
            hash_b58.starts_with("tz4"),
            "Expected to start with 'tz4', got: {hash_b58}"
        );
        let hash_decoded = PublicKeyHash::from_b58check(&hash_b58).unwrap();
        assert_eq!(public_key_hash, hash_decoded);

        // Test public key (BLpk)
        let pubkey_b58 = public_key.to_b58check();
        eprintln!("PK base58: {}", &pubkey_b58[..10.min(pubkey_b58.len())]);
        assert!(
            pubkey_b58.starts_with("BLpk"),
            "Expected to start with 'BLpk', got: {}",
            &pubkey_b58[..10.min(pubkey_b58.len())]
        );
        let pubkey_decoded = PublicKey::from_b58check(&pubkey_b58).unwrap();
        assert_eq!(public_key, pubkey_decoded);

        // Test secret key (BLsk)
        let secret_b58 = secret_key.to_b58check();
        eprintln!("SK base58: {}", &secret_b58[..10.min(secret_b58.len())]);
        assert!(
            secret_b58.starts_with("BLsk"),
            "Expected to start with 'BLsk', got: {}",
            &secret_b58[..10.min(secret_b58.len())]
        );
    }

    /// Test that out-of-range secret keys are properly handled via modular reduction.
    ///
    /// BLS12-381 scalar field order r:
    /// 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    ///
    /// Keys with first byte >= 0x73 might be >= r and require reduction.
    /// This test verifies OCaml compatibility for existing Tezos key files.
    #[test]
    fn test_out_of_range_key_modular_reduction() {
        // This key from OCaml has first byte 0xb5 > 0x73 (order's first byte)
        // OCaml accepts it via modular reduction; we must too for compatibility
        let out_of_range_key = "BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x";

        // Expected values from OCaml implementation
        let expected_pk =
            "BLpk1pn59Bwwi9K5VjubG4jphCVhdqWfji8GkV8eBXJCEYNMqE6s5LHv5W13zWtMey6Qipg5yCUD";
        let expected_pkh = "tz4QZtotXaZibHhGUUELAedaoHr8sPMw72fW";

        // Must load without error (modular reduction applied internally)
        let sk = SecretKey::from_b58check(out_of_range_key)
            .expect("Out-of-range key should be accepted via modular reduction");

        // Derived values must match OCaml exactly
        let pk = sk.to_public_key();
        let pkh = pk.hash();

        assert_eq!(
            pk.to_b58check(),
            expected_pk,
            "Public key must match OCaml derivation"
        );
        assert_eq!(
            pkh.to_b58check(),
            expected_pkh,
            "Public key hash must match OCaml derivation"
        );
    }

    /// Test full key derivation roundtrip:
    /// generate → derive pk → compute pkh → encode to base58 → decode → verify equality
    #[test]
    fn test_key_derivation_roundtrip() {
        let seed = [99u8; 32];

        // Generate keypair
        let (pkh_original, pk_original, sk_original) = generate_key(Some(&seed)).unwrap();

        // Encode all to base58
        let sk_b58 = sk_original.to_b58check();
        let pk_b58 = pk_original.to_b58check();
        let pkh_b58 = pkh_original.to_b58check();

        // Decode from base58
        let sk_decoded = SecretKey::from_b58check(&sk_b58).unwrap();
        let pk_decoded = PublicKey::from_b58check(&pk_b58).unwrap();
        let pkh_decoded = PublicKeyHash::from_b58check(&pkh_b58).unwrap();

        // Verify secret key bytes match
        assert_eq!(
            sk_original.to_bytes(),
            sk_decoded.to_bytes(),
            "Secret key roundtrip failed"
        );

        // Verify public key matches
        assert_eq!(pk_original, pk_decoded, "Public key roundtrip failed");

        // Verify public key hash matches
        assert_eq!(
            pkh_original, pkh_decoded,
            "Public key hash roundtrip failed"
        );

        // Verify full derivation chain: sk → pk → pkh
        let pk_from_decoded_sk = sk_decoded.to_public_key();
        assert_eq!(
            pk_from_decoded_sk, pk_original,
            "Public key derived from decoded secret key must match original"
        );

        let pkh_from_decoded_pk = pk_from_decoded_sk.hash();
        assert_eq!(
            pkh_from_decoded_pk, pkh_original,
            "Public key hash from derived public key must match original"
        );
    }
}
