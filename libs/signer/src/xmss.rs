//! XMSS (tz6) keys as this crate holds them.
//!
//! The scheme itself lives in `russignol-xmss`; what this module adds is the
//! Tezos base58 layer and the nonce derivations around it, mirroring `bls.rs`
//! for the BLS arm.
//!
//! The derivations below must agree byte for byte with Octez's
//! `src/lib_crypto/xmss.ml`; a divergence is a value no Octez node reads back.

use blake2::{Blake2b, Digest};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::base58check;

pub use russignol_xmss::{
    Epoch, Error, Lookahead, PUB_KEY_SIZE, PublicKey, PublicKeyHash, SIGNATURE_SIZE, SecretKey,
    Signature, deprioritize_key_generation,
};

type HmacSha256 = Hmac<Sha256>;

// Base58Check prefixes from OCaml code. The byte-lengths Octez registers
// alongside them describe leanMultisig's 31-byte public key and 2329-byte
// signature; leanVM-b's are 32 and 1212, so only the prefixes transfer.
//
// src/lib_crypto/base58.ml:480 - let xmss_public_key_hash = "\006\161\171" (* tz6(36) *)
pub(crate) const TZ6_PREFIX: &[u8] = &[0x06, 0xa1, 0xab];

// src/lib_crypto/base58.ml:483 - let xmss_public_key = "\001\121\006\180" (* xmpk(52) *)
pub(crate) const XMPK_PREFIX: &[u8] = &[0x01, 0x79, 0x06, 0xb4];

/// The bytes an `xmsk` value carries ahead of the key.
///
/// `src/lib_crypto/base58.ml:486` - `let xmss_secret_key = "\032\113\056\113" (* xmsk(91) *)`
pub const XMSK_PREFIX: &[u8] = &[0x20, 0x71, 0x38, 0x71];

// src/lib_crypto/base58.ml:492 - let xmss_signature = "\006\036\134\190\013" (* xmsig(3192) *)
pub(crate) const XMSIG_PREFIX: &[u8] = &[0x06, 0x24, 0x86, 0xbe, 0x0d];

/// Encode a tz6 public key hash
#[must_use]
pub fn pkh_to_b58check(pkh: &PublicKeyHash) -> String {
    base58check::encode(TZ6_PREFIX, pkh.as_bytes())
}

/// Encode an `xmpk` public key
#[must_use]
pub fn pk_to_b58check(pk: &PublicKey) -> String {
    base58check::encode(XMPK_PREFIX, &pk.to_bytes())
}

/// Encode an `xmsk` secret key
///
/// The returned string is key material; a caller that keeps it is responsible
/// for zeroizing it, as with [`crate::bls::SecretKey::to_b58check`].
#[must_use]
pub fn sk_to_b58check(sk: &SecretKey) -> String {
    base58check::encode(XMSK_PREFIX, &sk.to_bytes())
}

/// Encode an `xmsig` signature
#[must_use]
pub fn signature_to_b58check(sig: &Signature) -> String {
    base58check::encode(XMSIG_PREFIX, &sig.to_bytes())
}

/// Compute deterministic nonce using HMAC-SHA256
///
/// Corresponds to: `src/lib_crypto/xmss.ml:367-369` - `deterministic_nonce`,
/// which keys the HMAC with the serialized secret key.
///
/// # Panics
///
/// Cannot panic: HMAC-SHA256 accepts keys of any length.
#[must_use]
pub fn deterministic_nonce(sk: &SecretKey, msg: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(&sk.to_bytes()).expect("HMAC can take key of any size");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Compute deterministic nonce hash using `Blake2B`
/// Corresponds to: `src/lib_crypto/xmss.ml:371-372` - `deterministic_nonce_hash`
#[must_use]
pub fn deterministic_nonce_hash(sk: &SecretKey, msg: &[u8]) -> [u8; 32] {
    let nonce = deterministic_nonce(sk, msg);
    Blake2b::<blake2::digest::consts::U32>::digest(nonce).into()
}

/// Derive the per-key watermark MAC key from an XMSS signing secret.
///
/// Serves the same purpose as [`crate::bls::watermark_mac_key`] but through
/// BLAKE3's key-derivation mode rather than its keyed hash, because the secret
/// is kilobytes wide where a keyed hash takes exactly 32 bytes. The two modes
/// are domain-separated by BLAKE3 itself, so both arms can share one context
/// string.
#[must_use]
pub fn watermark_mac_key(sk: &SecretKey) -> [u8; 32] {
    blake3::derive_key("russignol-watermark-mac-v1", &sk.to_bytes())
}
