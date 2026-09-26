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

// Base58Check prefixes from Octez's leanVM `tz6`, on tezos/tezos branch
// `marina@leanvm-b` (ccd116cb). A prefix is chosen for one payload width, so
// these hold only for the 32-byte public keys and 1212-byte signatures that
// branch's leanVM produces.
//
// src/lib_crypto/base58.ml:480 - let xmss_public_key_hash = "\006\161\171" (* tz6(36) *)
pub(crate) const TZ6_PREFIX: &[u8] = &[0x06, 0xa1, 0xab];

// src/lib_crypto/base58.ml:483 - let xmss_public_key = "\019\090\092\013" (* xmpk(54) *)
pub(crate) const XMPK_PREFIX: &[u8] = &[0x13, 0x5a, 0x5c, 0x0d];

/// The bytes an `xmsk` value carries ahead of the key.
///
/// Not Octez's: this crate's secret is the serialized tree where Octez's is a
/// compact seed and range, so no Octez reads one. What reads it is
/// `load_entry` in `rpi-signer/src/signer_server.rs`, loading the tz6 secret
/// the card's wallet already holds under these bytes, taken from
/// leanMultisig-era Octez
/// (`src/lib_crypto/base58.ml:486` - `"\032\113\056\113" (* xmsk(91) *)`).
pub const XMSK_PREFIX: &[u8] = &[0x20, 0x71, 0x38, 0x71];

// src/lib_crypto/base58.ml:492 - let xmss_signature = "\036\180\033\044\187" (* xmsig(1667) *)
pub(crate) const XMSIG_PREFIX: &[u8] = &[0x24, 0xb4, 0x21, 0x2c, 0xbb];

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A tz6 secret stored under these literal bytes loads. They are spelled
    /// out rather than read from `XMSK_PREFIX` so the stored format holds
    /// still when the constant moves, which a value built from it could not.
    #[test]
    fn a_secret_stored_under_the_cards_prefix_loads() {
        let (sk, pk) = SecretKey::generate([7u8; 32], 0, 15).expect("range is valid");
        let stored = base58check::encode(&[0x20, 0x71, 0x38, 0x71], &sk.to_bytes());

        let loaded = crate::scheme::SecretKey::from_b58check(&stored).expect("the card's own key");
        assert_eq!(loaded.to_public_key(), crate::scheme::PublicKey::Xmss(pk));
    }

    #[test]
    fn keys_and_signatures_render_as_octez_registers_them() {
        let (sk, pk) = SecretKey::generate([7u8; 32], 0, 15).expect("range is valid");
        let signature = sk.sign(3, Some(b"\x13"), b"payload").expect("in range");

        let address = pkh_to_b58check(&pk.hash());
        let public = pk_to_b58check(&pk);
        let sig = signature_to_b58check(&signature);

        // The lengths `src/lib_crypto/base58.ml` registers beside each prefix
        assert!(address.starts_with("tz6"), "{address}");
        assert_eq!(address.len(), 36);
        assert!(public.starts_with("xmpk"), "{public}");
        assert_eq!(public.len(), 54);
        assert!(sig.starts_with("xmsig"), "{}", &sig[..12]);
        assert_eq!(sig.len(), 1667);
    }
}
