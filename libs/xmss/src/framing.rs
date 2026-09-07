//! On-wire framing for a tz6 signature.
//!
//! leanVM-b's `XmssSignature` does not carry the epoch it was produced at, and
//! its `verify` takes that epoch as a separate argument. The remote signer wire
//! protocol has no field for it either, so the signature bytes carry it. Octez
//! defines no such encoding for leanVM-b, so the layout below is this crate's
//! own; Octez's leanMultisig signatures get the property for free, with the
//! slot sitting inside the signature where `Xmss.check` reads it back.

use bincode::Options as _;
use xmss::{Epoch, XmssSignature};

use crate::encoding;

pub const EPOCH_LEN: usize = size_of::<Epoch>();

pub const SIGNATURE_SIZE: usize = EPOCH_LEN + xmss::SIG_SIZE;

/// Frame `signature` with the epoch it was produced at.
///
/// The epoch leads so a reader can take it without parsing the rest.
///
/// # Panics
///
/// If upstream's serializer does not emit exactly `xmss::SIG_SIZE` bytes,
/// which would mean this crate's width constant and the serializer disagree.
/// `layout_is_pinned` fails first if that ever happens.
#[must_use]
pub fn encode(epoch: Epoch, signature: &XmssSignature) -> [u8; SIGNATURE_SIZE] {
    let mut out = [0u8; SIGNATURE_SIZE];
    out[..EPOCH_LEN].copy_from_slice(&epoch.to_le_bytes());
    encoding()
        .serialize_into(&mut out[EPOCH_LEN..], signature)
        .expect("an XmssSignature serializes into SIG_SIZE bytes");
    out
}

/// Read a framed signature back into its epoch and the upstream signature.
///
/// Returns `None` when `bytes` is not exactly [`SIGNATURE_SIZE`] long, or when
/// the body is not a signature upstream will accept. These bytes arrive from
/// the network, so which of them decode is upstream's judgement to make rather
/// than something this layer asserts.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<(Epoch, XmssSignature)> {
    let bytes: &[u8; SIGNATURE_SIZE] = bytes.try_into().ok()?;
    let epoch = Epoch::from_le_bytes(std::array::from_fn(|i| bytes[i]));
    let signature = encoding().deserialize(&bytes[EPOCH_LEN..]).ok()?;
    Some((epoch, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmss::{DIGEST_LEN, LOG_LIFETIME, RANDOMNESS_LEN, V, WotsSignature};

    /// Distinguishable filler; every index used here is a chain or tree level,
    /// both well under 256.
    fn byte(index: usize) -> u8 {
        u8::try_from(index).expect("index fits in a byte")
    }

    /// Every field at a literal offset, so a change in what the serializer
    /// emits — field order, a length prefix, a varint width — fails here
    /// rather than at a verifier.
    #[test]
    fn layout_is_pinned() {
        let signature = XmssSignature {
            wots_signature: WotsSignature {
                chain_tips: std::array::from_fn(|c| [byte(c); DIGEST_LEN]),
                randomness: [0xAA; RANDOMNESS_LEN],
            },
            merkle_proof: std::array::from_fn(|n| [0x80 | byte(n); DIGEST_LEN]),
        };

        let out = encode(0x0102_0304, &signature);
        let tips_at = EPOCH_LEN;
        let randomness_at = tips_at + V * DIGEST_LEN;
        let proof_at = randomness_at + RANDOMNESS_LEN;

        assert_eq!(out.len(), 1212);
        assert_eq!(proof_at + LOG_LIFETIME * DIGEST_LEN, SIGNATURE_SIZE);
        assert_eq!(&out[..EPOCH_LEN], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&out[tips_at..tips_at + DIGEST_LEN], &[0u8; DIGEST_LEN]);
        assert_eq!(
            &out[randomness_at - DIGEST_LEN..randomness_at],
            &[byte(V - 1); DIGEST_LEN]
        );
        assert_eq!(&out[randomness_at..proof_at], [0xAA; RANDOMNESS_LEN]);
        assert_eq!(&out[proof_at..proof_at + DIGEST_LEN], &[0x80; DIGEST_LEN]);
        assert_eq!(
            &out[SIGNATURE_SIZE - DIGEST_LEN..],
            &[0x80 | byte(LOG_LIFETIME - 1); DIGEST_LEN]
        );

        assert_eq!(decode(&out), Some((0x0102_0304, signature)));
    }

    #[test]
    fn a_buffer_of_the_wrong_length_does_not_decode() {
        assert_eq!(decode(&[0u8; SIGNATURE_SIZE - 1]), None);
        assert_eq!(decode(&[0u8; SIGNATURE_SIZE + 1]), None);
    }
}
