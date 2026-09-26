//! On-wire framing for a tz6 signature.
//!
//! Upstream's `XmssSignature` does not carry the epoch it was produced at, and
//! its `verify` takes that epoch as a separate argument. Octez's `leanvm-b`
//! branch patches the epoch into the signature as four little-endian bytes
//! after the body, so a tz6 signature on the wire is exactly that: the body,
//! then the epoch.
//!
//! Octez writes the body with upstream's SSZ encoding. For a signature of
//! fixed-size byte arrays that is the plain concatenation of its fields, which
//! is also what `bincode` with fixed-width integers emits, so the body goes
//! through the crate's `bincode` configuration rather than pulling in
//! `ethereum_ssz` and its dependency tree. `tests/xmss.rs` pins the result
//! against bytes Octez produced.

use bincode::Options as _;
use xmss::{Epoch, SIG_SIZE, XmssSignature};

use crate::encoding;

pub const EPOCH_LEN: usize = size_of::<Epoch>();

pub const SIGNATURE_SIZE: usize = SIG_SIZE + EPOCH_LEN;

pub const EPOCH_AT: usize = SIG_SIZE;

/// Frame `signature` with the epoch it was produced at.
///
/// # Panics
///
/// If upstream's serializer does not emit exactly `xmss::SIG_SIZE` bytes,
/// which would mean this crate's width constant and the serializer disagree.
/// `layout_is_pinned` fails first if that ever happens.
#[must_use]
pub fn encode(epoch: Epoch, signature: &XmssSignature) -> [u8; SIGNATURE_SIZE] {
    let mut out = [0u8; SIGNATURE_SIZE];
    encoding()
        .serialize_into(&mut out[..SIG_SIZE], signature)
        .expect("an XmssSignature serializes into SIG_SIZE bytes");
    out[EPOCH_AT..].copy_from_slice(&epoch.to_le_bytes());
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
    if bytes.len() != SIGNATURE_SIZE {
        return None;
    }
    let (body, epoch) = bytes.split_last_chunk::<EPOCH_LEN>()?;
    let signature = encoding().deserialize(body).ok()?;
    Some((Epoch::from_le_bytes(*epoch), signature))
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
        let randomness_at = V * DIGEST_LEN;
        let proof_at = randomness_at + RANDOMNESS_LEN;
        let epoch_at = proof_at + LOG_LIFETIME * DIGEST_LEN;

        assert_eq!(out.len(), 1212);
        assert_eq!(epoch_at + EPOCH_LEN, SIGNATURE_SIZE);
        assert_eq!(&out[..DIGEST_LEN], &[0u8; DIGEST_LEN]);
        assert_eq!(
            &out[randomness_at - DIGEST_LEN..randomness_at],
            &[byte(V - 1); DIGEST_LEN]
        );
        assert_eq!(&out[randomness_at..proof_at], [0xAA; RANDOMNESS_LEN]);
        assert_eq!(&out[proof_at..proof_at + DIGEST_LEN], &[0x80; DIGEST_LEN]);
        assert_eq!(
            &out[epoch_at - DIGEST_LEN..epoch_at],
            &[0x80 | byte(LOG_LIFETIME - 1); DIGEST_LEN]
        );
        assert_eq!(&out[epoch_at..], &[0x04, 0x03, 0x02, 0x01]);

        assert_eq!(decode(&out), Some((0x0102_0304, signature)));
    }

    #[test]
    fn a_buffer_of_the_wrong_length_does_not_decode() {
        assert_eq!(decode(&[0u8; SIGNATURE_SIZE - 1]), None);
        assert_eq!(decode(&[0u8; SIGNATURE_SIZE + 1]), None);
    }
}
