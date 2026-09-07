//! Behaviour of the XMSS wrapper, exercised through its public API only.

use russignol_xmss::{
    Epoch, Error, Lookahead, PUB_KEY_SIZE, PublicKey, SIGNATURE_SIZE, SecretKey, hash_message,
};

const SEED: [u8; 32] = [7u8; 32];
const START: Epoch = 100;
const END: Epoch = 115;

fn key() -> (SecretKey, PublicKey) {
    SecretKey::generate(SEED, START, END).expect("range is valid")
}

#[test]
fn sign_then_verify_round_trips() {
    let (sk, pk) = key();
    let sig = sk.sign(START, Some(b"\x11"), b"payload").expect("in range");
    pk.verify(&sig, Some(b"\x11"), b"payload")
        .expect("its own signature verifies");
}

#[test]
fn verification_fails_on_a_different_message() {
    let (sk, pk) = key();
    let sig = sk.sign(START, None, b"payload").expect("in range");
    assert_eq!(
        pk.verify(&sig, None, b"other payload"),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn verification_fails_on_a_different_watermark() {
    let (sk, pk) = key();
    let sig = sk.sign(START, Some(b"\x11"), b"payload").expect("in range");
    assert_eq!(
        pk.verify(&sig, Some(b"\x12"), b"payload"),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn verification_fails_on_a_different_key() {
    let (sk, _) = key();
    let (_, other_pk) = SecretKey::generate([9u8; 32], START, END).expect("range is valid");
    let sig = sk.sign(START, None, b"payload").expect("in range");
    assert_eq!(
        other_pk.verify(&sig, None, b"payload"),
        Err(Error::VerificationFailed)
    );
}

/// The epoch travels inside the signature bytes, so rewriting it there is the
/// attack this must refuse: a verifier reading the tampered epoch must reject
/// rather than silently check a different one-time key.
#[test]
fn verification_fails_when_the_framed_epoch_is_tampered_with() {
    let (sk, pk) = key();
    let sig = sk.sign(START, None, b"payload").expect("in range");

    let mut bytes = sig.to_bytes();
    bytes[..4].copy_from_slice(&(START + 1).to_le_bytes());
    let tampered = russignol_xmss::Signature::from_bytes(&bytes).expect("still well-formed");

    assert_eq!(tampered.epoch(), START + 1);
    assert_eq!(
        pk.verify(&tampered, None, b"payload"),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn signing_outside_the_epoch_range_is_refused() {
    let (sk, _) = key();
    for epoch in [START - 1, END + 1] {
        assert_eq!(
            sk.sign(epoch, None, b"payload"),
            Err(Error::EpochOutOfRange {
                epoch,
                start: START,
                end: END,
            }),
            "epoch {epoch} is outside {START}..={END}"
        );
    }
}

#[test]
fn a_reloaded_secret_key_signs_the_same_epoch_and_verifies() {
    let (sk, pk) = key();
    let reloaded = SecretKey::from_bytes(&sk.to_bytes()).expect("its own encoding decodes");

    assert_eq!(reloaded.epoch_range(), sk.epoch_range());
    assert_eq!(reloaded.public_key(), pk);

    let sig = reloaded.sign(END, None, b"payload").expect("in range");
    assert_eq!(sig.epoch(), END);
    pk.verify(&sig, None, b"payload")
        .expect("the reloaded key signs under the original public key");
}

/// A stored key is exactly the bytes `to_bytes` produced, so a longer blob is
/// not that key. Reading one as a key accepts a value the device never wrote.
#[test]
fn a_secret_key_with_bytes_appended_is_refused() {
    let (sk, _) = key();
    let mut bytes = sk.to_bytes().to_vec();
    bytes.push(0);
    assert_eq!(
        SecretKey::from_bytes(&bytes).unwrap_err(),
        Error::MalformedSecretKey
    );
}

#[test]
fn a_truncated_secret_key_is_refused() {
    let (sk, _) = key();
    let bytes = sk.to_bytes();
    assert_eq!(
        SecretKey::from_bytes(&bytes[..bytes.len() - 1]).unwrap_err(),
        Error::MalformedSecretKey
    );
}

#[test]
fn signature_bytes_round_trip_and_are_fixed_width() {
    let (sk, _) = key();
    let sig = sk.sign(START, None, b"payload").expect("in range");
    let bytes = sig.to_bytes();

    assert_eq!(bytes.len(), SIGNATURE_SIZE);
    assert_eq!(SIGNATURE_SIZE, 1212);
    assert_eq!(
        russignol_xmss::Signature::from_bytes(&bytes).expect("round trips"),
        sig
    );
}

#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    let (sk, _) = key();
    let bytes = sk.sign(START, None, b"x").expect("in range").to_bytes();
    for len in [0, SIGNATURE_SIZE - 1] {
        assert_eq!(
            russignol_xmss::Signature::from_bytes(&bytes[..len]),
            Err(Error::MalformedSignature { len })
        );
    }
}

#[test]
fn public_key_bytes_round_trip_and_are_fixed_width() {
    let (_, pk) = key();
    let bytes = pk.to_bytes();

    assert_eq!(bytes.len(), PUB_KEY_SIZE);
    assert_eq!(PUB_KEY_SIZE, 32);
    assert_eq!(PublicKey::from_bytes(&bytes).expect("round trips"), pk);
    assert_eq!(
        PublicKey::from_bytes(&bytes[..31]),
        Err(Error::MalformedPublicKey { len: 31 })
    );
}

/// Pinned against `b2sum -l 256`, so a change to the digest width, the keying,
/// or the watermark ordering fails here rather than at a baker.
#[test]
fn message_hash_matches_octez_blake2b() {
    assert_eq!(
        hex(&hash_message(Some(b"\x11"), b"tz6 test vector")),
        "bf28642ac5f24640c8c485f3f6744e6e2fb96499186afe8a601e4bb04e4e0d02"
    );
    assert_eq!(
        hex(&hash_message(None, b"tz6 test vector")),
        "11e515474ab0df81fece2c33e65306e4a98475d550bf986e555c27ca17de1f40"
    );
}

/// A watermark is a prefix, not a separate field, so these two must collide —
/// which is why the caller passes the magic byte as the watermark rather than
/// concatenating it into the payload itself.
#[test]
fn the_watermark_is_a_plain_prefix() {
    assert_eq!(
        hash_message(Some(b"\x11"), b"tz6 test vector"),
        hash_message(None, b"\x11tz6 test vector")
    );
}

/// Key generation is deterministic in the seed and range, so both values are
/// pinned: the public key against a rerun, and its tz6 hash against
/// `b2sum -l 160`, which fails if the digest width or the hashed input moves.
#[test]
fn public_key_and_its_tz6_hash_are_pinned() {
    let (_, pk) = key();
    assert_eq!(
        hex(&pk.to_bytes()),
        "973b971e79d7ec23437096e5eacd0263710ae48f3b5ff4a4b06b0a3c17c6ef1c"
    );
    assert_eq!(
        hex(pk.hash().as_bytes()),
        "385cbcf5ffaa61bc59567020fd7d53e1c889da71"
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The subtree boundary a warm aims at, taken off the key rather than derived
/// from the range: upstream owns the width, and a second derivation of it here
/// would put the tests on a boundary the key does not use.
fn next_boundary(sk: &SecretKey) -> Epoch {
    let width = sk.subtree_width();
    (START / width + 1) * width
}

#[test]
fn a_lookahead_inside_the_resident_subtree_warms_nothing() {
    let (sk, _) = key();
    let boundary = next_boundary(&sk);

    assert_eq!(sk.epoch_to_warm(START, Lookahead(0)), None);
    assert_eq!(sk.epoch_to_warm(boundary - 1, Lookahead(0)), None);
}

/// The whole point of the lookahead: the subtree the next few signatures cross
/// into is built before one of them pays for it on the signing path.
#[test]
fn a_lookahead_across_the_boundary_warms_the_subtree_beyond_it() {
    let (sk, _) = key();
    let boundary = next_boundary(&sk);

    assert_eq!(sk.epoch_to_warm(boundary - 1, Lookahead(1)), Some(boundary));
    assert_eq!(
        sk.epoch_to_warm(boundary - 1, Lookahead(2)),
        Some(boundary + 1)
    );
}

#[test]
fn nothing_is_warmed_at_or_past_the_end_of_the_range() {
    let (sk, _) = key();

    assert_eq!(
        sk.epoch_to_warm(END, Lookahead(3)),
        None,
        "no subtree follows the last epoch"
    );
    assert_eq!(sk.epoch_to_warm(END + 1, Lookahead(1)), None);
    assert_eq!(sk.epoch_to_warm(START - 1, Lookahead(1)), None);
}

#[test]
fn warming_refuses_an_epoch_outside_the_range() {
    let (sk, _) = key();

    assert_eq!(sk.warm(START), Ok(()));
    assert_eq!(
        sk.warm(END + 1),
        Err(Error::EpochOutOfRange {
            epoch: END + 1,
            start: START,
            end: END,
        })
    );
}
