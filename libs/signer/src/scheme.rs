//! Keys and signatures over every scheme a device can hold.
//!
//! Each type is a sum over the schemes rather than a trait object, so the code
//! that only routes values — the key manager, the request handler, the
//! watermark store — carries no scheme branch, and the branch it would have
//! carried lives here once.

use std::ops::RangeInclusive;
use std::sync::Arc;

use thiserror::Error;

use crate::base58check;
use crate::bls;
use crate::xmss;

/// The signature scheme a key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// BLS12-381, addressed `tz4`
    Bls,
    /// XMSS over leanVM-b, addressed `tz6`
    Xmss,
}

impl Scheme {
    /// Width of this scheme's public key on the wire.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::Bls => bls::PublicKey::SIZE,
            Self::Xmss => xmss::PUB_KEY_SIZE,
        }
    }

    /// Width of this scheme's signature on the wire.
    ///
    /// The XMSS width includes the epoch this crate frames into the signature,
    /// since leanVM-b's own signature does not carry it.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Bls => bls::Signature::SIZE,
            Self::Xmss => xmss::SIGNATURE_SIZE,
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Bls => "BLS12-381",
            Self::Xmss => "XMSS",
        })
    }
}

/// Errors from key material and signatures of either scheme
#[derive(Error, Debug)]
pub enum Error {
    /// A BLS value did not validate.
    #[error("BLS error: {0}")]
    Bls(#[from] bls::Error),

    /// An XMSS value did not validate.
    #[error("XMSS error: {0}")]
    Xmss(#[from] xmss::Error),

    /// The value is not well-formed base58check.
    #[error("Base58 encoding error: {0}")]
    Base58(String),

    /// Well-formed base58check whose prefix belongs to no scheme this signer
    /// holds; carries the kind of value that was expected.
    #[error("Unrecognized base58 prefix for a {0}")]
    UnknownPrefix(&'static str),

    /// An XMSS key was asked to sign without an epoch. Each epoch is a one-time
    /// key, so the epoch comes from the device's epoch store and refusing is the
    /// only safe answer while nothing has claimed one.
    #[error("XMSS signing requires an epoch from the device's epoch store")]
    EpochUnavailable,
}

/// Result type for scheme-polymorphic key operations
pub type Result<T> = std::result::Result<T, Error>;

const PKH_PREFIXES: &[(&[u8], Scheme)] = &[
    (bls::TZ4_PREFIX, Scheme::Bls),
    (xmss::TZ6_PREFIX, Scheme::Xmss),
];

const PK_PREFIXES: &[(&[u8], Scheme)] = &[
    (bls::BLPK_PREFIX, Scheme::Bls),
    (xmss::XMPK_PREFIX, Scheme::Xmss),
];

const SK_PREFIXES: &[(&[u8], Scheme)] = &[
    (bls::BLSK_PREFIX, Scheme::Bls),
    (xmss::XMSK_PREFIX, Scheme::Xmss),
];

const SIG_PREFIXES: &[(&[u8], Scheme)] = &[
    (bls::BLSIG_PREFIX, Scheme::Bls),
    (xmss::XMSIG_PREFIX, Scheme::Xmss),
];

/// Decode a base58check value whose scheme is read from its prefix.
fn decode_by_prefix(
    s: &str,
    candidates: &[(&[u8], Scheme)],
    kind: &'static str,
) -> Result<(Scheme, Vec<u8>)> {
    base58check::decode_tagged(s, candidates)
        .map_err(Error::Base58)?
        .ok_or(Error::UnknownPrefix(kind))
}

/// A public key hash — 20 bytes under either scheme.
///
/// The scheme is part of the identity: a `tz4` and a `tz6` holding the same 20
/// bytes are different keys, and a request naming one must never resolve to the
/// other's signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyHash {
    /// `tz4`
    Bls(bls::PublicKeyHash),
    /// `tz6`
    Xmss(xmss::PublicKeyHash),
}

impl PublicKeyHash {
    /// The scheme this hash addresses
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        match self {
            Self::Bls(_) => Scheme::Bls,
            Self::Xmss(_) => Scheme::Xmss,
        }
    }

    /// The 20 hash bytes, which carry no scheme of their own
    #[must_use]
    pub fn to_bytes(&self) -> &[u8; 20] {
        match self {
            Self::Bls(pkh) => pkh.to_bytes(),
            Self::Xmss(pkh) => pkh.as_bytes(),
        }
    }

    /// Read 20 hash bytes as a hash of `scheme`.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice length is not 20.
    pub fn from_bytes(scheme: Scheme, bytes: &[u8]) -> Result<Self> {
        Ok(match scheme {
            Scheme::Bls => Self::Bls(bls::PublicKeyHash::from_bytes(bytes)?),
            Scheme::Xmss => Self::Xmss(xmss::PublicKeyHash::from_bytes(bytes)?),
        })
    }

    /// Encode as `tz4` or `tz6`
    #[must_use]
    pub fn to_b58check(&self) -> String {
        match self {
            Self::Bls(pkh) => pkh.to_b58check(),
            Self::Xmss(pkh) => xmss::pkh_to_b58check(pkh),
        }
    }

    /// Decode a `tz4` or `tz6` address.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not well-formed base58check, carries
    /// neither prefix, or is not 20 bytes.
    pub fn from_b58check(s: &str) -> Result<Self> {
        let (scheme, bytes) = decode_by_prefix(s, PKH_PREFIXES, "public key hash")?;
        Self::from_bytes(scheme, &bytes)
    }
}

/// A public key: 48 bytes under BLS, 32 under XMSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// `BLpk`
    Bls(bls::PublicKey),
    /// `xmpk`
    Xmss(xmss::PublicKey),
}

impl PublicKey {
    /// The scheme this key belongs to
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        match self {
            Self::Bls(_) => Scheme::Bls,
            Self::Xmss(_) => Scheme::Xmss,
        }
    }

    /// The key bytes, whose width is the scheme's
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Bls(pk) => pk.to_bytes().to_vec(),
            Self::Xmss(pk) => pk.to_bytes().to_vec(),
        }
    }

    /// Read key bytes as a key of `scheme`.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid key of that scheme.
    pub fn from_bytes(scheme: Scheme, bytes: &[u8]) -> Result<Self> {
        Ok(match scheme {
            Scheme::Bls => Self::Bls(bls::PublicKey::from_bytes(bytes)?),
            Scheme::Xmss => Self::Xmss(xmss::PublicKey::from_bytes(bytes)?),
        })
    }

    /// Verify `signature` over `data`, prefixed by `watermark` when one is
    /// given.
    ///
    /// A signature of the other scheme never verifies, whatever its bytes.
    #[must_use]
    pub fn verify(&self, signature: &Signature, data: &[u8], watermark: Option<&[u8]>) -> bool {
        match (self, signature) {
            (Self::Bls(pk), Signature::Bls(sig)) => bls::verify(pk, sig, data, watermark),
            (Self::Xmss(pk), Signature::Xmss(sig)) => pk.verify(sig, watermark, data).is_ok(),
            (Self::Bls(_), Signature::Xmss(_)) | (Self::Xmss(_), Signature::Bls(_)) => false,
        }
    }

    /// The address this key hashes to
    #[must_use]
    pub fn hash(&self) -> PublicKeyHash {
        match self {
            Self::Bls(pk) => PublicKeyHash::Bls(pk.hash()),
            Self::Xmss(pk) => PublicKeyHash::Xmss(pk.hash()),
        }
    }

    /// Encode as `BLpk` or `xmpk`
    #[must_use]
    pub fn to_b58check(&self) -> String {
        match self {
            Self::Bls(pk) => pk.to_b58check(),
            Self::Xmss(pk) => xmss::pk_to_b58check(pk),
        }
    }

    /// Decode a `BLpk` or `xmpk` public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not well-formed base58check, carries
    /// neither prefix, or is not a valid key of the scheme it names.
    pub fn from_b58check(s: &str) -> Result<Self> {
        let (scheme, bytes) = decode_by_prefix(s, PK_PREFIXES, "public key")?;
        Self::from_bytes(scheme, &bytes)
    }
}

/// A secret key.
///
/// The XMSS arm is behind an `Arc` because the signer holding it is cloned per
/// request and an XMSS key is tens of kilobytes; `russignol_xmss::SecretKey` is
/// deliberately not `Clone` for the stronger reason that a second live copy is
/// a second thing that can advance the epoch counter.
#[derive(Clone)]
pub enum SecretKey {
    /// `BLsk`
    Bls(bls::SecretKey),
    /// `xmsk`
    Xmss(Arc<xmss::SecretKey>),
}

impl SecretKey {
    /// The scheme this key signs under
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        match self {
            Self::Bls(_) => Scheme::Bls,
            Self::Xmss(_) => Scheme::Xmss,
        }
    }

    /// The matching public key
    #[must_use]
    pub fn to_public_key(&self) -> PublicKey {
        match self {
            Self::Bls(sk) => PublicKey::Bls(sk.to_public_key()),
            Self::Xmss(sk) => PublicKey::Xmss(sk.public_key()),
        }
    }

    /// Encode as `BLsk` or `xmsk`.
    ///
    /// The result is key material; a caller that keeps it zeroizes it.
    #[must_use]
    pub fn to_b58check(&self) -> String {
        match self {
            Self::Bls(sk) => sk.to_b58check(),
            Self::Xmss(sk) => xmss::sk_to_b58check(sk),
        }
    }

    /// Decode a `BLsk` or `xmsk` secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not well-formed base58check, carries
    /// neither prefix, or is not a valid key of the scheme it names.
    pub fn from_b58check(s: &str) -> Result<Self> {
        let (scheme, bytes) = decode_by_prefix(s, SK_PREFIXES, "secret key")?;
        Ok(match scheme {
            Scheme::Bls => Self::Bls(bls::SecretKey::from_bytes(&bytes)?),
            Scheme::Xmss => Self::Xmss(Arc::new(xmss::SecretKey::from_bytes(&bytes)?)),
        })
    }

    /// Sign `data` at `epoch`, prefixed by `watermark` when one is given.
    ///
    /// `epoch` is the one-time key this signature spends, and the device's
    /// epoch store is the only thing that may choose it — signing twice at one
    /// discloses the secret. `None` under a scheme that spends none.
    ///
    /// # Errors
    ///
    /// [`Error::EpochUnavailable`] for an XMSS key handed no epoch, and
    /// [`Error::Xmss`] for one outside the key's range.
    pub fn sign_at(
        &self,
        data: &[u8],
        watermark: Option<&[u8]>,
        epoch: Option<xmss::Epoch>,
    ) -> Result<Signature> {
        match self {
            Self::Bls(sk) => Ok(Signature::Bls(bls::sign(sk, data, watermark))),
            Self::Xmss(sk) => {
                let epoch = epoch.ok_or(Error::EpochUnavailable)?;
                Ok(Signature::Xmss(Box::new(sk.sign(epoch, watermark, data)?)))
            }
        }
    }

    /// Sign `data` with no epoch, which every scheme that spends one refuses.
    ///
    /// # Errors
    ///
    /// The reasons [`sign_at`](Self::sign_at) gives.
    pub fn sign(&self, data: &[u8], watermark: Option<&[u8]>) -> Result<Signature> {
        self.sign_at(data, watermark, None)
    }

    /// Keyed by this key's own secret, so a client re-deriving the nonce from
    /// the same key and data gets the same bytes (`bls.ml:373-375`,
    /// `xmss.ml:367-369`).
    #[must_use]
    pub fn deterministic_nonce(&self, data: &[u8]) -> [u8; 32] {
        match self {
            Self::Bls(sk) => bls::deterministic_nonce(sk, data),
            Self::Xmss(sk) => xmss::deterministic_nonce(sk, data),
        }
    }

    /// The digest a client asks for in place of the nonce itself, under the
    /// same interop constraint (`bls.ml:377-378`, `xmss.ml:371-372`).
    #[must_use]
    pub fn deterministic_nonce_hash(&self, data: &[u8]) -> [u8; 32] {
        match self {
            Self::Bls(sk) => bls::deterministic_nonce_hash(sk, data),
            Self::Xmss(sk) => xmss::deterministic_nonce_hash(sk, data),
        }
    }

    /// Derive the per-key watermark MAC key.
    ///
    /// The BLS arm is byte-identical to what provisioned cards already verify
    /// against, so their stored marks keep authenticating.
    #[must_use]
    pub fn watermark_mac_key(&self) -> [u8; 32] {
        match self {
            Self::Bls(sk) => bls::watermark_mac_key(sk),
            Self::Xmss(sk) => xmss::watermark_mac_key(sk),
        }
    }

    /// The epochs this key may ever sign at, under a scheme that spends a
    /// one-time key per signature.
    ///
    /// `None` for a scheme that signs as often as it likes, which is what tells
    /// the epoch store this key needs no counter.
    #[must_use]
    pub fn epoch_range(&self) -> Option<RangeInclusive<xmss::Epoch>> {
        match self {
            Self::Bls(_) => None,
            Self::Xmss(sk) => Some(sk.epoch_range()),
        }
    }

    /// Build the material a signature at `epoch` would otherwise build on the
    /// signing path, reporting the epoch built for.
    ///
    /// The build runs whether or not the key already holds that material, so a
    /// key just loaded from disk is warmed by the same call — the bottom-subtree
    /// cache does not survive serialization. `None` under a scheme that caches
    /// nothing per epoch.
    ///
    /// # Errors
    ///
    /// [`Error::Xmss`] where `epoch` is outside the key's range.
    pub fn warm(&self, epoch: xmss::Epoch) -> Result<Option<xmss::Epoch>> {
        match self {
            Self::Bls(_) => Ok(None),
            Self::Xmss(sk) => sk.warm(epoch).map(|()| Some(epoch)).map_err(Error::Xmss),
        }
    }

    /// The epoch `lookahead` from `next` reaches, where that lands in a
    /// different subtree from the one covering `next`.
    ///
    /// `None` under a scheme that caches nothing per epoch, and `None` where it
    /// lands in the same subtree.
    #[must_use]
    pub fn epoch_to_warm(
        &self,
        next: xmss::Epoch,
        lookahead: xmss::Lookahead,
    ) -> Option<xmss::Epoch> {
        match self {
            Self::Bls(_) => None,
            Self::Xmss(sk) => sk.epoch_to_warm(next, lookahead),
        }
    }
}

/// A signature: 96 bytes under BLS, 1212 under XMSS.
///
/// The XMSS arm is boxed so the enum stays near the BLS width. Signatures
/// travel by value through the request and response types, and an unboxed arm
/// would make every BLS response carry the XMSS one's footprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// `BLsig`
    Bls(bls::Signature),
    /// `xmsig`
    Xmss(Box<xmss::Signature>),
}

impl Signature {
    /// The scheme that produced this signature
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        match self {
            Self::Bls(_) => Scheme::Bls,
            Self::Xmss(_) => Scheme::Xmss,
        }
    }

    /// The signature bytes, whose width is the scheme's
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Bls(sig) => sig.to_bytes().to_vec(),
            Self::Xmss(sig) => sig.to_bytes().to_vec(),
        }
    }

    /// Read signature bytes as a signature of `scheme`.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid signature of that scheme.
    pub fn from_bytes(scheme: Scheme, bytes: &[u8]) -> Result<Self> {
        Ok(match scheme {
            Scheme::Bls => Self::Bls(bls::Signature::from_bytes(bytes)?),
            Scheme::Xmss => Self::Xmss(Box::new(xmss::Signature::from_bytes(bytes)?)),
        })
    }

    /// Encode as `BLsig` or `xmsig`
    #[must_use]
    pub fn to_b58check(&self) -> String {
        match self {
            Self::Bls(sig) => sig.to_b58check(),
            Self::Xmss(sig) => xmss::signature_to_b58check(sig),
        }
    }

    /// Decode a `BLsig` or `xmsig` signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not well-formed base58check, carries
    /// neither prefix, or is not a valid signature of the scheme it names.
    pub fn from_b58check(s: &str) -> Result<Self> {
        let (scheme, bytes) = decode_by_prefix(s, SIG_PREFIXES, "signature")?;
        Self::from_bytes(scheme, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // src/lib_crypto/base58.ml:379 - let ed25519_public_key_hash = "\006\161\159" (* tz1(36) *)
    const TZ1_PREFIX: &[u8] = &[0x06, 0xa1, 0x9f];

    fn bls_key() -> SecretKey {
        let (.., sk) = bls::generate_key(Some(&[42u8; 32])).expect("seeded key");
        SecretKey::Bls(sk)
    }

    /// A 16-epoch key: generation walks every in-range leaf, so the range is
    /// kept small enough that the cost does not dominate the test run.
    fn xmss_key() -> SecretKey {
        let (sk, _) = xmss::SecretKey::generate([7u8; 32], 0, 15).expect("range is valid");
        SecretKey::Xmss(Arc::new(sk))
    }

    /// The prefix as it sits in the decoded bytes, which is what a reader
    /// matches on. The rendered leading characters also depend on the payload
    /// width, and leanVM-b's keys and signatures are not the width Octez
    /// registered its `xmpk`/`xmsk`/`xmsig` lengths against.
    fn carries_prefix(b58: &str, prefix: &[u8]) -> bool {
        bs58::decode(b58)
            .into_vec()
            .expect("we encoded this")
            .starts_with(prefix)
    }

    #[test]
    fn each_scheme_round_trips_under_its_own_prefixes() {
        for sk in [bls_key(), xmss_key()] {
            let scheme = sk.scheme();
            let pk = sk.to_public_key();
            let pkh = pk.hash();
            let (address, sk_b58, pk_b58) = (pkh.to_b58check(), sk.to_b58check(), pk.to_b58check());

            let (address_text, hash_prefix, public_prefix, secret_prefix) = match scheme {
                Scheme::Bls => ("tz4", bls::TZ4_PREFIX, bls::BLPK_PREFIX, bls::BLSK_PREFIX),
                Scheme::Xmss => (
                    "tz6",
                    xmss::TZ6_PREFIX,
                    xmss::XMPK_PREFIX,
                    xmss::XMSK_PREFIX,
                ),
            };

            assert!(address.starts_with(address_text), "{scheme}: {address}");
            assert!(
                carries_prefix(&address, hash_prefix),
                "{scheme} hash prefix"
            );
            assert!(
                carries_prefix(&pk_b58, public_prefix),
                "{scheme} public prefix"
            );
            assert!(
                carries_prefix(&sk_b58, secret_prefix),
                "{scheme} secret prefix"
            );

            assert_eq!(PublicKeyHash::from_b58check(&address).unwrap(), pkh);
            assert_eq!(PublicKey::from_b58check(&pk_b58).unwrap(), pk);
            assert_eq!(
                SecretKey::from_b58check(&sk_b58).unwrap().to_public_key(),
                pk
            );
            assert_eq!(
                PublicKeyHash::from_bytes(scheme, pkh.to_bytes()).unwrap(),
                pkh
            );
            assert_eq!(PublicKey::from_bytes(scheme, &pk.to_bytes()).unwrap(), pk);
        }
    }

    /// A prefix naming a scheme this signer does not hold must be refused
    /// rather than read as one it does: defaulting would serve a tz1 request
    /// under a tz4 key.
    #[test]
    fn a_prefix_of_another_scheme_is_refused_rather_than_defaulted() {
        let foreign = base58check::encode(TZ1_PREFIX, &[3u8; 20]);
        assert!(matches!(
            PublicKeyHash::from_b58check(&foreign),
            Err(Error::UnknownPrefix("public key hash"))
        ));
    }

    /// Each kind has its own prefix set, so a value of one kind is not read as
    /// another however well-formed it is.
    #[test]
    fn a_value_of_one_kind_does_not_decode_as_another() {
        let sk = xmss_key();
        let address = sk.to_public_key().hash().to_b58check();

        assert!(matches!(
            PublicKey::from_b58check(&address),
            Err(Error::UnknownPrefix("public key"))
        ));
        assert!(matches!(
            SecretKey::from_b58check(&address),
            Err(Error::UnknownPrefix("secret key"))
        ));
        assert!(matches!(
            Signature::from_b58check(&address),
            Err(Error::UnknownPrefix("signature"))
        ));
    }

    /// The 20 bytes carry no scheme, so the sum type is what keeps a tz4 and a
    /// tz6 of the same bytes apart — a map keyed on them must not collide.
    #[test]
    fn one_hash_value_under_two_schemes_is_two_keys() {
        let bytes = bls_key().to_public_key().hash();
        let as_bls = PublicKeyHash::from_bytes(Scheme::Bls, bytes.to_bytes()).unwrap();
        let as_xmss = PublicKeyHash::from_bytes(Scheme::Xmss, bytes.to_bytes()).unwrap();

        assert_eq!(as_bls.to_bytes(), as_xmss.to_bytes());
        assert_ne!(as_bls, as_xmss);
        assert_ne!(as_bls.to_b58check(), as_xmss.to_b58check());
    }

    /// Signature bytes carry no scheme either, so a verifier must reject a
    /// signature of the other scheme rather than mis-parse it.
    #[test]
    fn a_signature_of_the_other_scheme_never_verifies() {
        let secret = bls_key();
        let over_bls = secret.sign(b"payload", None).expect("BLS signs");
        let SecretKey::Xmss(hash_based) = xmss_key() else {
            unreachable!("xmss_key builds the XMSS arm")
        };
        let over_xmss = Signature::Xmss(Box::new(
            hash_based.sign(0, None, b"payload").expect("in range"),
        ));

        let tz4 = secret.to_public_key();
        let tz6 = PublicKey::Xmss(hash_based.public_key());

        assert!(tz4.verify(&over_bls, b"payload", None));
        assert!(tz6.verify(&over_xmss, b"payload", None));
        assert!(!tz6.verify(&over_bls, b"payload", None));
        assert!(!tz4.verify(&over_xmss, b"payload", None));
    }

    /// Both derivations key on the secret, so two keys never share a MAC key
    /// and a mark authenticated under one is not accepted under the other.
    #[test]
    fn every_key_derives_its_own_watermark_mac_key() {
        assert_ne!(
            bls_key().watermark_mac_key(),
            xmss_key().watermark_mac_key()
        );
    }
    /// Provisioned cards authenticate their stored marks under this
    /// derivation, so a change to it leaves every existing mark unverifiable.
    /// Pinned against a value taken from the derivation as shipped.
    #[test]
    fn the_bls_watermark_mac_derivation_is_pinned() {
        let mac = bls_key().watermark_mac_key();
        let hex = mac.iter().fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        });
        assert_eq!(
            hex,
            "a1a0394610040f77359182b2a251386f0deac21b3c2b4cc5263cf716fa77e166"
        );
    }
}
