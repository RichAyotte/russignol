//! Core signer functionality for Tezos russignol-signer
//!
//! This module implements the main signing logic with magic byte validation.
//! Ported directly from: `src/lib_signer_backends/unencrypted.ml` and `src/bin_signer/handler.ml`

use crate::bls;
use crate::magic_bytes::{self, MagicByteError};
use crate::scheme::{self, PublicKey, PublicKeyHash, Scheme, SecretKey, Signature};
use crate::xmss::Epoch;
use thiserror::Error;

/// Signer errors
#[derive(Error, Debug)]
pub enum Error {
    /// BLS cryptographic error
    #[error("BLS error: {0}")]
    Bls(#[from] bls::Error),

    /// Key material or signature of either scheme failed to load or validate
    #[error("Key error: {0}")]
    Key(#[from] scheme::Error),

    /// Magic byte validation error
    #[error("Magic byte error: {0}")]
    MagicByte(#[from] MagicByteError),

    /// General signing operation failure
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Attempted BLS-specific operation on non-BLS key
    #[error("Proof of possession can only be requested for BLS keys")]
    NonBlsKey,
}

/// Result type for signer operations
pub type Result<T> = std::result::Result<T, Error>;

/// Signature version enumeration
/// Corresponds to: `src/lib_crypto/signature.ml` - Version type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVersion {
    /// Version 0 - Ed25519, Secp256k1, P256 (`signature_v0.mli:52-56`)
    V0,
    /// Version 1 - adds BLS12-381 (`signature_v1.mli:55-60`)
    V1,
    /// Version 2 - Ed25519, Secp256k1, P256, BLS12-381
    V2,
    /// Version 3 - adds ML-DSA-44 (`signature_v3.mli:39-45`)
    V3,
    /// Version 4 - Latest, adds XMSS (`signature_v4.mli:42-49`)
    V4,
}

impl SignatureVersion {
    /// The newest version this signer holds a signature union for.
    pub const LATEST: Self = Self::V4;

    /// Whether this version's signature union carries `scheme`.
    ///
    /// A scheme absent from the union has no tag to encode under, so signing at
    /// that version would produce bytes the client cannot read back.
    const fn carries(self, scheme: Scheme) -> bool {
        match scheme {
            Scheme::Bls => !matches!(self, Self::V0),
            Scheme::Xmss => matches!(self, Self::V4),
        }
    }

    /// The version this wire byte names, or `None` where it names none.
    #[must_use]
    pub const fn from_number(number: u8) -> Option<Self> {
        match number {
            0 => Some(Self::V0),
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            _ => None,
        }
    }

    /// The version number as it travels on the wire
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }
}

/// Unencrypted signer implementation
/// Corresponds to: `src/lib_signer_backends/unencrypted.ml`
#[derive(Clone)]
pub struct Unencrypted {
    secret_key: SecretKey,
    public_key: PublicKey,
    public_key_hash: PublicKeyHash,
}

impl Unencrypted {
    /// Create a new unencrypted signer from a secret key
    /// Corresponds to: unencrypted.ml:43-45 - `secret_key`
    #[must_use]
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = secret_key.to_public_key();
        let public_key_hash = public_key.hash();

        Self {
            secret_key,
            public_key,
            public_key_hash,
        }
    }

    /// Create from base58check encoded secret key
    ///
    /// # Errors
    ///
    /// Returns an error if the base58check string is invalid or decodes to an invalid key.
    pub fn from_b58check(sk_b58: &str) -> Result<Self> {
        let secret_key = SecretKey::from_b58check(sk_b58)?;
        Ok(Self::new(secret_key))
    }

    /// Generate a new random BLS signer
    /// Corresponds to: src/lib_crypto/bls.ml:359-371 - `generate_key`
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate(seed: Option<&[u8; 32]>) -> Result<Self> {
        Ok(Self::new(SecretKey::Bls(bls::generate_secret_key(seed)?)))
    }

    /// Generate a new random XMSS signer usable at every epoch in `epochs`.
    ///
    /// The span is the caller's rather than a constant read here: it is baked
    /// into the key at generation and decides how long the key signs before it
    /// is rotated, and a span wide enough to deploy costs tens of minutes to
    /// walk.
    ///
    /// # Errors
    ///
    /// Returns an error if the span is empty or if the seed cannot be drawn.
    pub fn generate_xmss(epochs: std::ops::RangeInclusive<Epoch>) -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| Error::SigningFailed(format!("Random generation failed: {e}")))?;
        let (secret, _) = crate::xmss::SecretKey::generate(seed, *epochs.start(), *epochs.end())
            .map_err(scheme::Error::from)?;
        Ok(Self::new(SecretKey::Xmss(std::sync::Arc::new(secret))))
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the public key hash
    #[must_use]
    pub fn public_key_hash(&self) -> &PublicKeyHash {
        &self.public_key_hash
    }

    /// Get the secret key
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Sign data at the epoch the device's store claimed for this signature
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:82-110 - sign
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `watermark` - Optional watermark prefix
    /// * `version` - Optional signature version; `None` means the latest
    /// * `epoch` - The one-time key to spend; `None` under a scheme that
    ///   spends none
    ///
    /// # Errors
    ///
    /// Returns an error if the requested signature version does not carry this
    /// key's scheme, or if the scheme cannot sign at that epoch.
    pub fn sign_at(
        &self,
        data: &[u8],
        watermark: Option<&[u8]>,
        version: Option<SignatureVersion>,
        epoch: Option<Epoch>,
    ) -> Result<Signature> {
        if let Some(version) = version {
            self.check_version(version)?;
        }
        Ok(self.secret_key.sign_at(data, watermark, epoch)?)
    }

    /// Refuse a version whose signature union does not carry this key's scheme.
    ///
    /// Signing at one would produce bytes with no tag the client can read back,
    /// so a caller holding a scarce resource — an XMSS epoch — checks here
    /// before spending it rather than after.
    /// Corresponds to: unencrypted.ml:102-110
    ///
    /// # Errors
    ///
    /// [`Error::SigningFailed`] naming the scheme and the version.
    pub fn check_version(&self, version: SignatureVersion) -> Result<()> {
        let scheme = self.secret_key.scheme();
        if version.carries(scheme) {
            return Ok(());
        }
        Err(Error::SigningFailed(format!(
            "{scheme} not supported in Signature version {}",
            version.number()
        )))
    }

    /// Sign data with no epoch, which every scheme that spends one refuses.
    ///
    /// # Errors
    ///
    /// The reasons [`sign_at`](Self::sign_at) gives.
    pub fn sign(
        &self,
        data: &[u8],
        watermark: Option<&[u8]>,
        version: Option<SignatureVersion>,
    ) -> Result<Signature> {
        self.sign_at(data, watermark, version, None)
    }

    /// Prove possession of the secret key (BLS-specific operation)
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:124-134 - `bls_prove_possession`
    ///
    /// # Arguments
    /// * `override_pk` - Optional public key to use as message (for testing)
    ///
    /// # Returns
    /// * Proof of possession signature
    ///
    /// # Errors
    ///
    /// [`Error::NonBlsKey`] if this signer holds a key of another scheme;
    /// infallible otherwise.
    pub fn bls_prove_possession(&self, override_pk: Option<&PublicKey>) -> Result<Signature> {
        let SecretKey::Bls(sk) = &self.secret_key else {
            return Err(Error::NonBlsKey);
        };
        let msg_to_sign_vec = override_pk.unwrap_or(&self.public_key).to_bytes();
        Ok(Signature::Bls(bls::pop_prove(sk, Some(&msg_to_sign_vec))))
    }

    /// Generate deterministic nonce
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:112-115 - `deterministic_nonce`
    #[must_use]
    pub fn deterministic_nonce(&self, data: &[u8]) -> [u8; 32] {
        self.secret_key.deterministic_nonce(data)
    }

    /// Generate deterministic nonce hash
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:117-120 - `deterministic_nonce_hash`
    #[must_use]
    pub fn deterministic_nonce_hash(&self, data: &[u8]) -> [u8; 32] {
        self.secret_key.deterministic_nonce_hash(data)
    }

    /// Check if deterministic nonces are supported (both schemes define one)
    /// Corresponds to: `src/lib_signer_backends/unencrypted.ml:122` - `supports_deterministic_nonces`
    #[must_use]
    pub fn supports_deterministic_nonces(&self) -> bool {
        true
    }
}

/// Signer handler with magic byte validation
/// Corresponds to: `src/bin_signer/handler.ml`
pub struct Handler {
    /// The underlying unencrypted signer
    pub signer: Unencrypted,
    allowed_magic_bytes: Option<&'static [u8]>,
}

impl Handler {
    /// Create a new signer handler
    ///
    /// # Arguments
    /// * `signer` - The underlying unencrypted signer
    /// * `allowed_magic_bytes` - Optional list of allowed magic bytes.
    ///   If None, all magic bytes are allowed.
    ///   Use `Some(MagicByte::all())` for Tenderbake only.
    #[must_use]
    pub fn new(signer: Unencrypted, allowed_magic_bytes: Option<&'static [u8]>) -> Self {
        Self {
            signer,
            allowed_magic_bytes,
        }
    }

    /// Create handler from base58check encoded secret key
    ///
    /// # Errors
    ///
    /// Returns an error if the base58check string is invalid or decodes to an invalid key.
    pub fn from_b58check(sk_b58: &str, allowed_magic_bytes: Option<&'static [u8]>) -> Result<Self> {
        let signer = Unencrypted::from_b58check(sk_b58)?;
        Ok(Self::new(signer, allowed_magic_bytes))
    }

    /// Create handler with Tenderbake-only magic bytes (0x11, 0x12, 0x13)
    #[must_use]
    pub fn new_tenderbake_only(signer: Unencrypted) -> Self {
        Self::new(signer, Some(magic_bytes::MagicByte::all()))
    }

    /// Sign data with magic byte validation
    /// Corresponds to: src/bin_signer/handler.ml:275-309 - sign
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `watermark` - Optional watermark prefix
    /// * `version` - Optional signature version
    ///
    /// # Returns
    /// * A signature of this key's own scheme if the magic byte is valid
    /// * Error if the magic byte check fails
    ///
    /// # Errors
    ///
    /// Returns an error if the magic byte is not allowed, or for the reasons
    /// [`Unencrypted::sign`] gives.
    pub fn sign(
        &self,
        data: &[u8],
        watermark: Option<&[u8]>,
        version: Option<SignatureVersion>,
    ) -> Result<Signature> {
        // Corresponds to: handler.ml:293 - check_magic_byte name magic_bytes data
        magic_bytes::check_magic_byte(data, self.allowed_magic_bytes)?;

        // Corresponds to: handler.ml:296-305
        self.signer.sign(data, watermark, version)
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        self.signer.public_key()
    }

    /// Get the public key hash
    #[must_use]
    pub fn public_key_hash(&self) -> &PublicKeyHash {
        self.signer.public_key_hash()
    }

    /// Prove possession of the secret key
    ///
    /// # Errors
    ///
    /// This method is infallible for BLS keys but returns `Result` for trait compatibility.
    pub fn bls_prove_possession(&self, override_pk: Option<&PublicKey>) -> Result<Signature> {
        self.signer.bls_prove_possession(override_pk)
    }

    /// Generate deterministic nonce
    #[must_use]
    pub fn deterministic_nonce(&self, data: &[u8]) -> [u8; 32] {
        self.signer.deterministic_nonce(data)
    }

    /// Generate deterministic nonce hash
    #[must_use]
    pub fn deterministic_nonce_hash(&self, data: &[u8]) -> [u8; 32] {
        self.signer.deterministic_nonce_hash(data)
    }

    /// Check if deterministic nonces are supported
    #[must_use]
    pub fn supports_deterministic_nonces(&self) -> bool {
        self.signer.supports_deterministic_nonces()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_signer() -> Unencrypted {
        let seed = [42u8; 32];
        Unencrypted::generate(Some(&seed)).unwrap()
    }

    /// A 16-epoch key: generation walks every in-range leaf, so the range is
    /// kept small enough that the cost does not dominate the test run.
    fn create_test_xmss_signer() -> Unencrypted {
        let (sk, _) = crate::xmss::SecretKey::generate([7u8; 32], 0, 15).unwrap();
        Unencrypted::new(SecretKey::Xmss(Arc::new(sk)))
    }

    /// A signer built from key material answers under the address that material
    /// derives, so a mis-wired constructor cannot serve one key's signatures
    /// under another key's name.
    #[test]
    fn test_signer_creation() {
        let signer = create_test_signer();
        let reloaded = Unencrypted::from_b58check(&signer.secret_key().to_b58check()).unwrap();

        assert_eq!(signer.public_key_hash(), reloaded.public_key_hash());
        assert_eq!(signer.public_key(), reloaded.public_key());
        assert_eq!(*signer.public_key_hash(), signer.public_key().hash());
        assert_eq!(signer.public_key_hash().scheme(), Scheme::Bls);
    }

    #[test]
    fn test_sign_basic() {
        let signer = create_test_signer();
        let data = b"Test message";

        let sig = signer.sign(data, None, None).unwrap();
        let pk = signer.public_key();

        assert!(pk.verify(&sig, data, None));
    }

    #[test]
    fn test_sign_with_watermark() {
        let signer = create_test_signer();
        let watermark = &[0x11u8]; // Tenderbake block
        let data = b"Block data";

        let sig = signer.sign(data, Some(watermark), None).unwrap();
        let pk = signer.public_key();

        assert!(pk.verify(&sig, data, Some(watermark)));
    }

    #[test]
    fn test_handler_no_magic_byte_restriction() {
        let signer = create_test_signer();
        let handler = Handler::new(signer, None);

        // Any data should be signable without magic byte restriction
        let data = b"\xFFtest";
        let sig = handler.sign(data, None, None).unwrap();

        assert!(handler.public_key().verify(&sig, data, None));
    }

    #[test]
    fn test_handler_tenderbake_only() {
        let signer = create_test_signer();
        let handler = Handler::new_tenderbake_only(signer);

        // Tenderbake block should work
        let data = b"\x11block_data";
        assert!(handler.sign(data, None, None).is_ok());

        // Tenderbake preattestation should work
        let data = b"\x12preattestation_data";
        assert!(handler.sign(data, None, None).is_ok());

        // Tenderbake attestation should work
        let data = b"\x13attestation_data";
        assert!(handler.sign(data, None, None).is_ok());

        // Emmy block should fail
        let data = b"\x01block_data";
        assert!(handler.sign(data, None, None).is_err());

        // Emmy endorsement should fail
        let data = b"\x02endorsement_data";
        assert!(handler.sign(data, None, None).is_err());

        // Random byte should fail
        let data = b"\xFFrandom_data";
        assert!(handler.sign(data, None, None).is_err());
    }

    #[test]
    fn test_bls_prove_possession() {
        let signer = create_test_signer();
        let handler = Handler::new(signer, None);

        let proof = handler.bls_prove_possession(None).unwrap();

        let (PublicKey::Bls(pk), Signature::Bls(proof)) = (handler.public_key(), &proof) else {
            panic!("a BLS signer proves possession with a BLS signature");
        };
        assert!(bls::pop_verify(pk, proof, Some(&pk.to_bytes())));
    }

    #[test]
    fn test_bls_prove_possession_with_override() {
        let signer = create_test_signer();
        let handler = Handler::new(signer, None);

        let pk = handler.public_key().clone();
        let proof = handler.bls_prove_possession(Some(&pk)).unwrap();

        let (PublicKey::Bls(pk), Signature::Bls(proof)) = (&pk, &proof) else {
            panic!("a BLS signer proves possession with a BLS signature");
        };
        assert!(bls::pop_verify(pk, proof, Some(&pk.to_bytes())));
    }

    /// Possession of a secret is what the BLS proof attests, and no other
    /// scheme defines one, so a tz6 key must refuse rather than answer with
    /// something a verifier would read as a BLS proof.
    #[test]
    fn proof_of_possession_is_refused_for_a_tz6_key() {
        let signer = create_test_xmss_signer();
        assert!(matches!(
            signer.bls_prove_possession(None),
            Err(Error::NonBlsKey)
        ));
    }

    #[test]
    fn test_deterministic_nonce() {
        let signer = create_test_signer();
        let handler = Handler::new(signer, None);

        let data = b"Test message";
        let nonce1 = handler.deterministic_nonce(data);
        let nonce2 = handler.deterministic_nonce(data);

        // Should be deterministic
        assert_eq!(nonce1, nonce2);

        // Different data should produce different nonce
        let nonce3 = handler.deterministic_nonce(b"Different message");
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_deterministic_nonce_hash() {
        let signer = create_test_signer();
        let handler = Handler::new(signer, None);

        let data = b"Test message";
        let hash1 = handler.deterministic_nonce_hash(data);
        let hash2 = handler.deterministic_nonce_hash(data);

        // Should be deterministic
        assert_eq!(hash1, hash2);
    }

    /// Octez defines the derivation for XMSS too (`xmss.ml:367-372`), so a tz6
    /// key answers these requests rather than failing them.
    #[test]
    fn a_tz6_key_derives_deterministic_nonces() {
        let signer = create_test_xmss_signer();

        assert!(signer.supports_deterministic_nonces());
        assert_eq!(
            signer.deterministic_nonce(b"Test message"),
            signer.deterministic_nonce(b"Test message")
        );
        assert_ne!(
            signer.deterministic_nonce(b"Test message"),
            signer.deterministic_nonce(b"Different message")
        );
        assert_eq!(
            signer.deterministic_nonce_hash(b"Test message"),
            signer.deterministic_nonce_hash(b"Test message")
        );
    }

    #[test]
    fn test_version_compatibility() {
        let signer = create_test_signer();

        assert!(
            signer
                .sign(b"data", None, Some(SignatureVersion::V0))
                .is_err(),
            "BLS is absent from the V0 signature union"
        );

        for version in [
            SignatureVersion::V1,
            SignatureVersion::V2,
            SignatureVersion::V3,
            SignatureVersion::V4,
        ] {
            assert!(
                signer.sign(b"data", None, Some(version)).is_ok(),
                "BLS is in the {version:?} signature union"
            );
        }

        // None (latest) should succeed for BLS
        assert!(signer.sign(b"data", None, None).is_ok());
    }

    /// XMSS enters the signature union only at V4 (`signature_v4.mli:110`), so
    /// signing below it would produce bytes with no tag the client can read.
    #[test]
    fn a_tz6_key_is_refused_by_every_signature_version_below_v4() {
        let signer = create_test_xmss_signer();

        for version in [
            SignatureVersion::V0,
            SignatureVersion::V1,
            SignatureVersion::V2,
            SignatureVersion::V3,
        ] {
            let err = signer
                .sign(b"data", None, Some(version))
                .expect_err("XMSS is absent from this signature union");
            assert!(
                matches!(err, Error::SigningFailed(ref msg) if msg.contains("XMSS")),
                "{version:?} rejected for the wrong reason: {err}"
            );
        }
    }

    /// The epoch is the store's to choose, so it arrives with the request. The
    /// signature carries it because leanVM-b's verifier takes the epoch as a
    /// separate input and the remote-signer wire has no field for one.
    #[test]
    fn a_tz6_key_signs_at_the_epoch_it_is_handed() {
        let signer = create_test_xmss_signer();
        let data = b"\x11block body";

        let signature = signer
            .sign_at(data, None, Some(SignatureVersion::V4), Some(3))
            .unwrap();

        let (PublicKey::Xmss(pk), Signature::Xmss(sig)) = (signer.public_key(), &signature) else {
            panic!("a tz6 signer answers with an xmpk and an xmsig");
        };
        assert_eq!(sig.epoch(), 3);
        pk.verify(sig, None, data)
            .expect("the signature verifies under the signer's own key");
    }

    /// Past the key's last epoch no one-time key is left, so the store's range
    /// and the key's own disagreeing is caught here rather than producing a
    /// signature nothing verifies.
    #[test]
    fn a_tz6_key_refuses_an_epoch_outside_its_range() {
        let signer = create_test_xmss_signer();

        let err = signer
            .sign_at(b"\x11data", None, None, Some(16))
            .expect_err("16 is past the 0..=15 range this key was generated for");

        assert!(
            matches!(
                err,
                Error::Key(scheme::Error::Xmss(crate::xmss::Error::EpochOutOfRange {
                    epoch: 16,
                    start: 0,
                    end: 15
                }))
            ),
            "refused for the wrong reason: {err}"
        );
    }

    /// Every XMSS epoch is a one-time key, so a signer with no epoch source
    /// refuses rather than picking one — signing twice at one epoch discloses
    /// the secret key.
    #[test]
    fn a_tz6_key_refuses_to_sign_while_no_epoch_source_exists() {
        let signer = create_test_xmss_signer();

        for version in [None, Some(SignatureVersion::V4)] {
            assert!(
                matches!(
                    signer.sign(b"\x11data", None, version),
                    Err(Error::Key(scheme::Error::EpochUnavailable))
                ),
                "signed at {version:?} with no epoch source"
            );
        }
    }

    /// The span a tz6 key is generated over is baked into the key and is what
    /// decides the date the card has to be rotated by. A key holding any other
    /// span is one whose rotation falls due somewhere nobody planned for.
    #[test]
    fn a_generated_tz6_key_holds_the_epochs_it_was_asked_for() {
        let signer = Unencrypted::generate_xmss(4..=19).expect("a non-empty span");

        assert_eq!(signer.secret_key().epoch_range(), Some(4..=19));
        assert!(signer.public_key_hash().to_b58check().starts_with("tz6"));
    }

    /// Two generations are two keys: a seed drawn once and reused would put one
    /// key on two cards, and two cards signing one XMSS key at one epoch
    /// discloses it.
    #[test]
    fn two_generated_tz6_keys_are_different_keys() {
        let first = Unencrypted::generate_xmss(0..=3).expect("a non-empty span");
        let second = Unencrypted::generate_xmss(0..=3).expect("a non-empty span");

        assert_ne!(first.public_key_hash(), second.public_key_hash());
    }

    /// An empty span is refused rather than answered with a key that can sign
    /// nowhere.
    #[test]
    fn an_inverted_epoch_span_generates_no_tz6_key() {
        let (first, last): (Epoch, Epoch) = (19, 4);
        assert!(Unencrypted::generate_xmss(first..=last).is_err());
    }
}
