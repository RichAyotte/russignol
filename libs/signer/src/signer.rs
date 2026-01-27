//! Core signer functionality for Tezos russignol-signer
//!
//! This module implements the main signing logic with magic byte validation.
//! Ported directly from: `src/lib_signer_backends/unencrypted.ml` and `src/bin_signer/handler.ml`

use crate::bls::{self, PublicKey, PublicKeyHash, SecretKey, Signature};
use crate::magic_bytes::{self, MagicByteError};
use thiserror::Error;

/// Signer errors
#[derive(Error, Debug)]
pub enum SignerError {
    /// BLS cryptographic error
    #[error("BLS error: {0}")]
    Bls(#[from] bls::BlsError),

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
pub type Result<T> = std::result::Result<T, SignerError>;

/// Signature version enumeration
/// Corresponds to: `src/lib_crypto/signature.ml` - Version type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVersion {
    /// Version 0 - Legacy (Ed25519, Secp256k1, P256 only)
    V0,
    /// Version 1 - (Ed25519, Secp256k1, P256 only)
    V1,
    /// Version 2 - Latest (includes BLS12-381)
    V2,
}

/// Unencrypted signer implementation
/// Corresponds to: `src/lib_signer_backends/unencrypted.ml`
#[derive(Clone)]
pub struct UnencryptedSigner {
    secret_key: SecretKey,
    public_key: PublicKey,
    public_key_hash: PublicKeyHash,
}

impl UnencryptedSigner {
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
    pub fn from_b58check(sk_b58: &str) -> Result<Self> {
        let secret_key = SecretKey::from_b58check(sk_b58)?;
        Ok(Self::new(secret_key))
    }

    /// Generate a new random signer
    /// Corresponds to: src/lib_crypto/bls.ml:359-371 - `generate_key`
    pub fn generate(seed: Option<&[u8; 32]>) -> Result<Self> {
        let (pkh, pk, sk) = bls::generate_key(seed)?;
        Ok(Self {
            secret_key: sk,
            public_key: pk,
            public_key_hash: pkh,
        })
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

    /// Sign data with optional watermark and version
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:82-110 - sign
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `watermark` - Optional watermark prefix
    /// * `version` - Optional signature version (for compatibility)
    ///
    /// # Returns
    /// * BLS12-381 signature
    pub fn sign(
        &self,
        data: &[u8],
        watermark: Option<&[u8]>,
        version: Option<SignatureVersion>,
    ) -> Result<Signature> {
        // For BLS12-381, we always use Version_2 or None
        // Corresponds to: unencrypted.ml:102-110
        match version {
            Some(SignatureVersion::V0) => {
                // BLS not supported in V0
                Err(SignerError::SigningFailed(
                    "BLS12-381 not supported in Signature version 0".to_string(),
                ))
            }
            Some(SignatureVersion::V1) => {
                // BLS not supported in V1
                Err(SignerError::SigningFailed(
                    "BLS12-381 not supported in Signature version 1".to_string(),
                ))
            }
            Some(SignatureVersion::V2) | None => {
                // BLS supported in V2 and V_latest
                Ok(bls::sign(&self.secret_key, data, watermark))
            }
        }
    }

    /// Prove possession of the secret key (BLS-specific operation)
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:124-134 - `bls_prove_possession`
    ///
    /// # Arguments
    /// * `override_pk` - Optional public key to use as message (for testing)
    ///
    /// # Returns
    /// * Proof of possession signature
    pub fn bls_prove_possession(&self, override_pk: Option<&PublicKey>) -> Result<Signature> {
        let msg_to_sign_vec = if let Some(pk) = override_pk {
            // If override_pk is provided (for testing), use its bytes directly.
            pk.to_bytes().to_vec()
        } else {
            // For production PoP: use the signer's public key bytes.
            self.public_key.to_bytes().to_vec()
        };
        // Pass the constructed message to bls::pop_prove.
        Ok(bls::pop_prove(&self.secret_key, Some(&msg_to_sign_vec)))
    }

    /// Generate deterministic nonce
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:112-115 - `deterministic_nonce`
    #[must_use]
    pub fn deterministic_nonce(&self, data: &[u8]) -> [u8; 32] {
        bls::deterministic_nonce(&self.secret_key, data)
    }

    /// Generate deterministic nonce hash
    /// Corresponds to: src/lib_signer_backends/unencrypted.ml:117-120 - `deterministic_nonce_hash`
    #[must_use]
    pub fn deterministic_nonce_hash(&self, data: &[u8]) -> [u8; 32] {
        bls::deterministic_nonce_hash(&self.secret_key, data)
    }

    /// Check if deterministic nonces are supported (always true for BLS)
    /// Corresponds to: `src/lib_signer_backends/unencrypted.ml:122` - `supports_deterministic_nonces`
    #[must_use]
    pub fn supports_deterministic_nonces(&self) -> bool {
        true
    }
}

/// Signer handler with magic byte validation
/// Corresponds to: `src/bin_signer/handler.ml`
pub struct SignerHandler {
    /// The underlying unencrypted signer
    pub signer: UnencryptedSigner,
    allowed_magic_bytes: Option<Vec<u8>>,
}

impl SignerHandler {
    /// Create a new signer handler
    ///
    /// # Arguments
    /// * `signer` - The underlying unencrypted signer
    /// * `allowed_magic_bytes` - Optional list of allowed magic bytes.
    ///   If None, all magic bytes are allowed.
    ///   Use `Some(vec![0x11, 0x12, 0x13])` for Tenderbake only.
    #[must_use]
    pub fn new(signer: UnencryptedSigner, allowed_magic_bytes: Option<Vec<u8>>) -> Self {
        Self {
            signer,
            allowed_magic_bytes,
        }
    }

    /// Create handler from base58check encoded secret key
    pub fn from_b58check(sk_b58: &str, allowed_magic_bytes: Option<Vec<u8>>) -> Result<Self> {
        let signer = UnencryptedSigner::from_b58check(sk_b58)?;
        Ok(Self::new(signer, allowed_magic_bytes))
    }

    /// Create handler with Tenderbake-only magic bytes (0x11, 0x12, 0x13)
    #[must_use]
    pub fn new_tenderbake_only(signer: UnencryptedSigner) -> Self {
        Self::new(signer, Some(vec![0x11, 0x12, 0x13]))
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
    /// * BLS12-381 signature if magic byte is valid
    /// * Error if magic byte check fails
    pub fn sign(
        &self,
        data: &[u8],
        watermark: Option<&[u8]>,
        version: Option<SignatureVersion>,
    ) -> Result<Signature> {
        // Check magic byte first
        // Corresponds to: handler.ml:293 - check_magic_byte name magic_bytes data
        magic_bytes::check_magic_byte(data, self.allowed_magic_bytes.as_deref())?;

        // Sign the data
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

    fn create_test_signer() -> UnencryptedSigner {
        let seed = [42u8; 32];
        UnencryptedSigner::generate(Some(&seed)).unwrap()
    }

    #[test]
    fn test_signer_creation() {
        let signer = create_test_signer();
        assert!(signer.supports_deterministic_nonces());
    }

    #[test]
    fn test_sign_basic() {
        let signer = create_test_signer();
        let data = b"Test message";

        let sig = signer.sign(data, None, None).unwrap();
        let pk = signer.public_key();

        // Verify signature
        assert!(bls::verify(pk, &sig, data, None));
    }

    #[test]
    fn test_sign_with_watermark() {
        let signer = create_test_signer();
        let watermark = &[0x11u8]; // Tenderbake block
        let data = b"Block data";

        let sig = signer.sign(data, Some(watermark), None).unwrap();
        let pk = signer.public_key();

        // Verify signature with watermark
        assert!(bls::verify(pk, &sig, data, Some(watermark)));
    }

    #[test]
    fn test_handler_no_magic_byte_restriction() {
        let signer = create_test_signer();
        let handler = SignerHandler::new(signer, None);

        // Any data should be signable without magic byte restriction
        let data = b"\xFFtest";
        let sig = handler.sign(data, None, None).unwrap();

        // Verify
        assert!(bls::verify(handler.public_key(), &sig, data, None));
    }

    #[test]
    fn test_handler_tenderbake_only() {
        let signer = create_test_signer();
        let handler = SignerHandler::new_tenderbake_only(signer);

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
        let handler = SignerHandler::new(signer, None);

        let proof = handler.bls_prove_possession(None).unwrap();

        // Verify proof of possession
        assert!(bls::pop_verify(
            handler.public_key(),
            &proof,
            Some(&handler.public_key().to_bytes())
        ));
    }

    #[test]
    fn test_bls_prove_possession_with_override() {
        let signer = create_test_signer();
        let handler = SignerHandler::new(signer, None);

        let pk = handler.public_key().clone();
        let proof = handler.bls_prove_possession(Some(&pk)).unwrap();

        // Verify proof with the public key as message
        assert!(bls::pop_verify(&pk, &proof, Some(&pk.to_bytes())));
    }

    #[test]
    fn test_deterministic_nonce() {
        let signer = create_test_signer();
        let handler = SignerHandler::new(signer, None);

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
        let handler = SignerHandler::new(signer, None);

        let data = b"Test message";
        let hash1 = handler.deterministic_nonce_hash(data);
        let hash2 = handler.deterministic_nonce_hash(data);

        // Should be deterministic
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_version_compatibility() {
        let signer = create_test_signer();

        // V0 should fail for BLS
        let result = signer.sign(b"data", None, Some(SignatureVersion::V0));
        assert!(result.is_err());

        // V1 should fail for BLS
        let result = signer.sign(b"data", None, Some(SignatureVersion::V1));
        assert!(result.is_err());

        // V2 should succeed for BLS
        let result = signer.sign(b"data", None, Some(SignatureVersion::V2));
        assert!(result.is_ok());

        // None (latest) should succeed for BLS
        let result = signer.sign(b"data", None, None);
        assert!(result.is_ok());
    }
}
