//! High-performance BLS12-381 signer for Tezos, optimized for Raspberry Pi Zero 2W
//!
//! This library provides a minimal, high-performance implementation of the Tezos
//! russignol-signer functionality, focusing solely on BLS12-381 signatures with
//! Tenderbake magic byte support (0x11, 0x12, 0x13).
//!
//! # Design Goals
//!
//! - **ARM Cortex-A53 Optimization**: Leverages NEON SIMD instructions for BLS12-381 operations
//! - **Minimal Binary Size**: Aggressive LTO and size optimizations for embedded deployment
//! - **Low Latency**: Stack-allocated buffers and minimal heap allocations
//! - **Constant-Time Operations**: Side-channel resistant cryptographic primitives
//!
//! # Architecture Mapping
//!
//! This implementation is a direct 1:1 port of the OCaml russignol-signer:
//!
//! - `bls` module ← `src/lib_crypto/bls.ml`
//! - `magic_bytes` module ← `src/bin_signer/handler.ml` (magic byte checking)
//! - `signer` module ← `src/lib_signer_backends/unencrypted.ml` + `handler.ml`
//!
//! # Example Usage
//!
//! ```rust
//! use russignol_signer_lib::{UnencryptedSigner, SignerHandler};
//!
//! // Generate a new signer with a deterministic seed
//! let seed = [42u8; 32];
//! let signer = UnencryptedSigner::generate(Some(&seed)).unwrap();
//!
//! // Create handler with Tenderbake-only magic bytes
//! let handler = SignerHandler::new_tenderbake_only(signer);
//!
//! // Sign Tenderbake block data
//! let block_data = b"\x11\x00\x00\x00\x01..."; // Magic byte 0x11 + block data
//! let signature = handler.sign(block_data, None, None).unwrap();
//!
//! // Get the public key hash (tz4 address)
//! let pkh = handler.public_key_hash();
//! println!("Signer address: {}", pkh.to_b58check());
//! ```

#![warn(missing_docs)]

mod base58check;
pub mod bls;
pub mod high_watermark;
pub mod magic_bytes;
pub mod protocol;
pub mod server;
pub mod signer;
/// Signing activity tracking module
pub mod signing_activity;
/// Test utilities for creating Tezos operation data
pub mod test_utils;
pub mod wallet;

// Re-export commonly used types
pub use bls::{BlsError, PublicKey, PublicKeyHash, SecretKey, Signature};
pub use high_watermark::{ChainId, HighWatermark, Watermark, WatermarkError};
pub use magic_bytes::{MagicByte, MagicByteError};
pub use protocol::{ProtocolError, SignerRequest, SignerResponse};
pub use server::{KeyManager as ServerKeyManager, RequestHandler, ServerError, SignerServer};
pub use signer::{SignatureVersion, SignerError, SignerHandler, UnencryptedSigner};
pub use signing_activity::{OperationType, SignatureActivity, SigningActivity};
pub use wallet::{KeyManager, StoredKey};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Target platform optimization level
#[cfg(target_arch = "aarch64")]
pub const TARGET_PLATFORM: &str = "ARM Cortex-A53 (Raspberry Pi Zero 2W)";

/// Target platform optimization level for non-ARM architectures
#[cfg(not(target_arch = "aarch64"))]
pub const TARGET_PLATFORM: &str = "Generic";
