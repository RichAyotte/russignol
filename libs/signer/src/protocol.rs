//! Binary protocol implementation for Tezos signer messages
//!
//! Implements the binary encoding/decoding for communication between octez-client
//! and russignol-signer over TCP sockets.
//!
//! Ported from: `src/lib_signer_services/signer_messages.ml`

use crate::bls::{PublicKey, PublicKeyHash, Signature};
use thiserror::Error;

/// A public key hash that includes the signature version byte.
/// This is used for requests that involve signing, where the client
/// can specify a version.
pub type VersionedPublicKeyHash = (PublicKeyHash, u8);

/// Protocol errors
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Unknown request tag
    #[error("Unknown request tag: 0x{0:02X}")]
    UnknownTag(u8),

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    /// Message too short
    #[error("Message too short: expected at least {expected}, got {actual}")]
    MessageTooShort {
        /// Expected minimum length
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Public key hash decoding error
    #[error("Failed to decode public key hash: {0}")]
    PkhDecodeError(String),

    /// Public key decoding error
    #[error("Failed to decode public key: {0}")]
    PkDecodeError(String),

    /// Signature decoding error
    #[error("Failed to decode signature: {0}")]
    SignatureDecodeError(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Data payload is too large
    #[error("Data payload too large: size {size} exceeds maximum {max}")]
    DataTooLarge {
        /// The size of the data payload
        size: usize,
        /// The maximum allowed size
        max: usize,
    },
}

/// Result type for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Request types from client to signer
/// Corresponds to: `src/lib_signer_services/signer_messages.ml:310-389`
#[derive(Debug, Clone, PartialEq)]
pub enum SignerRequest {
    /// Sign a message
    /// Tag: 0x00
    /// Corresponds to: signer_messages.ml:320-333
    Sign {
        /// Public key hash and version of the signer
        pkh: VersionedPublicKeyHash,
        /// Data to sign
        data: Vec<u8>,
        /// Optional authentication signature
        signature: Option<Signature>,
    },

    /// Get public key for a given hash
    /// Tag: 0x01
    /// Corresponds to: signer_messages.ml:335-339
    PublicKey {
        /// Public key hash to query
        pkh: PublicKeyHash,
    },

    /// Get list of authorized keys (if authentication enabled)
    /// Tag: 0x02
    /// Corresponds to: signer_messages.ml:341-342
    AuthorizedKeys,

    /// Generate deterministic nonce
    /// Tag: 0x03
    /// Corresponds to: signer_messages.ml:344-357
    DeterministicNonce {
        /// Public key hash and version
        pkh: VersionedPublicKeyHash,
        /// Data to generate nonce from
        data: Vec<u8>,
        /// Optional authentication signature
        signature: Option<Signature>,
    },

    /// Generate deterministic nonce hash
    /// Tag: 0x04
    /// Corresponds to: signer_messages.ml:359-372
    DeterministicNonceHash {
        /// Public key hash and version
        pkh: VersionedPublicKeyHash,
        /// Data to generate nonce hash from
        data: Vec<u8>,
        /// Optional authentication signature
        signature: Option<Signature>,
    },

    /// Check if deterministic nonces are supported
    /// Tag: 0x05
    /// Corresponds to: signer_messages.ml:374-378
    SupportsDeterministicNonces {
        /// Public key hash to check
        pkh: PublicKeyHash,
    },

    /// Get list of known public key hashes
    /// Tag: 0x06
    /// Corresponds to: signer_messages.ml:380-381
    KnownKeys,

    /// BLS proof of possession request
    /// Tag: 0x07
    /// Corresponds to: signer_messages.ml:383-388
    BlsProveRequest {
        /// Public key hash
        pkh: PublicKeyHash,
        /// Optional override public key (for testing)
        override_pk: Option<PublicKey>,
    },
}

impl SignerRequest {
    /// Get the request tag byte
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Sign { .. } => 0x00,
            Self::PublicKey { .. } => 0x01,
            Self::AuthorizedKeys => 0x02,
            Self::DeterministicNonce { .. } => 0x03,
            Self::DeterministicNonceHash { .. } => 0x04,
            Self::SupportsDeterministicNonces { .. } => 0x05,
            Self::KnownKeys => 0x06,
            Self::BlsProveRequest { .. } => 0x07,
        }
    }
}

/// Response types from signer to client
/// Corresponds to: `src/lib_signer_services/signer_messages.ml:391-461`
#[derive(Debug, Clone, PartialEq)]
pub enum SignerResponse {
    /// Signature response
    /// Corresponds to: signer_messages.ml:399-405
    Signature(Signature),

    /// Public key response
    /// Corresponds to: signer_messages.ml:407-413
    PublicKey(PublicKey),

    /// Authorized keys response
    /// None if authentication is disabled
    /// Some(keys) if authentication is enabled
    /// Corresponds to: signer_messages.ml:415-428
    AuthorizedKeys(Option<Vec<PublicKeyHash>>),

    /// Deterministic nonce response (32 bytes)
    /// Corresponds to: signer_messages.ml:430-435
    Nonce([u8; 32]),

    /// Deterministic nonce hash response (32 bytes)
    /// Corresponds to: signer_messages.ml:437-442
    NonceHash([u8; 32]),

    /// Boolean response for `supports_deterministic_nonces`
    /// Corresponds to: signer_messages.ml:444-448
    Bool(bool),

    /// List of known public key hashes
    /// Corresponds to: signer_messages.ml:450-455
    KnownKeys(Vec<PublicKeyHash>),

    /// Error response
    /// Corresponds to: Error handling in OCaml
    Error(String),
}

impl SignerResponse {
    /// Get the response tag byte
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Signature(_) => 0x00,
            Self::PublicKey(_) => 0x01,
            Self::AuthorizedKeys(_) => 0x02,
            Self::Nonce(_) => 0x03,
            Self::NonceHash(_) => 0x04,
            Self::Bool(_) => 0x05,
            Self::KnownKeys(_) => 0x06,
            Self::Error(_) => 0xFF,
        }
    }
}

/// Binary encoding/decoding for Tezos signer protocol
/// Corresponds to: Tezos `Data_encoding` library
pub mod encoding {
    use super::{
        ProtocolError, PublicKey, PublicKeyHash, Result, Signature, SignerRequest, SignerResponse,
        VersionedPublicKeyHash,
    };
    use std::io::{Cursor, Read, Write};

    /// Maximum size for variable-length data payloads (e.g., block headers).
    /// Matches octez-signer's implicit limit from uint16 socket framing.
    const MAX_DATA_LEN: usize = 65535;

    /// Encode a `SignerRequest` to binary format
    /// Corresponds to: `signer_messages.ml:Request.encoding`
    pub fn encode_request(req: &SignerRequest) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Write tag
        buf.write_all(&[req.tag()])?;

        match req {
            SignerRequest::Sign {
                pkh,
                data,
                signature,
            }
            | SignerRequest::DeterministicNonce {
                pkh,
                data,
                signature,
            }
            | SignerRequest::DeterministicNonceHash {
                pkh,
                data,
                signature,
            } => {
                encode_versioned_pkh(&mut buf, pkh)?;
                encode_bytes(&mut buf, data)?;
                encode_option_signature(&mut buf, signature.as_ref())?;
            }
            SignerRequest::PublicKey { pkh }
            | SignerRequest::SupportsDeterministicNonces { pkh } => {
                encode_raw_pkh(&mut buf, pkh)?;
            }
            SignerRequest::AuthorizedKeys | SignerRequest::KnownKeys => {
                // No additional data
            }
            SignerRequest::BlsProveRequest { pkh, override_pk } => {
                encode_raw_pkh(&mut buf, pkh)?;
                encode_option_pk(&mut buf, override_pk.as_ref())?;
            }
        }

        Ok(buf)
    }

    /// Decode a `SignerRequest` from binary format
    /// Corresponds to: `signer_messages.ml:Request.encoding`
    pub fn decode_request(data: &[u8]) -> Result<SignerRequest> {
        let mut cursor = Cursor::new(data);

        // Read tag
        let tag = read_u8(&mut cursor)?;

        match tag {
            0x00 => {
                let pkh = decode_versioned_pkh(&mut cursor)?;
                let data = decode_bytes(&mut cursor)?;
                let signature = decode_option_signature(&mut cursor)?;
                Ok(SignerRequest::Sign {
                    pkh,
                    data,
                    signature,
                })
            }
            0x01 => {
                let pkh = decode_raw_pkh(&mut cursor)?;
                Ok(SignerRequest::PublicKey { pkh })
            }
            0x02 => Ok(SignerRequest::AuthorizedKeys),
            0x03 => {
                let pkh = decode_versioned_pkh(&mut cursor)?;
                let data = decode_bytes(&mut cursor)?;
                let signature = decode_option_signature(&mut cursor)?;
                Ok(SignerRequest::DeterministicNonce {
                    pkh,
                    data,
                    signature,
                })
            }
            0x04 => {
                let pkh = decode_versioned_pkh(&mut cursor)?;
                let data = decode_bytes(&mut cursor)?;
                let signature = decode_option_signature(&mut cursor)?;
                Ok(SignerRequest::DeterministicNonceHash {
                    pkh,
                    data,
                    signature,
                })
            }
            0x05 => {
                let pkh = decode_raw_pkh(&mut cursor)?;
                Ok(SignerRequest::SupportsDeterministicNonces { pkh })
            }
            0x06 => Ok(SignerRequest::KnownKeys),
            0x07 => {
                let pkh = decode_raw_pkh(&mut cursor)?;
                let override_pk = decode_option_pk(&mut cursor)?;
                Ok(SignerRequest::BlsProveRequest { pkh, override_pk })
            }
            _ => Err(ProtocolError::UnknownTag(tag)),
        }
    }

    /// Encode a `SignerResponse` to binary format
    /// Corresponds to: `signer_messages.ml:Response.encoding`
    ///
    /// NOTE: OCaml wraps all responses in `result_encoding`, which means:
    /// - Tag 0x00 = Ok(response)
    /// - Tag 0x01 = Error(message)
    ///
    /// We handle `SignerResponse::Error` separately to wrap it in `Error` result.
    pub fn encode_response(resp: &SignerResponse) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        if let SignerResponse::Error(msg) = resp {
            // Write Result::Error tag
            buf.write_all(&[0x01])?;

            // Tezos Data_encoding.json uses BSON for binary encoding.
            // Construct a "Generic error" which is accepted by octez-client.
            // Schema: { "kind": "generic", "error": String }
            let error_doc = bson::doc! {
                "kind": "generic",
                "error": msg,
            };

            let mut bson_bytes = Vec::new();
            error_doc.to_writer(&mut bson_bytes).map_err(|e| {
                ProtocolError::InvalidFormat(format!("BSON serialization error: {e}"))
            })?;

            // Encode as a list (Trace) containing one error.
            //
            // Data_encoding structure:
            // 1. Trace (list): [Total Bytes (u32)] [Item 1] [Item 2] ...
            // 2. Error (json/bson): [Length (u32)] [BSON bytes]
            //
            // So we need: [Total Len] [Item Len] [BSON Bytes]
            // Where Item Len = bson_bytes.len()
            // And Total Len = Item Len + 4 (for the Item Len prefix)

            let item_len = u32::try_from(bson_bytes.len()).map_err(|_| {
                ProtocolError::InvalidFormat("BSON error message too large".to_string())
            })?;
            let total_len = item_len + 4;

            buf.write_all(&total_len.to_be_bytes())?; // Trace length
            buf.write_all(&item_len.to_be_bytes())?; // Error item length
            buf.write_all(&bson_bytes)?; // Error item body

            log::debug!("=> SEND ({} bytes): {}", buf.len(), hex::encode(&buf));
            return Ok(buf);
        }

        // For all other (successful) responses, write Result::Ok tag
        buf.write_all(&[0x00])?;

        // In request-response protocols, the client knows what type of response
        // to expect based on the request it sent. The response payload itself
        // is not tagged, except for unions like AuthorizedKeys.
        match resp {
            SignerResponse::Signature(sig) => {
                encode_signature(&mut buf, sig)?;
            }
            SignerResponse::PublicKey(pk) => {
                encode_pk(&mut buf, pk)?;
            }
            SignerResponse::AuthorizedKeys(keys) => {
                // AuthorizedKeys uses a union encoding, not an option encoding
                // Tag 0 = No_authentication (no auth required)
                // Tag 1 = Authorized_keys (list of PKHs)
                match keys {
                    None => {
                        // No authentication required - just write tag 0
                        buf.write_all(&[0x00])?;
                    }
                    Some(list) => {
                        // Authentication enabled - write tag 1 + list
                        buf.write_all(&[0x01])?;
                        encode_pkh_list(&mut buf, list)?;
                    }
                }
            }
            SignerResponse::Nonce(nonce) => {
                buf.extend_from_slice(nonce);
            }
            SignerResponse::NonceHash(hash) => {
                buf.extend_from_slice(hash);
            }
            SignerResponse::Bool(b) => {
                buf.write_all(&[if *b { 0xFF } else { 0x00 }])?;
            }
            SignerResponse::KnownKeys(keys) => {
                encode_pkh_list(&mut buf, keys)?;
            }
            SignerResponse::Error(_) => {
                // This case is handled above and should not be reached
                unreachable!();
            }
        }

        log::debug!("=> SEND ({} bytes): {}", buf.len(), hex::encode(&buf));
        Ok(buf)
    }

    /// Decode a `SignerResponse` from binary format
    /// Corresponds to: `signer_messages.ml:Response.encoding`
    pub fn decode_response(data: &[u8], request: &SignerRequest) -> Result<SignerResponse> {
        let mut cursor = Cursor::new(data);

        // Read the outer Result tag
        let result_tag = read_u8(&mut cursor)?;
        match result_tag {
            0x01 => {
                // Error case
                // The "bytes" here is the whole encoded trace (list of errors).
                // [Total Len] [Item 1] [Item 2]...
                // decode_bytes reads [Total Len] and returns the content (Total Len bytes).
                let trace_bytes = decode_bytes(&mut cursor)?;

                // Now parse the trace (list of items)
                // Each item is [Len] [Bytes] (where Bytes is JSON)
                let mut trace_cursor = Cursor::new(&trace_bytes);
                let mut error_msgs = Vec::new();

                while trace_cursor.position() < trace_bytes.len() as u64 {
                    // Read item length
                    // Need to check if we have enough bytes for length
                    if trace_cursor.position() + 4 > trace_bytes.len() as u64 {
                        break;
                    }
                    let item_len = match read_u32_be(&mut trace_cursor) {
                        Ok(l) => l as usize,
                        Err(_) => break,
                    };

                    if trace_cursor.position() + item_len as u64 > trace_bytes.len() as u64 {
                        break;
                    }

                    let mut json_bytes = vec![0u8; item_len];
                    if trace_cursor.read_exact(&mut json_bytes).is_err() {
                        break;
                    }

                    // Try to parse BSON (primary format for binary encoding)
                    if let Ok(doc) = bson::Document::from_reader(Cursor::new(&json_bytes)) {
                        if let Ok(msg) = doc.get_str("error") {
                            error_msgs.push(msg.to_string());
                        }
                    }
                    // Fallback: Try to parse JSON (for legacy or text mode if ever used)
                    else if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&json_bytes)
                        && let Some(msg) = val.get("error").and_then(|v| v.as_str())
                    {
                        error_msgs.push(msg.to_string());
                    }
                }

                let full_msg = if error_msgs.is_empty() {
                    // Fallback if parsing failed or empty (e.g. raw string or legacy format)
                    // Note: if it was BSON, this will look like garbage.
                    String::from_utf8_lossy(&trace_bytes).to_string()
                } else {
                    error_msgs.join("; ")
                };

                Ok(SignerResponse::Error(full_msg))
            }
            0x00 => {
                // Ok case - decode payload based on what was requested
                match request {
                    SignerRequest::Sign { .. } | SignerRequest::BlsProveRequest { .. } => {
                        let sig = decode_signature(&mut cursor)?;
                        Ok(SignerResponse::Signature(sig))
                    }
                    SignerRequest::PublicKey { .. } => {
                        let pk = decode_pk(&mut cursor)?;
                        Ok(SignerResponse::PublicKey(pk))
                    }
                    SignerRequest::AuthorizedKeys => {
                        let keys = decode_option_pkh_list(&mut cursor)?;
                        Ok(SignerResponse::AuthorizedKeys(keys))
                    }
                    SignerRequest::DeterministicNonce { .. } => {
                        let mut nonce = [0u8; 32];
                        cursor.read_exact(&mut nonce)?;
                        Ok(SignerResponse::Nonce(nonce))
                    }
                    SignerRequest::DeterministicNonceHash { .. } => {
                        let mut hash = [0u8; 32];
                        cursor.read_exact(&mut hash)?;
                        Ok(SignerResponse::NonceHash(hash))
                    }
                    SignerRequest::SupportsDeterministicNonces { .. } => {
                        let b = read_u8(&mut cursor)? != 0x00;
                        Ok(SignerResponse::Bool(b))
                    }
                    SignerRequest::KnownKeys => {
                        let keys = decode_pkh_list(&mut cursor)?;
                        Ok(SignerResponse::KnownKeys(keys))
                    }
                }
            }
            tag => Err(ProtocolError::InvalidFormat(format!(
                "Invalid Result tag: 0x{tag:02X}"
            ))),
        }
    }

    // Helper functions for encoding primitives

    fn read_u8<R: Read>(cursor: &mut R) -> Result<u8> {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u32_be<R: Read>(cursor: &mut R) -> Result<u32> {
        let mut buf = [0u8; 4];
        cursor.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    /// Encodes a PKH using the simple tagged union format.
    /// `[tag][20_bytes]`
    fn encode_raw_pkh<W: Write>(buf: &mut W, pkh: &PublicKeyHash) -> Result<()> {
        // The `public_key_hash` encoding is a tagged union.
        // For this signer, we only support BLS keys, which have tag 3.
        buf.write_all(&[3])?;
        buf.write_all(pkh.to_bytes())?;
        Ok(())
    }

    /// Decodes a PKH using the simple tagged union format.
    /// `[tag][20_bytes]`
    fn decode_raw_pkh<R: Read>(cursor: &mut R) -> Result<PublicKeyHash> {
        let tag = read_u8(cursor)?;
        match tag {
            // BLS
            0x03 => {
                let mut bytes = [0u8; 20];
                cursor.read_exact(&mut bytes)?;
                PublicKeyHash::from_bytes(&bytes)
                    .map_err(|e| ProtocolError::PkhDecodeError(e.to_string()))
            }
            _ => Err(ProtocolError::InvalidFormat(format!(
                "Unsupported PKH encoding tag: 0x{tag:02X}. Only BLS (tag 3) is supported."
            ))),
        }
    }

    /// Encodes a PKH using the complex, versioned format for signing requests.
    /// `[outer_tag][inner_tag][20_bytes][version]`
    fn encode_versioned_pkh<W: Write>(buf: &mut W, pkh: &VersionedPublicKeyHash) -> Result<()> {
        // Outer tag for `pkh_encoding` union
        buf.write_all(&[3])?; // 3 = BLS with version
        // Inner encoding is `obj2 (req "pkh" raw_encoding) (req "version" ...)`
        encode_raw_pkh(buf, &pkh.0)?;
        buf.write_all(&[pkh.1])?; // version
        Ok(())
    }

    /// Decodes a PKH using the complex, versioned format for signing requests.
    /// `[outer_tag][inner_tag][20_bytes][version]`
    fn decode_versioned_pkh<R: Read>(cursor: &mut R) -> Result<VersionedPublicKeyHash> {
        let outer_tag = read_u8(cursor)?;
        if outer_tag != 3 {
            return Err(ProtocolError::InvalidFormat(format!(
                "Unsupported versioned PKH tag: 0x{outer_tag:02X}. Only BLS (tag 3) is supported."
            )));
        }
        let pkh = decode_raw_pkh(cursor)?;
        let version = read_u8(cursor)?;
        Ok((pkh, version))
    }

    fn encode_pk<W: Write>(buf: &mut W, pk: &PublicKey) -> Result<()> {
        // Public key encoding is a tagged union. BLS is tag 3.
        buf.write_all(&[3])?;
        let bytes = pk.to_bytes();
        buf.write_all(&bytes)?;
        Ok(())
    }

    fn decode_pk<R: Read>(cursor: &mut R) -> Result<PublicKey> {
        let tag = read_u8(cursor)?;
        if tag != 3 {
            return Err(ProtocolError::InvalidFormat(format!(
                "Unsupported PK encoding tag: 0x{tag:02X}. Only BLS (tag 3) is supported."
            )));
        }
        let mut bytes = [0u8; 48];
        cursor.read_exact(&mut bytes)?;
        PublicKey::from_bytes(&bytes).map_err(|e| ProtocolError::PkDecodeError(e.to_string()))
    }

    fn encode_signature<W: Write>(buf: &mut W, sig: &Signature) -> Result<()> {
        let bytes = sig.to_bytes();
        buf.write_all(&bytes)?;
        Ok(())
    }

    fn decode_signature<R: Read>(cursor: &mut R) -> Result<Signature> {
        let mut bytes = [0u8; 96];
        cursor.read_exact(&mut bytes)?;
        Signature::from_bytes(&bytes)
            .map_err(|e| ProtocolError::SignatureDecodeError(e.to_string()))
    }

    fn encode_bytes<W: Write>(buf: &mut W, data: &[u8]) -> Result<()> {
        // Length-prefixed bytes (4-byte big-endian length)
        let len = u32::try_from(data.len()).map_err(|_| {
            ProtocolError::InvalidFormat("Data length exceeds u32::MAX".to_string())
        })?;
        buf.write_all(&len.to_be_bytes())?;
        buf.write_all(data)?;
        Ok(())
    }

    fn decode_bytes<R: Read>(cursor: &mut R) -> Result<Vec<u8>> {
        let len = read_u32_be(cursor)? as usize;

        // Prevent DoS attack from malicious length prefix
        if len > MAX_DATA_LEN {
            return Err(ProtocolError::DataTooLarge {
                size: len,
                max: MAX_DATA_LEN,
            });
        }

        let mut data = vec![0u8; len];
        cursor.read_exact(&mut data)?;
        Ok(data)
    }

    fn encode_option_signature<W: Write>(buf: &mut W, sig: Option<&Signature>) -> Result<()> {
        if let Some(s) = sig {
            buf.write_all(&[0xFF])?; // Some tag
            encode_signature(buf, s)?;
        } else {
            // Per spec, if an option is at the end of an object, it's omitted entirely.
        }
        Ok(())
    }

    fn decode_option_signature<R: Read>(cursor: &mut R) -> Result<Option<Signature>> {
        // In obj3 encoding, optional fields at the end are omitted entirely when None
        // So if we hit EOF, it means the signature is None
        let mut buf = [0u8; 1];
        match cursor.read(&mut buf) {
            Ok(0) => Ok(None), // EOF
            Ok(1) => {
                if buf[0] == 0xFF {
                    Ok(Some(decode_signature(cursor)?))
                } else {
                    Err(ProtocolError::InvalidFormat(format!(
                        "Invalid option tag: 0x{:02X}",
                        buf[0]
                    )))
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    Ok(None)
                } else {
                    Err(e.into())
                }
            }
            _ => unreachable!(),
        }
    }

    fn encode_option_pk<W: Write>(buf: &mut W, pk: Option<&PublicKey>) -> Result<()> {
        match pk {
            Some(p) => {
                buf.write_all(&[0xFF])?; // Some tag
                encode_pk(buf, p)?;
            }
            None => {
                buf.write_all(&[0x00])?; // None tag
            }
        }
        Ok(())
    }

    fn decode_option_pk<R: Read>(cursor: &mut R) -> Result<Option<PublicKey>> {
        let tag = read_u8(cursor)?;
        match tag {
            0xFF => Ok(Some(decode_pk(cursor)?)),
            0x00 => Ok(None),
            _ => Err(ProtocolError::InvalidFormat(format!(
                "Invalid option tag: 0x{tag:02X}"
            ))),
        }
    }

    fn encode_pkh_list<W: Write>(buf: &mut W, list: &[PublicKeyHash]) -> Result<()> {
        // The OCaml `Data_encoding.list` writes the total byte size of the list,
        // not the number of items.
        // Each raw PKH is encoded as 1-byte tag + 20-byte hash = 21 bytes.
        let total_byte_size = list.len() * (1 + 20);
        let len = u32::try_from(total_byte_size).map_err(|_| {
            ProtocolError::InvalidFormat("List byte size exceeds u32::MAX".to_string())
        })?;
        buf.write_all(&len.to_be_bytes())?;
        for pkh in list {
            encode_raw_pkh(buf, pkh)?;
        }
        Ok(())
    }

    fn decode_pkh_list<R: Read>(cursor: &mut R) -> Result<Vec<PublicKeyHash>> {
        let len_bytes = read_u32_be(cursor)? as usize;
        let mut pkhs = Vec::new();
        let mut bytes_read = 0;
        // Each raw PKH is 21 bytes (1 tag + 20 hash)
        while bytes_read < len_bytes {
            pkhs.push(decode_raw_pkh(cursor)?);
            bytes_read += 21;
        }
        Ok(pkhs)
    }

    fn decode_option_pkh_list<R: Read>(cursor: &mut R) -> Result<Option<Vec<PublicKeyHash>>> {
        let tag = read_u8(cursor)?;
        match tag {
            0xFF => Ok(Some(decode_pkh_list(cursor)?)),
            0x00 => Ok(None),
            _ => Err(ProtocolError::InvalidFormat(format!(
                "Invalid option tag: 0x{tag:02X}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{encoding::*, *};
    use crate::bls::generate_key;

    #[test]
    fn test_request_tags() {
        // Verify tag values match OCaml implementation
        let pkh = PublicKeyHash::from_bytes(&[0u8; 20]).unwrap();

        assert_eq!(
            SignerRequest::Sign {
                pkh: (pkh, 0),
                data: vec![],
                signature: None
            }
            .tag(),
            0x00
        );

        assert_eq!(SignerRequest::PublicKey { pkh }.tag(), 0x01);
        assert_eq!(SignerRequest::AuthorizedKeys.tag(), 0x02);

        assert_eq!(
            SignerRequest::DeterministicNonce {
                pkh: (pkh, 0),
                data: vec![],
                signature: None
            }
            .tag(),
            0x03
        );

        assert_eq!(
            SignerRequest::DeterministicNonceHash {
                pkh: (pkh, 0),
                data: vec![],
                signature: None
            }
            .tag(),
            0x04
        );

        assert_eq!(
            SignerRequest::SupportsDeterministicNonces { pkh }.tag(),
            0x05
        );
        assert_eq!(SignerRequest::KnownKeys.tag(), 0x06);

        assert_eq!(
            SignerRequest::BlsProveRequest {
                pkh,
                override_pk: None
            }
            .tag(),
            0x07
        );
    }

    #[test]
    fn test_response_tags() {
        let seed = [42u8; 32];
        let (pkh, pk, sk) = generate_key(Some(&seed)).unwrap();
        let data = b"test";
        let sig = crate::bls::sign(&sk, data, None);

        assert_eq!(SignerResponse::Signature(sig).tag(), 0x00);
        assert_eq!(SignerResponse::PublicKey(pk).tag(), 0x01);
        assert_eq!(SignerResponse::AuthorizedKeys(None).tag(), 0x02);
        assert_eq!(SignerResponse::Nonce([0u8; 32]).tag(), 0x03);
        assert_eq!(SignerResponse::NonceHash([0u8; 32]).tag(), 0x04);
        assert_eq!(SignerResponse::Bool(true).tag(), 0x05);
        assert_eq!(SignerResponse::KnownKeys(vec![pkh]).tag(), 0x06);
        assert_eq!(SignerResponse::Error("test".to_string()).tag(), 0xFF);
    }

    #[test]
    fn test_roundtrip_sign_request() {
        let pkh = PublicKeyHash::from_bytes(&[1u8; 20]).unwrap();
        let data = vec![0x11, 0x00, 0x00, 0x00, 0x01];
        let request = SignerRequest::Sign {
            pkh: (pkh, 2),
            data: data.clone(),
            signature: None,
        };
        let encoded = encode_request(&request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_roundtrip_public_key_request() {
        let pkh = PublicKeyHash::from_bytes(&[2u8; 20]).unwrap();
        let request = SignerRequest::PublicKey { pkh };
        let encoded = encode_request(&request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_roundtrip_authorized_keys_request() {
        let request = SignerRequest::AuthorizedKeys;
        let encoded = encode_request(&request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_roundtrip_signature_response() {
        let pkh = PublicKeyHash::from_bytes(&[0u8; 20]).unwrap();
        let seed = [1u8; 32];
        let (_pkh, _pk, sk) = generate_key(Some(&seed)).unwrap();
        let data = b"test data";
        let sig = crate::bls::sign(&sk, data, None);

        let request = SignerRequest::Sign {
            pkh: (pkh, 0),
            data: vec![],
            signature: None,
        };
        let response = SignerResponse::Signature(sig);

        let encoded = encode_response(&response).unwrap();
        let decoded = decode_response(&encoded, &request).unwrap();

        assert_eq!(response, decoded);
    }

    #[test]
    fn test_roundtrip_public_key_response() {
        let pkh = PublicKeyHash::from_bytes(&[0u8; 20]).unwrap();
        let seed = [2u8; 32];
        let (_pkh, pk, _sk) = generate_key(Some(&seed)).unwrap();

        let request = SignerRequest::PublicKey { pkh };
        let response = SignerResponse::PublicKey(pk);

        let encoded = encode_response(&response).unwrap();
        let decoded = decode_response(&encoded, &request).unwrap();

        assert_eq!(response, decoded);
    }

    #[test]
    fn test_roundtrip_nonce_response() {
        let pkh = PublicKeyHash::from_bytes(&[0u8; 20]).unwrap();
        let nonce = [5u8; 32];

        let request = SignerRequest::DeterministicNonce {
            pkh: (pkh, 0),
            data: vec![],
            signature: None,
        };
        let response = SignerResponse::Nonce(nonce);

        let encoded = encode_response(&response).unwrap();
        let decoded = decode_response(&encoded, &request).unwrap();

        assert_eq!(response, decoded);
    }

    #[test]
    fn test_roundtrip_bool_response() {
        let pkh = PublicKeyHash::from_bytes(&[0u8; 20]).unwrap();
        let request = SignerRequest::SupportsDeterministicNonces { pkh };

        let response_true = SignerResponse::Bool(true);
        let encoded_true = encode_response(&response_true).unwrap();
        let decoded_true = decode_response(&encoded_true, &request).unwrap();
        assert_eq!(response_true, decoded_true);

        let response_false = SignerResponse::Bool(false);
        let encoded_false = encode_response(&response_false).unwrap();
        let decoded_false = decode_response(&encoded_false, &request).unwrap();
        assert_eq!(response_false, decoded_false);
    }

    #[test]
    fn test_roundtrip_known_keys_response() {
        let pkh1 = PublicKeyHash::from_bytes(&[6u8; 20]).unwrap();
        let pkh2 = PublicKeyHash::from_bytes(&[7u8; 20]).unwrap();

        let request = SignerRequest::KnownKeys;
        let response = SignerResponse::KnownKeys(vec![pkh1, pkh2]);

        let encoded = encode_response(&response).unwrap();
        let decoded = decode_response(&encoded, &request).unwrap();

        assert_eq!(response, decoded);
    }

    #[test]
    fn test_roundtrip_error_response() {
        let request = SignerRequest::KnownKeys; // Dummy request
        let response = SignerResponse::Error("Test error message".to_string());

        let encoded = encode_response(&response).unwrap();
        let decoded = decode_response(&encoded, &request).unwrap();

        // We check that we can successfully roundtrip the error message
        assert_eq!(response, decoded);
    }

    /// Test that `MAX_DATA_LEN` matches octez-signer's uint16 socket frame limit
    ///
    /// octez-signer uses a 2-byte (uint16) length prefix for socket framing,
    /// limiting total message size to 65535 bytes. We match this behavior.
    #[test]
    fn test_max_data_len_matches_octez_signer() {
        // octez-signer's implicit limit from uint16 socket framing
        const SOCKET_FRAME_MAX: usize = 65535;

        // Create a Sign request with data under the limit - should succeed
        let pkh = PublicKeyHash::from_bytes(&[1u8; 20]).unwrap();
        let data_under_limit = vec![0x11u8; SOCKET_FRAME_MAX - 1];
        let request_under = SignerRequest::Sign {
            pkh: (pkh, 0),
            data: data_under_limit,
            signature: None,
        };
        let encoded_under = encode_request(&request_under).unwrap();
        assert!(
            decode_request(&encoded_under).is_ok(),
            "Data under 64KB limit should decode successfully"
        );

        // Create a Sign request with data over the limit - should fail
        let data_over_limit = vec![0x11u8; SOCKET_FRAME_MAX + 1];
        let request_over = SignerRequest::Sign {
            pkh: (pkh, 0),
            data: data_over_limit,
            signature: None,
        };
        let encoded_over = encode_request(&request_over).unwrap();
        let result = decode_request(&encoded_over);
        assert!(
            result.is_err(),
            "Data over 64KB limit should be rejected to match octez-signer"
        );

        // Verify the error is specifically DataTooLarge
        match result {
            Err(ProtocolError::DataTooLarge { size, max }) => {
                assert_eq!(size, SOCKET_FRAME_MAX + 1);
                assert_eq!(
                    max, SOCKET_FRAME_MAX,
                    "MAX_DATA_LEN should be 65535 to match octez-signer"
                );
            }
            other => panic!("Expected DataTooLarge error, got: {other:?}"),
        }
    }
}
