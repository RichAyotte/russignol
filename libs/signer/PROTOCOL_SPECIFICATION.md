# Tezos Remote Signer TCP Protocol Specification

**Reverse-engineered from OCaml implementation**
**Date:** November 2025
**Source:** `src/lib_base/unix/socket.ml`, `src/lib_signer_services/signer_messages.ml`

## Overview

The Tezos remote signer uses a binary protocol over TCP sockets for communication between the baker/client and signer. This document provides the complete protocol specification based on the actual OCaml implementation.

## Message Framing

### Length Prefix
- **Size:** 2 bytes (uint16, big-endian)
- **Maximum message size:** 65,535 bytes
- **Note:** Earlier documentation incorrectly stated 4 bytes

```rust
// OCaml source: src/lib_base/unix/socket.ml
let size_of_length_of_message_payload = 2
```

### Message Structure
```
[2-byte length][N bytes payload]
```

**Example:**
```
[00 6a]  // Length = 106 bytes
[00 03 03 b0 8f ... ]  // 106 bytes of payload
```

## Response Wrapper

**All responses are wrapped in a Result encoding:**

```
[0x00]  // Result::Ok tag
[response data]
```

**OR**

```
[0x01]  // Result::Error tag
[error message as bytes]
```

**Important:** Responses do NOT include a response type tag after the Result tag. The client knows what type to expect based on the request sent.

## Request Types

### Request Tag Encoding

```rust
0x00 - Sign
0x01 - PublicKey
0x02 - AuthorizedKeys
0x03 - DeterministicNonce
0x04 - DeterministicNonceHash
0x05 - SupportsDeterministicNonces
0x06 - KnownKeys
0x07 - BlsProveRequest
```

### 1. Sign Request (Tag 0x00)

**Structure:**
```
[0x00]  // Sign tag
[PKH encoding]  // See PKH Encoding section
[data length: 4 bytes big-endian]
[data bytes]
[optional signature]  // Omitted entirely if None (EOF = None)
```

**Example (106 bytes):**
```
00              // Sign tag
03 03           // PKH: BLS with version (tag 3, inner tag 3)
b0 8f...        // PKH: 20 bytes
02              // PKH: version byte
00 00 00 4e     // Data length: 78 bytes
12 5c 3b...     // Data: 78 bytes (starts with magic byte 0x12)
                // No signature (EOF)
```

### 2. PublicKey Request (Tag 0x01)

**Structure:**
```
[0x01]  // PublicKey tag
[PKH encoding]
```

### 3. AuthorizedKeys Request (Tag 0x02)

**Structure:**
```
[0x02]  // AuthorizedKeys tag only
```

**Note:** This is the simplest request - just one byte!

### 4-7. Other Requests

Similar structure to Sign request, with different tags and fields. See `signer_messages.ml` for details.

## Public Key Hash (PKH) Encoding

PKH encoding is a **union** with different variants for different key types and BLS versioning.

### Union Tags

```rust
0x00 - Ed25519 PKH (20 bytes)
0x01 - Secp256k1 PKH (20 bytes)
0x02 - P256 PKH (20 bytes)
0x03 - BLS with version (nested structure)
```

### Tag 0x03: BLS with Version (CRITICAL!)

This is a **nested encoding** with the following structure:

```
[0x03]              // Outer tag: BLS with version
[0x03]              // Inner PKH tag (curve type within Public_key_hash.encoding)
[20 bytes]          // PKH bytes
[1 byte]            // Version (0, 1, 2, or 3)
```

**Total: 23 bytes for BLS PKH**

**OCaml Source:**
```ocaml
case (Tag 3) ~title:"Bls"
  (obj2
    (req "pkh" Tezos_crypto.Signature.Public_key_hash.encoding)
    (req "version" version_encoding))
```

**Example:**
```
03              // Tag 3: BLS with version
03              // Inner tag for BLS curve type
b0 8f 04 00 ... // 20 bytes PKH
02              // Version 2
```

**Version Encoding:**
```rust
0x00 - Version_0
0x01 - Version_1
0x02 - Version_2
0x03 - Version_3 (observed in practice)
```

## Response Types

### Response Structure

**Important:** Responses start with Result::Ok tag (0x00) but do NOT have a response type tag. The client knows what type to expect based on its request.

### 1. Signature Response (for Sign request)

**Structure:**
```
[0x00]      // Result::Ok
[96 bytes]  // BLS signature bytes
```

**Total: 97 bytes**

### 2. PublicKey Response

**Structure:**
```
[0x00]      // Result::Ok
[48 bytes]  // BLS public key bytes
```

### 3. AuthorizedKeys Response

**Structure (No Authentication):**
```
[0x00]  // Result::Ok
[0x00]  // Union tag 0: No_authentication
```

**Total: 2 bytes**

**Structure (With Authentication):**
```
[0x00]          // Result::Ok
[0x01]          // Union tag 1: Authorized_keys
[list encoding] // List of PKH (4-byte length + PKHs)
```

**OCaml Source:**
```ocaml
module Response = struct
  type t =
    | No_authentication
    | Authorized_keys of Public_key_hash.t list

  let encoding = union [
    case (Tag 0) (constant "no_authentication_required") ...
    case (Tag 1) (list Public_key_hash.encoding) ...
  ]
end
```

### 4. Error Response

**Structure:**
```
[0x01]              // Result::Error tag
[4-byte length]     // Error message length
[error message]     // UTF-8 error string
```

## Optional Field Encoding

### Standard Option (when NOT at end of object)

```
[0x00]  // None
```

**OR**

```
[0xFF]  // Some
[value] // The value
```

### Optional Fields at End of Object

**CRITICAL:** When an optional field is at the END of an object (like signature in Sign request), it is **omitted entirely** when None. There is NO tag byte.

**Detection:** EOF (end of message) = None

**Implementation:**
```rust
fn decode_option_signature<R: Read>(cursor: &mut R) -> Result<Option<Signature>> {
    match read_u8(cursor) {
        Ok(0xFF) => Ok(Some(decode_signature(cursor)?)),
        Ok(0x00) => Ok(None),
        Err(e) if e.kind() == UnexpectedEof => Ok(None), // EOF = None!
        Err(e) => Err(e),
        Ok(tag) => Err(InvalidFormat(tag)),
    }
}
```

## Connection Handling

### Connection Lifecycle

1. **Baker connects** to signer
2. **Multiple requests** on same connection:
   - AuthorizedKeys request → response
   - Sign request → response
   - (connection may stay open for more requests)
3. **Client closes** connection when done

### Important Notes

- Connections can be **persistent** (multiple request/response pairs)
- Or **ephemeral** (one request/response, then close)
- Server must handle **both patterns**
- Each request/response is **independent** (no state between them except high watermark)

## BLS Cryptography Details

### Curve and Scheme

- **Curve:** BLS12-381
- **Variant:** MinPk (minimize public key size)
- **Scheme:** PoP (Proof of Possession)

### Ciphersuite

**CRITICAL:** Must use the correct DST (Domain Separation Tag):

```rust
const POP_CIPHERSUITE_ID: &[u8] =
    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
```

**OCaml Source:**
```ocaml
Bls12_381_signature.MinPk.Pop.sign sk msg
```

### Key Sizes

```rust
Secret Key:  32 bytes
Public Key:  48 bytes
Signature:   96 bytes
PKH:         20 bytes (Blake2b hash)
```

### Secret Key Encoding

**CRITICAL:** BLS12-381 secret keys are **little-endian scalars**, but must be **reversed to big-endian** for BLST library:

```rust
// Read as little-endian from Tezos
let mut reversed_bytes = bytes.to_vec();
reversed_bytes.reverse();  // Convert to big-endian for BLST

let sk = blst::min_pk::SecretKey::from_bytes(&reversed_bytes)?;
```

### Out-of-Range Keys

Keys exceeding the curve order must be reduced modulo the curve order:

```rust
const CURVE_ORDER: &str =
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

// Read as LE, reduce mod r, write as BE
let key_int = BigUint::from_bytes_le(bytes);
let reduced = key_int % curve_order;
let sk_bytes = reduced.to_bytes_be();
```

### Signature Encoding

Signatures use **compressed G2 point encoding**:

```rust
let sig_bytes = signature.to_bytes();  // 96 bytes, compressed
```

## Magic Bytes (Watermarks)

Operations to be signed are prefixed with magic bytes:

```rust
0x01 - Block (pre-Ithaca)
0x02 - Endorsement (pre-Ithaca)
0x11 - Block (post-Ithaca)
0x12 - Preattestation
0x13 - Attestation
```

**Example data to sign (preattestation):**
```
12              // Magic byte
5c 3b a7 70     // Chain ID (4 bytes)
...             // Block hash, level, round, etc.
```

## Complete Examples

### Example 1: AuthorizedKeys Request/Response

**Request (1 byte):**
```
[00 01]  // Length: 1
[02]     // AuthorizedKeys tag
```

**Response (2 bytes):**
```
[00 02]  // Length: 2
[00]     // Result::Ok
[00]     // Union tag 0: No_authentication
```

### Example 2: Sign Request/Response

**Request (106 bytes):**
```
[00 6a]                              // Length: 106
[00]                                 // Sign tag
[03 03 b0 8f ... (20 bytes) 02]     // BLS PKH (23 bytes)
[00 00 00 4e]                        // Data length: 78
[12 5c 3b ... (78 bytes)]           // Data
                                     // No signature (EOF)
```

**Response (97 bytes):**
```
[00 61]                              // Length: 97
[00]                                 // Result::Ok
[8e e6 d4 ... (96 bytes)]           // Signature
```

### Example 3: Decoding BLS PKH

**Bytes:**
```
03 03 b0 8f 04 00 24 ca 09 8a aa 8e 24 53 e5 f5 9c 6a c6 57 a0 f7 02
```

**Decoding:**
```
03              → Outer tag: BLS with version
03              → Inner tag: BLS curve type
b0 8f ... a0 f7 → 20 bytes PKH
02              → Version 2
```

**Base58Check encoding:** `tz4R6oqYMfRxvjD7AkQiRKuttsBiMiDJ3vRP`

## Error Cases and Edge Cases

### 1. Message Too Large
- Maximum: 65,535 bytes (uint16 limit)
- Server should reject larger messages

### 2. Invalid Tags
- Unknown request tag → Error response
- Unknown union tag → Decoding error

### 3. Truncated Messages
- If length header says N bytes but fewer available → EOF error
- Except for optional fields at end → EOF = None

### 4. High Watermark Violations
- Server tracks last signed level/round per chain
- Reject signing at lower level → Watermark error

### 5. Invalid Magic Bytes
- Server can be configured to only allow specific magic bytes
- Unknown magic byte → Magic byte error

## Implementation Checklist

### Server Implementation

- [ ] Use **2-byte length prefix** (not 4!)
- [ ] Handle **persistent connections** (loop for multiple requests)
- [ ] Wrap responses in **Result::Ok** (0x00)
- [ ] **Do NOT** add response type tag
- [ ] Handle **EOF as None** for optional signature
- [ ] Decode **nested BLS PKH** (3 levels: outer tag, inner tag, version)
- [ ] Use **correct BLS ciphersuite** (Pop with DST)
- [ ] **Reverse secret key bytes** (LE to BE)
- [ ] Handle **out-of-range keys** (modular reduction)
- [ ] Return **No_authentication** (tag 0x00) when auth disabled

### Client Implementation

- [ ] Send **2-byte length prefix**
- [ ] Include **request type tag**
- [ ] Encode **BLS PKH correctly** (3 levels)
- [ ] **Omit optional signature** entirely when None (no tag)
- [ ] Expect **Result wrapper** on responses
- [ ] **No response type tag** (client knows expected type)
- [ ] Handle **persistent connections** or close after each request

## Common Pitfalls

1. ❌ **Using 4-byte length prefix** → Use 2 bytes!
2. ❌ **Adding response type tag** → Don't! Only Result::Ok/Error tag
3. ❌ **Writing 0x00 for None signature** → Omit entirely (EOF)
4. ❌ **Missing nested BLS encoding** → 3 levels: tag, inner tag, version
5. ❌ **Wrong BLS ciphersuite** → Must use Pop with correct DST
6. ❌ **Not reversing secret key bytes** → LE to BE conversion required
7. ❌ **Closing connection too early** → Support multiple requests
8. ❌ **Returning key list for AuthorizedKeys** → Return No_authentication (0x00)

## Testing

### Test Vector 1: BLS Key Derivation

**Secret Key (base58):**
```
BLsk2snGqdSb7qBDhKbc62AxbZXJycDvA5QmeYYhB7Nb3wFuMMbq9x
```

**Expected Public Key:**
```
BLpk1pn59Bwwi9K5VjubG4jphCVhdqWfji8GkV8eBXJCEYNMqE6s5LHv5W13zWtMey6Qipg5yCUD
```

**Expected PKH:**
```
tz4QZtotXaZibHhGUUELAedaoHr8sPMw72fW
```

### Test Vector 2: Out-of-Range Key

**Secret Key (base58):**
```
BLsk2L4dMse5ac4V9RhPHwZmDp1nbK2mzsfjtGURyMtnZnVrr89uZQ
```

**Note:** This key exceeds curve order and requires modular reduction.

**Expected PKH:**
```
tz4R6oqYMfRxvjD7AkQiRKuttsBiMiDJ3vRP
```

## References

- **BLS IETF Draft:** https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature
- **BLST Library:** https://github.com/supranational/blst
- **Tezos Source:** https://gitlab.com/tezos/tezos
- **Base58Check:** Tezos-specific encoding with prefixes

## License

This specification is derived from the Tezos open-source codebase (MIT License).

## Message Size Analysis

This section provides a practical breakdown of the total size of common requests on the wire.

### Attestation Request Size

Attestation signing requests have a fixed and predictable size. The example below is for a non-BLS key, which is the largest variant.

| Part | Size (Bytes) | Description |
| :--- | :--- | :--- |
| **Length Prefix** | **2** | A `u16` value indicating the payload length (76 bytes). |
| | | **--- Payload Starts ---** |
| Request Tag | 1 | `0x00` to indicate a `Sign` request. |
| PKH Encoding | 24 | The public key hash (`pkh`) of the key to sign with. |
| Data Length | 4 | A `u32` value indicating the signed data length (48 bytes). |
| Data to Sign | 48 | The actual attestation payload (magic byte, etc.). |
| Auth Signature | 0 | Optional field, absent in standard baking requests. |
| **Total Payload** | **76** | (1 + 24 + 4 + 48) |
| **Total on Wire** | **78** | (2-byte prefix + 76-byte payload) |

### Block Signing Request Size

Block signing requests have a variable size because the block header format contains a variable-length `fitness` field.

| Part | Size (Bytes) | Description |
| :--- | :--- | :--- |
| **Length Prefix** | **2** | A `u16` value indicating the payload length. |
| | | **--- Payload Starts ---** |
| Request Tag | 1 | `0x00` to indicate a `Sign` request. |
| PKH Encoding | 24 | The public key hash (`pkh`) of the key to sign with. |
| Data Length | 4 | A `u32` value indicating the block header's length. |
| Data to Sign | **Variable** | The block header. Typically 100-200 bytes, but can be up to 32KB. |
| Auth Signature | 0 | Optional field, absent in standard baking requests. |
| **Total Payload** | **Variable** | (29 bytes of metadata + variable block header size) |
| **Total on Wire** | **Variable** | (2-byte prefix + Total Payload) |

This variability in the block signing request is the primary motivation for enforcing a maximum size limit (e.g., 64KB) in the protocol parser to prevent memory exhaustion attacks.
