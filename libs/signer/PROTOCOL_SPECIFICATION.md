# Tezos Remote Signer TCP Protocol Specification

**Reverse-engineered from OCaml implementation**
**Source:** `src/lib_base/unix/socket.ml`, `src/lib_signer_services/signer_messages.ml`

## Overview

The Tezos remote signer uses a binary protocol over TCP sockets for communication between the baker/client and signer. This document provides the complete protocol specification based on the actual OCaml implementation.

## Message Framing

### Length Prefix
- **Size:** 2 bytes (uint16, big-endian) — not 4 bytes
- **Maximum message size:** 65,535 bytes

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
[error trace]  // See "Error Response" below — NOT a raw string
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
[versioned PKH]  // See PKH Encoding section (23 bytes for BLS)
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
[raw PKH]  // 21 bytes — no version byte (see PKH Encoding section)
```

### 3. AuthorizedKeys Request (Tag 0x02)

**Structure:**
```
[0x02]  // AuthorizedKeys tag only
```

**Note:** This is the simplest request - just one byte!

### 4. DeterministicNonce (Tag 0x03) and DeterministicNonceHash (Tag 0x04)

Same layout as the Sign request:
```
[tag]  // 0x03 or 0x04
[versioned PKH]
[data length: 4 bytes big-endian]
[data bytes]
[optional signature]  // Omitted entirely if None (EOF = None)
```

### 5. SupportsDeterministicNonces Request (Tag 0x05)

**Structure:**
```
[0x05]  // SupportsDeterministicNonces tag
[raw PKH]  // 21 bytes
```

### 6. KnownKeys Request (Tag 0x06)

**Structure:**
```
[0x06]  // KnownKeys tag only
```

### 7. BlsProveRequest (Tag 0x07)

**Structure:**
```
[0x07]  // BlsProveRequest tag
[raw PKH]  // 21 bytes
[optional public key]  // Standard option encoding (NOT trailing-omitted)
```

The optional public key uses the standard option encoding: `0x00` = None, or `0xFF` followed by the public key encoding (`[0x03][48 bytes]` = 49 bytes, so 50 bytes total for Some).

## Public Key Hash (PKH) Encoding

Two distinct PKH encodings are used, depending on the request type.

### Raw PKH (21 bytes)

Used by PublicKey (0x01), SupportsDeterministicNonces (0x05), and BlsProveRequest (0x07). A tagged union with **no version byte**:

```rust
0x00 - Ed25519 PKH (20 bytes)
0x01 - Secp256k1 PKH (20 bytes)
0x02 - P256 PKH (20 bytes)
0x03 - BLS PKH (20 bytes)
```

```
[tag][20 bytes]  // 21 bytes total
```

This implementation accepts only tag 0x03 (BLS) and returns a decoding error for tags 0x00–0x02.

### Versioned PKH

Used by Sign (0x00), DeterministicNonce (0x03), and DeterministicNonceHash (0x04). A union where **only the BLS case carries a version byte**:

```rust
0x00 - Ed25519 PKH (20 bytes)              // 21 bytes total
0x01 - Secp256k1 PKH (20 bytes)            // 21 bytes total
0x02 - P256 PKH (20 bytes)                 // 21 bytes total
0x03 - BLS: nested raw PKH + version byte  // 23 bytes total
```

#### Tag 0x03: BLS with Version (CRITICAL!)

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

### 1. Signature Response (for Sign and BlsProveRequest)

**Structure:**
```
[0x00]      // Result::Ok
[96 bytes]  // BLS signature bytes
```

**Payload: 97 bytes (99 bytes on wire with the length prefix)**

### 2. PublicKey Response

**Structure:**
```
[0x00]      // Result::Ok
[0x03]      // Public key union tag (BLS)
[48 bytes]  // BLS public key bytes
```

**Payload: 50 bytes (52 bytes on wire).** Note: unlike the signature, the public key encoding is a tagged union, so the payload includes the `0x03` tag before the 48 key bytes.

### 3. AuthorizedKeys Response

**Structure (No Authentication):**
```
[0x00]  // Result::Ok
[0x00]  // Union tag 0: No_authentication
```

**Payload: 2 bytes (4 bytes on wire)**

**Structure (With Authentication):**
```
[0x00]          // Result::Ok
[0x01]          // Union tag 1: Authorized_keys
[list encoding] // 4-byte big-endian TOTAL BYTE LENGTH of the list,
                // followed by raw PKHs (21 bytes each)
```

The list length prefix is the total byte size of the list contents (`N × 21`), not the item count.

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

### 4. Nonce and NonceHash Responses

**Structure (for DeterministicNonce and DeterministicNonceHash):**
```
[0x00]      // Result::Ok
[32 bytes]  // Raw nonce (or nonce hash) bytes, no length prefix
```

### 5. Bool Response (for SupportsDeterministicNonces)

**Structure:**
```
[0x00]  // Result::Ok
[0xFF]  // true
```
or
```
[0x00]  // Result::Ok
[0x00]  // false
```

### 6. KnownKeys Response

**Structure:**
```
[0x00]           // Result::Ok
[4 bytes BE]     // Total byte length of the list (N × 21)
[N × 21 bytes]   // Raw PKHs ([0x03][20 bytes] each)
```

### 7. Error Response

**Structure:**
```
[0x01]              // Result::Error tag
[4 bytes BE]        // Total byte length of the error trace
[4 bytes BE]        // Byte length of the first trace item
[BSON document]     // {"kind": "generic", "error": "<message>"}
```

Errors are encoded as a Data_encoding error **trace**: a list (4-byte total byte length) of items, where each item is a 4-byte length followed by a BSON-serialized JSON error object. The trace total length equals the item length + 4 (for the item's own length prefix). This implementation emits a single "generic" error item, which octez-client accepts.

**The error message is NOT a raw UTF-8 string** — decoders must parse the trace framing and the BSON document to extract the `error` field.

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

Used by the BlsProveRequest override public key.

### Optional Fields at End of Object

**CRITICAL:** When an optional field is at the END of an object (like signature in Sign request), it is **omitted entirely** when None. There is NO tag byte.

**Detection:** EOF (end of message) = None

Because the field is omitted when None, a `0x00` tag byte is **invalid** in this position — only `0xFF` (Some) or EOF (None) are accepted:

```rust
fn decode_option_signature<R: Read>(cursor: &mut R) -> Result<Option<Signature>> {
    match read_u8(cursor) {
        Ok(0xFF) => Ok(Some(decode_signature(cursor)?)),
        Err(e) if e.kind() == UnexpectedEof => Ok(None), // EOF = None!
        Ok(tag) => Err(InvalidFormat(tag)),              // includes 0x00
        Err(e) => Err(e),
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

### Ciphersuites

**CRITICAL:** Two distinct DSTs (Domain Separation Tags) are used.

Regular signatures (`sign`/`verify`):

```rust
const SIG_DST: &[u8] =
    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
```

Proof of possession (`pop_prove`/`pop_verify`):

```rust
const POP_DST: &[u8] =
    b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
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

Keys whose **little-endian value** is >= the curve order are rejected, matching octez (`Bls12_381_signature.sk_of_bytes_exn` raises):

```text
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Note: because keys are little-endian, the most significant byte is the *last* stored byte — a key file beginning `0xb5...` is not necessarily out of range.

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

**Response (2-byte payload):**
```
[00 02]  // Length: 2
[00]     // Result::Ok
[00]     // Union tag 0: No_authentication
```

### Example 2: Sign Request/Response

**Request (106-byte payload):**
```
[00 6a]                              // Length: 106
[00]                                 // Sign tag
[03 03 b0 8f ... (20 bytes) 02]     // BLS PKH (23 bytes)
[00 00 00 4e]                        // Data length: 78
[12 5c 3b ... (78 bytes)]           // Data
                                     // No signature (EOF)
```

**Response (97-byte payload):**
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
- The server tracks the last signed level/round **per key and per operation type** (block, preattestation, attestation); chain ID is not part of the watermark state
- Signing below the current level → Watermark error
- Signing at the current level with a round <= the current round → Watermark error (the round must be strictly higher at the same level)
- Signing with no existing watermark entry → Watermark error (watermarks must be initialized before the first signature)
- A corrupt watermark file prevents the signer from loading

### 5. Invalid Magic Bytes
- Server can be configured to only allow specific magic bytes
- Unknown magic byte → Magic byte error

## Implementation Checklist

### Server Implementation

- [ ] Use **2-byte length prefix** (not 4!)
- [ ] Handle **persistent connections** (loop for multiple requests)
- [ ] Wrap responses in **Result::Ok** (0x00)
- [ ] **Do NOT** add response type tag
- [ ] Include the **union tag (0x03)** in PublicKey responses
- [ ] Encode errors as a **trace of BSON items**, not a raw string
- [ ] Handle **EOF as None** for optional signature
- [ ] Decode **nested BLS PKH** (3 levels: outer tag, inner tag, version)
- [ ] Use **correct BLS ciphersuites** (distinct DSTs for sign and PoP)
- [ ] **Reverse secret key bytes** (LE to BE)
- [ ] Reject **out-of-range keys** (little-endian value >= curve order, as octez does)
- [ ] Return **No_authentication** (tag 0x00) when auth disabled

### Client Implementation

- [ ] Send **2-byte length prefix**
- [ ] Include **request type tag**
- [ ] Encode **BLS PKH correctly** (versioned for Sign/nonce requests, raw for the rest)
- [ ] **Omit optional signature** entirely when None (no tag)
- [ ] Expect **Result wrapper** on responses
- [ ] **No response type tag** (client knows expected type)
- [ ] Handle **persistent connections** or close after each request

## Common Pitfalls

1. ❌ **Using 4-byte length prefix** → Use 2 bytes!
2. ❌ **Adding response type tag** → Don't! Only Result::Ok/Error tag
3. ❌ **Writing 0x00 for None signature** → Omit entirely (EOF)
4. ❌ **Missing nested BLS encoding** → 3 levels: tag, inner tag, version
5. ❌ **Using the versioned PKH everywhere** → PublicKey/SupportsDeterministicNonces/BlsProveRequest use the 21-byte raw PKH
6. ❌ **Treating the error payload as a UTF-8 string** → It is a trace of BSON items
7. ❌ **Wrong BLS ciphersuite** → Distinct DSTs for signing and proof of possession
8. ❌ **Not reversing secret key bytes** → LE to BE conversion required
9. ❌ **Closing connection too early** → Support multiple requests
10. ❌ **Returning key list for AuthorizedKeys** → Return No_authentication (0x00)

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

**Note:** The stored key bytes begin `0xb5...`, which exceeds the first byte of the curve order (`0x73...`) if misread as big-endian. Secret keys are little-endian, so the actual scalar value is in range — an implementation that skips the byte reversal will derive the wrong public key.

### Test Vector 2: BLS Key Derivation

**Secret Key (base58):**
```
BLsk2L4dMse5ac4V9RhPHwZmDp1nbK2mzsfjtGURyMtnZnVrr89uZQ
```

**Expected Public Key:**
```
BLpk1xn1JkUyo2edVE9RAFgC6MEDRSKEzddXLBy1zzczX52TTuxJ2NcsPZTRhP6EidWayhYbcAMr
```

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

Attestation and preattestation signing requests are fixed-size. The signed payload is: magic byte (1) + chain ID (4) + branch (32) + kind (1) + slot (2, non-BLS keys only) + level (4) + round (4) + block payload hash (32) — **78 bytes for BLS (tz4) keys, 80 bytes otherwise**.

| Part | BLS key (tz4) | Non-BLS key | Description |
| :--- | :--- | :--- | :--- |
| **Length Prefix** | **2** | **2** | A `u16` value indicating the payload length. |
| | | | **--- Payload Starts ---** |
| Request Tag | 1 | 1 | `0x00` to indicate a `Sign` request. |
| PKH Encoding | 23 | 21 | Versioned PKH; only the BLS case carries a version byte. |
| Data Length | 4 | 4 | A `u32` value indicating the signed data length. |
| Data to Sign | 78 | 80 | The attestation payload (magic byte, etc.). |
| Auth Signature | 0 | 0 | Trailing optional field, omitted in standard baking requests. |
| **Total Payload** | **106** | **106** | |
| **Total on Wire** | **108** | **108** | |

Both key families yield the same totals: the BLS PKH is 2 bytes longer, and the BLS attestation payload is 2 bytes shorter (no slot field).

### Block Signing Request Size

Block signing requests have a variable size because the block header format contains a variable-length `fitness` field.

| Part | Size (Bytes) | Description |
| :--- | :--- | :--- |
| **Length Prefix** | **2** | A `u16` value indicating the payload length. |
| | | **--- Payload Starts ---** |
| Request Tag | 1 | `0x00` to indicate a `Sign` request. |
| PKH Encoding | 23 | The versioned BLS PKH (21 for non-BLS keys). |
| Data Length | 4 | A `u32` value indicating the block header's length. |
| Data to Sign | **Variable** | The block header. Typically 100-200 bytes, but can be up to 32KB. |
| Auth Signature | 0 | Trailing optional field, absent in standard baking requests. |
| **Total Payload** | **Variable** | (28 bytes of metadata + variable block header size) |
| **Total on Wire** | **Variable** | (2-byte prefix + Total Payload) |

This variability in the block signing request is the primary motivation for enforcing a maximum size limit (e.g. 64KB) in the protocol parser to prevent memory exhaustion attacks.
