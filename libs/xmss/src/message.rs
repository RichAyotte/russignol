//! Message derivation for XMSS signing.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// Length of the digest XMSS signs.
pub const MESSAGE_LEN: usize = 32;

/// Hash `watermark || payload` to the fixed-width input XMSS signs.
///
/// Unkeyed BLAKE2b-256, matching Octez's `Xmss.hash_message`
/// (`src/lib_crypto/xmss.ml:327-329`), which calls the module-level `Blake2B`
/// — `Blake2b.direct` with an empty key and a 32-byte digest. A verifier that
/// derives a different digest rejects every signature, so this construction is
/// interop-critical and is pinned by a test vector.
#[must_use]
pub fn hash_message(watermark: Option<&[u8]>, payload: &[u8]) -> [u8; MESSAGE_LEN] {
    let mut hasher = Blake2b::<U32>::new();
    if let Some(prefix) = watermark {
        hasher.update(prefix);
    }
    hasher.update(payload);
    hasher.finalize().into()
}
