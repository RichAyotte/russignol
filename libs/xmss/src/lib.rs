//! XMSS (tz6) signing for Tezos, over the vendored leanVM-b `xmss` crate.
//!
//! XMSS is stateful: every epoch is a one-time key, and signing two different
//! messages at one epoch discloses the secret key rather than costing a
//! deposit. This crate deliberately does not track which epochs are spent —
//! the caller supplies the epoch and owns that state, so there is exactly one
//! place in the system that can get it wrong.

pub mod framing;
pub mod message;

use std::ops::RangeInclusive;

use blake2::digest::consts::U20;
use blake2::{Blake2b, Digest as _};
use zeroize::Zeroizing;

pub use framing::SIGNATURE_SIZE;
pub use message::{MESSAGE_LEN, hash_message};
pub use xmss::{Epoch, PUB_KEY_SIZE};

/// Width of a tz6 public key hash, matching Octez's `Xmss.Public_key_hash`
/// (`src/lib_crypto/xmss.ml:22`, `size = Some 20`).
pub const PUBLIC_KEY_HASH_SIZE: usize = 20;

pub const SEED_SIZE: usize = 32;

/// A distance in epochs, distinct from the [`Epoch`] it is measured from
/// because [`SecretKey::epoch_to_warm`] takes both: one integer type for the
/// two leaves a transposition that still type-checks and names a subtree no
/// caller meant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lookahead(pub Epoch);

/// The `bincode` configuration every byte encoding in this crate goes through.
///
/// Fixed-width integers, which is what makes `xmss::SIG_SIZE` exact where
/// `bincode::options()` would default to varint; and trailing bytes refused, so
/// a blob longer than the value it encodes does not decode as that value.
pub(crate) fn encoding() -> impl bincode::Options {
    use bincode::Options as _;

    bincode::options()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The requested range starts past its end.
    InvalidRange { start: Epoch, end: Epoch },
    /// The epoch is outside the key's usable range.
    EpochOutOfRange {
        epoch: Epoch,
        start: Epoch,
        end: Epoch,
    },
    /// Signature bytes were not [`SIGNATURE_SIZE`] long.
    MalformedSignature { len: usize },
    /// Public key bytes were not [`PUB_KEY_SIZE`] long.
    MalformedPublicKey { len: usize },
    /// Public key hash bytes were not [`PUBLIC_KEY_HASH_SIZE`] long.
    MalformedPublicKeyHash { len: usize },
    /// Secret key bytes did not decode.
    MalformedSecretKey,
    /// The signature does not attest this message under this key.
    VerificationFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRange { start, end } => {
                write!(f, "epoch range {start}..={end} starts past its end")
            }
            Self::EpochOutOfRange { epoch, start, end } => {
                write!(
                    f,
                    "epoch {epoch} is outside the key's range {start}..={end}"
                )
            }
            Self::MalformedSignature { len } => {
                write!(f, "signature is {len} bytes, expected {SIGNATURE_SIZE}")
            }
            Self::MalformedPublicKey { len } => {
                write!(f, "public key is {len} bytes, expected {PUB_KEY_SIZE}")
            }
            Self::MalformedPublicKeyHash { len } => {
                write!(
                    f,
                    "public key hash is {len} bytes, expected {PUBLIC_KEY_HASH_SIZE}"
                )
            }
            Self::MalformedSecretKey => write!(f, "secret key did not decode"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for Error {}

/// An XMSS secret key: the seed, its epoch range, and the upper Merkle tree.
///
/// Not `Clone`: a second live copy is a second thing that can sign, and the
/// scheme's safety rests on one holder advancing one epoch counter.
#[derive(Debug)]
pub struct SecretKey(xmss::XmssSecretKey);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(xmss::XmssPublicKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKeyHash([u8; PUBLIC_KEY_HASH_SIZE]);

/// A signature together with the epoch it was produced at.
///
/// The two travel as one value because verification needs both and leanVM-b's
/// signature does not carry the epoch itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    epoch: Epoch,
    inner: xmss::XmssSignature,
}

/// Runs XMSS key generation's worker pool in the operating system's background
/// scheduling class.
///
/// Generation is the only work here that fans out across cores; signing and the
/// bottom-subtree rebuild are single-threaded. So lowering the pool cannot slow a
/// signature, while leaving it at the default class puts one CPU-bound thread per
/// core against the single thread a signature runs on. Only a call before the
/// first generation has any effect.
///
/// The thread calling [`SecretKey::generate`] keeps its own class and takes one
/// core's share of the work, the pool declining to strand a thread it borrowed
/// in a class Linux gives an unprivileged caller no way out of.
pub fn deprioritize_key_generation() {
    parallel::set_worker_qos(parallel::Qos::Utility);
}
impl SecretKey {
    /// Generate a key usable for every epoch in `start..=end`.
    ///
    /// Cost is proportional to the width of the range: upstream builds every
    /// in-range leaf.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRange`] if `start` is past `end`.
    pub fn generate(
        seed: [u8; SEED_SIZE],
        start: Epoch,
        end: Epoch,
    ) -> Result<(Self, PublicKey), Error> {
        let (secret, public) = xmss::key_gen_from_seed(seed, start, end)
            .map_err(|_| Error::InvalidRange { start, end })?;
        Ok((Self(secret), PublicKey(public)))
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    #[must_use]
    pub fn epoch_range(&self) -> RangeInclusive<Epoch> {
        self.0.epoch_range()
    }

    /// Epochs one bottom subtree covers, which is the distance between the
    /// rebuilds a signature pays for.
    #[must_use]
    pub fn subtree_width(&self) -> Epoch {
        self.0.subtree_width()
    }

    /// Build the bottom subtree covering `epoch`, so a signature at it pays no
    /// rebuild on the signing path.
    ///
    /// # Errors
    ///
    /// [`Error::EpochOutOfRange`] if `epoch` is not in [`Self::epoch_range`].
    pub fn warm(&self, epoch: Epoch) -> Result<(), Error> {
        self.0.prepare(epoch).map_err(|_| {
            let range = self.epoch_range();
            Error::EpochOutOfRange {
                epoch,
                start: *range.start(),
                end: *range.end(),
            }
        })
    }

    /// The epoch `lookahead` from `next` reaches, where that lands in a
    /// different subtree from the one covering `next`.
    ///
    /// `None` where it lands in the same subtree, and `None` outside the range.
    /// What the key already holds is not read here: a caller needing the subtree
    /// covering `next` itself asks [`Self::warm`] for it, which after a load is
    /// every caller — the cache does not survive serialization.
    #[must_use]
    pub fn epoch_to_warm(&self, next: Epoch, lookahead: Lookahead) -> Option<Epoch> {
        let range = self.epoch_range();
        if !range.contains(&next) {
            return None;
        }
        let width = self.subtree_width();
        let target = next.saturating_add(lookahead.0).min(*range.end());
        (target / width != next / width).then_some(target)
    }

    /// Sign `payload` at `epoch`.
    ///
    /// # Errors
    ///
    /// [`Error::EpochOutOfRange`] if `epoch` is not in [`Self::epoch_range`].
    pub fn sign(
        &self,
        epoch: Epoch,
        watermark: Option<&[u8]>,
        payload: &[u8],
    ) -> Result<Signature, Error> {
        let digest = hash_message(watermark, payload);
        let inner = xmss::sign(&mut rand::rng(), &self.0, &digest, epoch).map_err(|_| {
            let range = self.epoch_range();
            Error::EpochOutOfRange {
                epoch,
                start: *range.start(),
                end: *range.end(),
            }
        })?;
        Ok(Signature { epoch, inner })
    }

    /// Serialize seed, range and upper tree.
    ///
    /// Goes through upstream's `serde` implementation because the fields are
    /// crate-private there, so no hand-rolled encoding can reach them. The
    /// bottom-subtree cache is `#[serde(skip)]` upstream and is rebuilt on
    /// first use after a reload.
    ///
    /// # Panics
    ///
    /// If the key does not serialize, which for a struct of owned digests
    /// means allocation failed.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        use bincode::Options as _;

        Zeroizing::new(
            encoding()
                .serialize(&self.0)
                .expect("XmssSecretKey serializes"),
        )
    }

    /// # Errors
    ///
    /// [`Error::MalformedSecretKey`] if `bytes` is not exactly a serialized key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        use bincode::Options as _;

        encoding()
            .deserialize(bytes)
            .map(Self)
            .map_err(|_| Error::MalformedSecretKey)
    }
}

impl PublicKey {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUB_KEY_SIZE] {
        self.0.flatten()
    }

    /// # Errors
    ///
    /// [`Error::MalformedPublicKey`] if `bytes` is not [`PUB_KEY_SIZE`] long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; PUB_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| Error::MalformedPublicKey { len: bytes.len() })?;
        Ok(Self(xmss::XmssPublicKey {
            merkle_root: std::array::from_fn(|i| bytes[i]),
            public_param: std::array::from_fn(|i| bytes[xmss::DIGEST_LEN + i]),
        }))
    }

    /// The tz6 hash: BLAKE2b-160 over the public key bytes, matching Octez's
    /// `Xmss.Public_key.hash`.
    #[must_use]
    pub fn hash(&self) -> PublicKeyHash {
        let mut hasher = Blake2b::<U20>::new();
        hasher.update(self.to_bytes());
        PublicKeyHash(hasher.finalize().into())
    }

    /// Verify `signature` against `payload` at the epoch the signature carries.
    ///
    /// The epoch is taken from the signature rather than from the caller, so a
    /// verifier cannot be steered to a different one than the signer used.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`] if the signature does not attest this
    /// message under this key at that epoch.
    pub fn verify(
        &self,
        signature: &Signature,
        watermark: Option<&[u8]>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let digest = hash_message(watermark, payload);
        xmss::verify(&self.0, &digest, &signature.inner, signature.epoch)
            .map_err(|_| Error::VerificationFailed)
    }
}

impl PublicKeyHash {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_HASH_SIZE] {
        &self.0
    }

    /// # Errors
    ///
    /// [`Error::MalformedPublicKeyHash`] if `bytes` is not
    /// [`PUBLIC_KEY_HASH_SIZE`] long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| Error::MalformedPublicKeyHash { len: bytes.len() })
    }
}

impl Signature {
    /// The epoch this signature was produced at, as carried in its bytes.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        framing::encode(self.epoch, &self.inner)
    }

    /// # Errors
    ///
    /// [`Error::MalformedSignature`] if `bytes` is not [`SIGNATURE_SIZE`] long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (epoch, inner) =
            framing::decode(bytes).ok_or(Error::MalformedSignature { len: bytes.len() })?;
        Ok(Self { epoch, inner })
    }
}
