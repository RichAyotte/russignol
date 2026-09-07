//! Base58 over the Bitcoin alphabet, which Tezos's base58check is built on.
//!
//! A conversion between base 58 and base 256 is quadratic in the value: every
//! limb produced so far is touched once per group of digits taken in. The
//! constant is what this module keeps small, by moving a group of digits at a
//! time over wide limbs where a byte-at-a-time conversion moves one digit over
//! 8-bit ones. An `xmsk` value at the deployed range is 179,491 characters,
//! and the difference is the load of a tz6 key at unlock taking seconds
//! rather than minutes.

use std::fmt;

use zeroize::Zeroizing;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The digit each ASCII byte stands for, [`NO_DIGIT`] outside the alphabet.
const DIGITS: [u8; 128] = digits();
const NO_DIGIT: u8 = u8::MAX;

const fn digits() -> [u8; 128] {
    let mut table = [NO_DIGIT; 128];
    let mut digit: u8 = 0;
    while (digit as usize) < ALPHABET.len() {
        table[ALPHABET[digit as usize] as usize] = digit;
        digit += 1;
    }
    table
}

/// Digits the decode takes in at once. 58^10 is the largest power of 58 under
/// 2^64, so a group's value and the multiplier that moves the limbs past it
/// both fit the limb the product is taken over.
const DECODE_GROUP: usize = 10;

/// Digits the encode gives out at once, as the divisor each pass over the
/// limbs takes out. 58^5 is the largest power of 58 under 2^32: the encode
/// divides where the decode multiplies, and a dividend wider than 64 bits is a
/// library call where a 128-bit product is two instructions, so its limbs are
/// 32 bits and its groups half the decode's.
const ENCODE_GROUP: usize = 5;
const ENCODE_RADIX: u64 = 58u64.pow(5);

/// A character outside the alphabet, at the byte offset it sits at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The byte at `index` is not one of the 58 characters.
    InvalidCharacter {
        /// Byte offset into the input.
        index: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter { index } => {
                write!(f, "invalid base58 character at byte {index}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Encode `bytes` as base58, a leading zero byte becoming a leading `1`.
///
/// # Panics
///
/// Cannot panic: each conversion is of a value its own arithmetic bounds, as
/// the message beside it says.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let significant = &bytes[zeros..];

    // Little-endian limbs off big-endian bytes, the first chunk from the end
    // carrying however many bytes are left over.
    let mut limbs: Zeroizing<Vec<u32>> = Zeroizing::new(
        significant
            .rchunks(4)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold(0u32, |limb, &b| (limb << 8) | u32::from(b))
            })
            .collect(),
    );

    // A byte is 8 bits and a digit log2(58) of them, 5.858, so the digits
    // number under 1.366 bytes; groups are five digits each.
    let mut groups: Zeroizing<Vec<u32>> = Zeroizing::new(Vec::with_capacity(
        significant.len() * 1366 / (1000 * ENCODE_GROUP) + 1,
    ));
    let mut len = limbs.len();
    while len > 0 {
        let mut remainder: u64 = 0;
        for limb in limbs[..len].iter_mut().rev() {
            let dividend = (remainder << 32) | u64::from(*limb);
            *limb = u32::try_from(dividend / ENCODE_RADIX)
                .expect("a dividend under 2^32 times the radix divides to under 2^32");
            remainder = dividend % ENCODE_RADIX;
        }
        groups.push(u32::try_from(remainder).expect("a remainder is under the radix"));
        while len > 0 && limbs[len - 1] == 0 {
            len -= 1;
        }
    }

    let mut out = Vec::with_capacity(zeros + groups.len() * ENCODE_GROUP);
    out.resize(zeros, b'1');
    let mut leading = true;
    for group in groups.iter().rev() {
        let mut value = *group;
        let mut digits = [0u8; ENCODE_GROUP];
        for digit in digits.iter_mut().rev() {
            *digit = u8::try_from(value % 58).expect("a digit is under 58");
            value /= 58;
        }
        for digit in digits {
            if leading && digit == 0 {
                continue;
            }
            leading = false;
            out.push(ALPHABET[usize::from(digit)]);
        }
    }
    String::from_utf8(out).expect("every byte is from the alphabet")
}

/// Decode base58 text into the bytes it encodes.
///
/// # Errors
///
/// [`Error::InvalidCharacter`] at the first byte outside the alphabet.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    let input = s.as_bytes();
    let zeros = input.iter().take_while(|&&c| c == b'1').count();
    let significant = &input[zeros..];

    // Ten digits are under 64 bits, so the limbs never outnumber the groups.
    let mut limbs: Zeroizing<Vec<u64>> =
        Zeroizing::new(Vec::with_capacity(significant.len() / DECODE_GROUP + 1));
    for (offset, group) in significant.chunks(DECODE_GROUP).enumerate() {
        let mut value: u64 = 0;
        let mut radix: u64 = 1;
        for (i, &c) in group.iter().enumerate() {
            let digit = DIGITS
                .get(usize::from(c))
                .copied()
                .filter(|&d| d != NO_DIGIT)
                .ok_or(Error::InvalidCharacter {
                    index: zeros + offset * DECODE_GROUP + i,
                })?;
            value = value * 58 + u64::from(digit);
            radix *= 58;
        }

        let mut carry = u128::from(value);
        for limb in limbs.iter_mut() {
            let (low, high) = split(u128::from(*limb) * u128::from(radix) + carry);
            *limb = low;
            carry = u128::from(high);
        }
        if carry != 0 {
            let (low, _) = split(carry);
            limbs.push(low);
        }
    }

    let mut out = Vec::with_capacity(zeros + limbs.len() * 8);
    out.resize(zeros, 0);
    let mut leading = true;
    for limb in limbs.iter().rev() {
        for byte in limb.to_be_bytes() {
            if leading && byte == 0 {
                continue;
            }
            leading = false;
            out.push(byte);
        }
    }
    Ok(out)
}

/// The low and high 64 bits of a product, which never carries past 128:
/// a limb times a radix under 2^64 plus a carry under 2^64 is under 2^128.
fn split(wide: u128) -> (u64, u64) {
    let low = u64::try_from(wide & u128::from(u64::MAX)).expect("masked to 64 bits");
    let high = u64::try_from(wide >> 64).expect("shifted down by 64 bits");
    (low, high)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Values written out rather than derived, so both directions are checked
    /// against text this module had no hand in.
    const VECTORS: &[(&str, &[u8])] = &[
        ("", &[]),
        ("1", &[0]),
        ("111", &[0, 0, 0]),
        ("2", &[1]),
        ("z", &[57]),
        ("21", &[58]),
        ("1112", &[0, 0, 0, 1]),
        ("2NEpo7TZRRrLZSi2U", b"Hello World!"),
    ];

    /// Bytes that look like nothing in particular, at any length, from a seed:
    /// a linear congruential generator so a case names its input by one number.
    fn bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                u8::try_from(state >> 56).expect("eight bits")
            })
            .collect()
    }

    #[test]
    fn decodes_the_written_vectors() {
        for (text, expected) in VECTORS {
            assert_eq!(decode(text).as_deref(), Ok(*expected), "{text}");
        }
    }

    #[test]
    fn encodes_the_written_vectors() {
        for (text, bytes) in VECTORS {
            assert_eq!(encode(bytes), *text);
        }
    }

    /// Lengths from zero up past two ten-digit groups and two 64-bit limbs, so
    /// a short last group and a carry into a fresh limb are both drawn.
    #[test]
    fn agrees_with_bs58_at_every_length_across_the_group_and_limb_boundaries() {
        for len in 0..=40 {
            let input = bytes(u64::try_from(len).expect("small"), len);
            let text = bs58::encode(&input).into_string();
            assert_eq!(encode(&input), text, "encode of {len} bytes");
            assert_eq!(
                decode(&text).as_deref(),
                Ok(&input[..]),
                "decode of {len} bytes"
            );
        }
    }

    #[test]
    fn keeps_leading_zero_bytes_through_both_directions() {
        let input = [0, 0, 0, 1, 2, 3];
        let text = encode(&input);
        assert!(text.starts_with("111"), "{text}");
        assert!(!text.starts_with("1111"), "{text}");
        assert_eq!(decode(&text).as_deref(), Ok(&input[..]));
    }

    /// Thousands of limbs, which is the shape an `xmsk` value has.
    #[test]
    fn agrees_with_bs58_on_a_value_of_thousands_of_limbs() {
        let input = bytes(0x00C0_FFEE, 20_000);
        let text = bs58::encode(&input).into_string();
        assert_eq!(encode(&input), text);
        assert_eq!(decode(&text).as_deref(), Ok(&input[..]));
    }

    #[test]
    fn rejects_a_character_outside_the_alphabet_naming_its_offset() {
        for (text, index) in [("11O", 2), ("0", 0), ("aIb", 1), ("zl", 1), ("2 2", 1)] {
            assert_eq!(
                decode(text),
                Err(Error::InvalidCharacter { index }),
                "{text:?}"
            );
        }
    }

    /// A multibyte character is refused at the offset of its first byte, the
    /// index being a byte offset the caller can slice the input at.
    #[test]
    fn rejects_a_non_ascii_character_at_its_first_byte() {
        assert_eq!(
            decode("ab\u{e9}c"),
            Err(Error::InvalidCharacter { index: 2 })
        );
    }

    proptest! {
        #[test]
        fn round_trips_any_bytes(input in proptest::collection::vec(any::<u8>(), 0..2048)) {
            prop_assert_eq!(decode(&encode(&input)), Ok(input));
        }

        #[test]
        fn matches_bs58_on_any_bytes(input in proptest::collection::vec(any::<u8>(), 0..512)) {
            let text = bs58::encode(&input).into_string();
            prop_assert_eq!(encode(&input), text.clone());
            prop_assert_eq!(decode(&text), Ok(input));
        }
    }
}
