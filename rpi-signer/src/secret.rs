//! Wrapper for byte buffers and strings that hold PIN material or decrypted
//! secret keys.
//!
//! Combines `zeroize::Zeroizing` (zero on drop) with a redacted `Debug` impl
//! so a stray `{:?}` formatter anywhere downstream cannot leak the contents.

use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Default, Eq, PartialEq)]
pub struct Secret<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Adopt an existing `Zeroizing<T>` without re-wrapping its allocation.
    pub fn from_zeroizing(value: Zeroizing<T>) -> Self {
        Self(value)
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> From<Zeroizing<T>> for Secret<T> {
    fn from(value: Zeroizing<T>) -> Self {
        Self::from_zeroizing(value)
    }
}

impl<T: Zeroize> Deref for Secret<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn debug_is_redacted_for_bytes() {
        let s: Secret<Vec<u8>> = Secret::new(vec![1, 2, 3, 4]);
        assert_eq!(format!("{s:?}"), "<redacted>");
    }

    #[test]
    fn debug_is_redacted_for_string() {
        let s: Secret<String> = Secret::new(String::from("super-secret-json"));
        assert_eq!(format!("{s:?}"), "<redacted>");
    }

    #[test]
    fn zeroize_on_drop_marker_holds() {
        assert_zeroize_on_drop::<Secret<Vec<u8>>>();
        assert_zeroize_on_drop::<Secret<String>>();
    }

    #[test]
    fn from_zeroizing_round_trip() {
        let s: Secret<String> = Secret::from_zeroizing(Zeroizing::new(String::from("x")));
        assert_eq!(s.as_str(), "x");
    }
}
