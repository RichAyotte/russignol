//! ASCII-safe truncation for operator-facing strings.
//!
//! The display fonts (`libs/ui/src/fonts.rs`) cover only ISO-8859-1, and
//! `render_aligned` aborts mid-string at a missing glyph, so the ellipsis
//! must be a literal ASCII `...`, never U+2026.

/// Truncate `s` to its first `prefix` and last `suffix` characters joined by
/// `...`. Returns the input unchanged when it is no longer than
/// `prefix + suffix + 3`, since truncating would not shorten it.
pub fn truncate_middle(s: &str, prefix: usize, suffix: usize) -> String {
    if s.len() <= prefix + suffix + 3 {
        return s.to_string();
    }
    format!("{}...{}", &s[..prefix], &s[s.len() - suffix..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TZ4_PKH: &str = "tz4HVR43NNbNhLGTHUNCGWEUjYmDT1RGcNjZ";

    #[test]
    fn passes_through_at_the_length_boundary() {
        assert_eq!(
            truncate_middle("0123456789abcdefghi", 10, 6),
            "0123456789abcdefghi"
        );
    }

    #[test]
    fn truncates_just_above_the_length_boundary() {
        assert_eq!(
            truncate_middle("0123456789abcdefghij", 10, 6),
            "0123456789...efghij"
        );
    }

    #[test]
    fn keeps_prefix_and_suffix_of_a_pkh() {
        assert_eq!(truncate_middle(TZ4_PKH, 10, 6), "tz4HVR43NN...RGcNjZ");
    }

    #[test]
    fn zero_suffix_keeps_only_the_prefix() {
        assert_eq!(truncate_middle(TZ4_PKH, 8, 0), "tz4HVR43...");
    }

    #[test]
    fn output_is_pure_ascii() {
        assert!(truncate_middle(TZ4_PKH, 8, 0).is_ascii());
        assert!(truncate_middle(TZ4_PKH, 10, 6).is_ascii());
    }
}
