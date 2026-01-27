// Font definitions for Russignol applications

// Proportional font with extended characters (includes degree symbol, etc.)
pub use u8g2_fonts::fonts::u8g2_font_helvR12_tf as FONT_PROPORTIONAL;

// Medium proportional font for table data and secondary text
pub use u8g2_fonts::fonts::u8g2_font_helvR10_tf as FONT_MEDIUM;
// Backwards compatibility alias
pub use u8g2_fonts::fonts::u8g2_font_helvR10_tf as FONT_MONOSPACE;

// True monospace font for keys, hashes, and technical data (Courier 12pt)
pub use u8g2_fonts::fonts::u8g2_font_courR12_tf as FONT_MONO;

// Small monospace font for compact key/hash display (Courier 10pt)
pub use u8g2_fonts::fonts::u8g2_font_courR10_tf as FONT_MONO_SMALL;

// Small font for error messages and wrapped text
pub use u8g2_fonts::fonts::u8g2_font_helvR08_tf as FONT_SMALL;

// Iconic fonts for status indicators
// Streamline Interface Essential Key Lock
// According to u8g2 wiki, streamline fonts start at '0' (0x30)
// '0' (0x30 / 48) = double key icon
// '1' (0x31 / 49) = single key icon
pub use u8g2_fonts::fonts::u8g2_font_streamline_interface_essential_key_lock_t as ICON_KEY;

// Streamline Interface Essential Circle Triangle
// Contains warning triangle icons with exclamation marks
// Character '0' (0x30) is typically the first icon in the set
pub use u8g2_fonts::fonts::u8g2_font_streamline_interface_essential_circle_triangle_t as ICON_WARNING;
