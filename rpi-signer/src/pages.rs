pub mod about;
pub mod blockchain;
pub mod confirmation;
pub mod dialog;
pub mod greeting;
pub mod image_info;
pub mod menu;
pub mod notice;
pub mod pin;
pub mod screensaver;
pub mod signatures;
pub mod status;
pub mod watermarks;

// Re-export Page trait from the library instead of defining our own
pub use russignol_ui::pages::Page;

use russignol_signer_lib::KeyRole;

// Display dimensions in landscape (90° rotated) orientation.
// Native panel is 122×250; after rotation pages see 250×122.
pub const DISPLAY_WIDTH: i32 = epd_2in13_v4::common::HEIGHT.cast_signed();
pub const DISPLAY_HEIGHT: i32 = epd_2in13_v4::common::WIDTH.cast_signed();

/// Key-icon glyph for a role, in the [`crate::fonts::ICON_KEY`] glyph set
/// (C→"1", P→"0").
#[must_use]
pub const fn key_icon(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Consensus => "1",
        KeyRole::Companion => "0",
    }
}
