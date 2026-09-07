pub mod about;
pub mod blockchain;
pub mod confirmation;
pub mod dialog;
pub mod greeting;
pub mod image_info;
pub mod keys;
pub mod menu;
pub mod notice;
pub mod pin;
pub mod provision;
pub mod screensaver;
pub mod signatures;
pub mod status;
pub mod watermarks;

pub use russignol_ui::pages::Page;

use crate::widgets::Button;
use embedded_graphics::prelude::{Point, Size};
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

/// Left edge of the first tab and right edge of the second.
const TAB_MARGIN: i32 = 6;
const TAB_Y: i32 = 2;
const TAB_H: u32 = 30;
const TAB_GAP: i32 = 6;
/// Half of what the margins and the gap leave, so the pair spans the panel by
/// construction rather than by a width held equal to it.
const TAB_W: u32 = ((DISPLAY_WIDTH - 2 * TAB_MARGIN - TAB_GAP) / 2).cast_unsigned();

/// The first pixel row a tabbed page's own content may use. Read by the
/// tests that hold each view clear of the bar drawn over it.
#[cfg(test)]
pub const TABS_BOTTOM: i32 = TAB_Y + TAB_H.cast_signed();

/// Capitalize a key alias for display (`consensus_tz4` draws as
/// `Consensus_tz4`), so one key reads the same on every page that names it.
#[must_use]
pub fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// The two tabs a page carrying two views draws across its top.
///
/// One definition for both such pages: a tab bar an operator meets at two
/// different sizes reads as two different controls.
#[must_use]
pub fn tab_pair(left: &str, right: &str) -> (Button, Button) {
    let size = Size::new(TAB_W, TAB_H);
    let mut left_tab = Button::new_text(size, left);
    left_tab.bounds.top_left = Point::new(TAB_MARGIN, TAB_Y);
    let mut right_tab = Button::new_text(size, right);
    right_tab.bounds.top_left = Point::new(TAB_MARGIN + TAB_W.cast_signed() + TAB_GAP, TAB_Y);
    (left_tab, right_tab)
}

/// Raise a failed write to the panel and drop the two font-level refusals.
///
/// `GlyphNotFound` and `BackgroundColorNotSupported` are properties of the font
/// and the string rather than of the display, and leave their own glyph blank.
/// `DisplayError` is the same fault the drawing primitives raise through `?`,
/// so swallowing it would report a page that never reached the panel as drawn.
pub fn drawn<E>(
    result: Result<Option<embedded_graphics::primitives::Rectangle>, u8g2_fonts::Error<E>>,
) -> Result<(), E> {
    match result {
        Err(u8g2_fonts::Error::DisplayError(e)) => Err(e),
        Ok(_) | Err(_) => Ok(()),
    }
}

/// Hold `label` to the button it is drawn in, measured in the font a button
/// draws text with: a glyph's width is the font's rather than the label's
/// length, and a label wider than its button is drawn over the rounded edge
/// and past it.
///
/// # Panics
///
/// Panics if the font cannot draw the label, or if it does not fit.
#[cfg(test)]
pub fn assert_label_fits(label: &str, button_width: u32) {
    use u8g2_fonts::{FontRenderer, types::VerticalPosition};

    /// Clear pixels either side of the widest glyph, so a label is not drawn
    /// touching the stroke around it.
    const PADDING: u32 = 6;

    let width = FontRenderer::new::<crate::fonts::FONT_PROPORTIONAL>()
        .get_rendered_dimensions(label, Point::zero(), VerticalPosition::Center)
        .expect("the font draws these glyphs")
        .bounding_box
        .expect("a non-empty label has a bounding box")
        .size
        .width;
    assert!(
        width + PADDING <= button_width,
        "{label:?} is {width}px wide inside a {button_width}px button"
    );
}

/// A panel that keeps where it was drawn on and none of what was drawn, so a
/// test can ask which rows a view actually reaches rather than which rows its
/// constants name.
#[cfg(test)]
pub mod test_ink {
    use super::{DISPLAY_HEIGHT, DISPLAY_WIDTH};
    use embedded_graphics::{
        Pixel,
        draw_target::DrawTarget,
        geometry::{OriginDimensions, Size},
        pixelcolor::BinaryColor,
    };
    use std::collections::BTreeSet;

    #[derive(Default)]
    pub struct Ink(pub BTreeSet<(i32, i32)>);

    impl Ink {
        /// The topmost pixel row anything reached, or `None` where the draw
        /// left the panel blank.
        #[must_use]
        pub fn top_row(&self) -> Option<i32> {
            self.0.iter().map(|&(_, y)| y).min()
        }
    }

    impl DrawTarget for Ink {
        type Color = BinaryColor;
        type Error = core::convert::Infallible;

        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<Self::Color>>,
        {
            for Pixel(point, _) in pixels {
                // Clipped as the panel clips it, so ink drawn off the edge is
                // ink no test can find either.
                if (0..DISPLAY_WIDTH).contains(&point.x) && (0..DISPLAY_HEIGHT).contains(&point.y) {
                    self.0.insert((point.x, point.y));
                }
            }
            Ok(())
        }
    }

    impl OriginDimensions for Ink {
        fn size(&self) -> Size {
            Size::new(
                DISPLAY_WIDTH.cast_unsigned(),
                DISPLAY_HEIGHT.cast_unsigned(),
            )
        }
    }

    /// A panel that refuses one write, the `refused`-th it is handed, and
    /// takes every other, so a test can ask of each write a page makes whether
    /// its failure reaches the caller.
    pub struct RefusesWrite {
        refused: Option<usize>,
        /// Writes handed to the panel so far, the refused one included.
        pub writes: usize,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct WriteRefused;

    impl RefusesWrite {
        /// Takes every write, so `writes` afterwards is the whole frame.
        #[must_use]
        pub const fn counting() -> Self {
            Self {
                refused: None,
                writes: 0,
            }
        }

        #[must_use]
        pub const fn at(refused: usize) -> Self {
            Self {
                refused: Some(refused),
                writes: 0,
            }
        }
    }

    impl DrawTarget for RefusesWrite {
        type Color = BinaryColor;
        type Error = WriteRefused;

        fn draw_iter<I>(&mut self, _pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<Self::Color>>,
        {
            let index = self.writes;
            self.writes += 1;
            if self.refused == Some(index) {
                return Err(WriteRefused);
            }
            Ok(())
        }
    }

    impl OriginDimensions for RefusesWrite {
        fn size(&self) -> Size {
            Size::new(
                DISPLAY_WIDTH.cast_unsigned(),
                DISPLAY_HEIGHT.cast_unsigned(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TAB_W, assert_label_fits, drawn};

    /// A write that never reached the panel is raised, and the two refusals
    /// that are the font's rather than the display's are not. Every page draws
    /// through this, so a page reporting a frame it never wrote reports it
    /// here first.
    #[test]
    fn a_failed_panel_write_is_raised_and_a_font_refusal_is_not() {
        assert_eq!(
            drawn::<u8>(Err(u8g2_fonts::Error::DisplayError(7))),
            Err(7),
            "a display error must reach the caller"
        );
        assert_eq!(
            drawn::<u8>(Err(u8g2_fonts::Error::GlyphNotFound('x'))),
            Ok(())
        );
        assert_eq!(
            drawn::<u8>(Err(u8g2_fonts::Error::BackgroundColorNotSupported)),
            Ok(())
        );
        assert_eq!(drawn::<u8>(Ok(None)), Ok(()));
    }

    /// Every label a tabbed page puts on the bar fits the tab it sits in.
    #[test]
    fn every_tab_label_fits_its_button() {
        let labels = crate::pages::keys::TABS
            .into_iter()
            .chain(crate::pages::image_info::TABS);

        for label in labels {
            assert_label_fits(label, TAB_W);
        }
    }
}
