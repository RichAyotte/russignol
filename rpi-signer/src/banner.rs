//! Non-blocking unknown-key alert banner.
//!
//! Drawn over the top of any non-modal page after the page renders, so it
//! never replaces the page or blocks navigation. Tapping the banner region
//! dismisses the alert.

use crate::app::AlertContent;
use crate::fonts;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point, Primitive, Size},
    primitives::{PrimitiveStyle, Rectangle},
};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

/// Banner height in pixels; touches above this line dismiss the alert.
pub const HEIGHT: i32 = 32;

const MARGIN: i32 = 4;
const LINE_1_BASELINE: i32 = 13;
const LINE_2_BASELINE: i32 = 28;

/// Fixed guidance line telling the operator what to fix.
const GUIDANCE: &str = "Check baker signer config, restart baker";

/// Headline naming the most recent unknown pkh and how many other distinct
/// unknown keys were requested; overflow marks the count as a lower bound.
fn headline(content: &AlertContent) -> String {
    let short = crate::text::truncate_middle(content.pkh, 8, 0);
    match (content.others, content.overflow) {
        (0, false) => format!("Unknown key {short}"),
        (1, false) => format!("Unknown key {short} (+1 other)"),
        (n, false) => format!("Unknown key {short} (+{n} others)"),
        (n, true) => format!("Unknown key {short} (+{n}+ others)"),
    }
}

/// Draw the alert banner: the most recent unknown pkh, how many other
/// distinct unknown keys were requested, and what the operator must fix.
pub fn draw<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    content: &AlertContent,
) -> Result<(), D::Error> {
    Rectangle::new(
        Point::zero(),
        Size::new(
            crate::pages::DISPLAY_WIDTH.unsigned_abs(),
            HEIGHT.unsigned_abs(),
        ),
    )
    .into_styled(PrimitiveStyle::with_fill(BinaryColor::Off))
    .draw(display)?;

    let font = FontRenderer::new::<fonts::FONT_MEDIUM>();
    draw_line(display, &font, &headline(content), LINE_1_BASELINE)?;

    let font = FontRenderer::new::<fonts::FONT_SMALL>();
    draw_line(display, &font, GUIDANCE, LINE_2_BASELINE)
}

/// Render one banner line. Display errors propagate to the caller;
/// font-content errors are logged — the font-coverage test keeps them
/// unreachable for banner content.
fn draw_line<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    font: &FontRenderer,
    line: &str,
    baseline: i32,
) -> Result<(), D::Error> {
    match font.render_aligned(
        line,
        Point::new(MARGIN, baseline),
        VerticalPosition::Baseline,
        HorizontalAlignment::Left,
        FontColor::Transparent(BinaryColor::On),
        display,
    ) {
        Ok(_) => Ok(()),
        Err(u8g2_fonts::Error::DisplayError(e)) => Err(e),
        Err(u8g2_fonts::Error::GlyphNotFound(c)) => {
            log::error!("banner: font missing glyph {c:?} in {line:?}");
            Ok(())
        }
        Err(u8g2_fonts::Error::BackgroundColorNotSupported) => {
            log::error!("banner: font background color not supported");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKH: &str = "tz4HVR43NNbNhLGTHUNCGWEUjYmDT1RGcNjZ";

    fn content(others: usize, overflow: bool) -> AlertContent<'static> {
        AlertContent {
            pkh: PKH,
            others,
            overflow,
        }
    }

    #[test]
    fn headline_for_a_single_key_has_no_suffix() {
        assert_eq!(headline(&content(0, false)), "Unknown key tz4HVR43...");
    }

    #[test]
    fn headline_for_two_keys_says_one_other() {
        assert_eq!(
            headline(&content(1, false)),
            "Unknown key tz4HVR43... (+1 other)"
        );
    }

    #[test]
    fn headline_for_many_keys_counts_others() {
        assert_eq!(
            headline(&content(5, false)),
            "Unknown key tz4HVR43... (+5 others)"
        );
    }

    #[test]
    fn headline_on_overflow_marks_the_count_as_a_lower_bound() {
        assert_eq!(
            headline(&content(7, true)),
            "Unknown key tz4HVR43... (+7+ others)"
        );
    }

    /// The display fonts cover only ISO-8859-1, and `render_aligned` aborts
    /// mid-string at a missing glyph, so every string the banner emits must
    /// be renderable.
    #[test]
    fn fonts_cover_every_banner_string() {
        let medium = FontRenderer::new::<fonts::FONT_MEDIUM>();
        for content in [
            content(0, false),
            content(1, false),
            content(7, false),
            content(7, true),
        ] {
            let line = headline(&content);
            assert!(
                medium
                    .get_rendered_dimensions(
                        line.as_str(),
                        Point::zero(),
                        VerticalPosition::Baseline
                    )
                    .is_ok(),
                "headline {line:?} contains a glyph the medium font cannot render"
            );
        }

        let small = FontRenderer::new::<fonts::FONT_SMALL>();
        assert!(
            small
                .get_rendered_dimensions(GUIDANCE, Point::zero(), VerticalPosition::Baseline)
                .is_ok(),
            "guidance line contains a glyph the small font cannot render"
        );
    }
}
