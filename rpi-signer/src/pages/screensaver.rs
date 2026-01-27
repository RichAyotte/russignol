use super::Page;
use crate::fonts;
use embedded_graphics::{image::Image, pixelcolor::BinaryColor, prelude::*};
use tinybmp::Bmp;
use u8g2_fonts::FontRenderer;

const RUSSIGNOL_LOGO: &[u8] = include_bytes!("../../assets/sleeping-russignol-61h.bmp");

pub struct ScreensaverPage;

impl ScreensaverPage {
    pub fn new() -> Self {
        Self
    }
}

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for ScreensaverPage {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let display_bounds = display.bounding_box();
        let display_width = display_bounds.size.width.cast_signed();
        let display_height = display_bounds.size.height.cast_signed();

        let logo_result: Result<Bmp<BinaryColor>, _> = Bmp::from_slice(RUSSIGNOL_LOGO);
        let logo_size = logo_result
            .as_ref()
            .map(|l| l.bounding_box().size)
            .unwrap_or(Size::new(64, 64)); // Fallback size if BMP fails

        // Calculate total height of logo + spacing + text, then center vertically
        let text_height = 12;
        let logo_text_gap = 6;
        let total_content_height = logo_size.height.cast_signed() + logo_text_gap + text_height;
        let content_top = (display_height - total_content_height) / 2;

        // Center logo horizontally
        let logo_x = (display_width - logo_size.width.cast_signed()) / 2;
        if let Ok(logo) = logo_result {
            Image::new(&logo, Point::new(logo_x, content_top)).draw(display)?;
        } else {
            log::error!("Failed to parse screensaver logo BMP - binary may be corrupted");
        }

        // Draw "Russignol" name centered below logo
        let font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
        let text_y = content_top + logo_size.height.cast_signed() + logo_text_gap + text_height;
        font.render_aligned(
            "Russignol",
            Point::new(display_width / 2, text_y),
            u8g2_fonts::types::VerticalPosition::Baseline,
            u8g2_fonts::types::HorizontalAlignment::Center,
            u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

        Ok(())
    }
}
