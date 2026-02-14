//! Greeting page shown at first boot before the setup process begins
//!
//! This page displays the Russignol logo and a "Begin" button to start
//! the first-boot setup process (PIN creation and key generation).

use crate::events::AppEvent;
use crossbeam_channel::Sender;
use embedded_graphics::{image::Image, pixelcolor::BinaryColor, prelude::*};
use russignol_ui::{fonts, widgets::Button};
use tinybmp::Bmp;
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment as U8gHAlign, VerticalPosition},
};

use super::Page;

/// Static logo BMP loaded at compile time
const LOGO_DATA: &[u8] = include_bytes!("../../assets/russignol-61h.bmp");

/// Greeting page with logo and "Begin" button for first-boot setup
pub struct GreetingPage {
    app_sender: Sender<AppEvent>,
    button: Button,
}

impl GreetingPage {
    /// Create a new greeting page
    pub fn new(app_sender: Sender<AppEvent>) -> Self {
        Self {
            app_sender,
            // Generous padding around text
            button: Button::new_text(Size::new(90, 36), "Begin"),
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for GreetingPage {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let display_bounds = display.bounding_box();
        let display_width = display_bounds.size.width.cast_signed();
        let display_height = display_bounds.size.height.cast_signed();

        // Split screen: left half for logo+name, right half for button
        let half_width = display_width / 2;

        // === LEFT HALF: Logo + "Russignol" name (vertically centered together) ===
        let logo_result: Result<Bmp<BinaryColor>, _> = Bmp::from_slice(LOGO_DATA);
        let logo_size = logo_result
            .as_ref()
            .map(|l| l.bounding_box().size)
            .unwrap_or(Size::new(64, 64)); // Fallback size if BMP fails

        // Calculate total height of logo + spacing + text, then center vertically
        let text_height = 12; // approximate height of FONT_PROPORTIONAL
        let logo_text_gap = 6;
        let total_content_height = logo_size.height.cast_signed() + logo_text_gap + text_height;
        let content_top = (display_height - total_content_height) / 2;

        // Center logo horizontally in left half
        let logo_x = (half_width - logo_size.width.cast_signed()) / 2;
        let logo_y = content_top;
        if let Ok(logo) = logo_result {
            Image::new(&logo, Point::new(logo_x, logo_y)).draw(display)?;
        } else {
            log::error!("Failed to parse logo BMP - binary may be corrupted");
        }

        // Draw "Russignol" name centered below logo
        let name_font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
        let name_y = logo_y + logo_size.height.cast_signed() + logo_text_gap + text_height;
        name_font
            .render_aligned(
                "Russignol",
                Point::new(half_width / 2, name_y),
                VerticalPosition::Baseline,
                U8gHAlign::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok(); // Ignore font errors (BackgroundColorNotSupported can't happen with Transparent)

        // === RIGHT HALF: Button vertically centered ===
        let right_margin = 5;
        let right_start = half_width + 5;
        let right_width = (display_width - right_start - right_margin).cast_unsigned();

        let right_center_x = right_start + right_width.cast_signed() / 2;
        let button_height = self.button.bounds.size.height.cast_signed();
        let button_width = self.button.bounds.size.width.cast_signed();
        let button_top_y = (display_height - button_height) / 2;

        self.button.bounds.top_left = Point::new(right_center_x - button_width / 2, button_top_y);
        self.button.draw(display)?;

        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        if self.button.contains(point) {
            let _ = self.app_sender.send(AppEvent::StartSetup);
            true
        } else {
            false
        }
    }
}
