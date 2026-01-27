use super::Page;
use crate::fonts;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point, Size},
    primitives::Rectangle,
};
use embedded_text::{
    TextBox,
    alignment::{HorizontalAlignment, VerticalAlignment},
    style::TextBoxStyleBuilder,
};
use u8g2_fonts::U8g2TextStyle;

/// `ErrorPage` displays an error message with word-wrapped text.
///
/// Used for first-boot setup to show error messages that may be long.
pub struct ErrorPage {
    title: String,
    message: String,
}

impl ErrorPage {
    /// Create a new `ErrorPage` with title and message
    #[must_use]
    pub fn new(title: &str, message: &str) -> Self {
        Self {
            title: title.to_string(),
            message: message.to_string(),
        }
    }

    /// Update the error message
    pub fn set_message(&mut self, title: &str, message: &str) {
        self.title = title.to_string();
        self.message = message.to_string();
    }
}

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for ErrorPage {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let display_bounds = display.bounding_box();
        let display_width = display_bounds.size.width.cast_signed();
        let display_height = display_bounds.size.height.cast_signed();

        // Layout constants
        let horizontal_margin = 8;
        let top_margin = 5;

        // Draw title "ERROR" at top using smaller font for more message space
        let title_bounds = Rectangle::new(
            Point::new(horizontal_margin, top_margin),
            Size::new((display_width - 2 * horizontal_margin).cast_unsigned(), 20),
        );

        let title_style = U8g2TextStyle::new(fonts::FONT_PROPORTIONAL, BinaryColor::Off);
        let title_textbox_style = TextBoxStyleBuilder::new()
            .alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Top)
            .build();

        TextBox::with_textbox_style(&self.title, title_bounds, title_style, title_textbox_style)
            .draw(display)?;

        // Draw message with word-wrapping in remaining space
        let message_top = top_margin + 25;
        let message_bounds = Rectangle::new(
            Point::new(horizontal_margin, message_top),
            Size::new(
                (display_width - 2 * horizontal_margin).cast_unsigned(),
                (display_height - message_top - 5).cast_unsigned(),
            ),
        );

        let character_style = U8g2TextStyle::new(fonts::FONT_MONOSPACE, BinaryColor::Off);
        let textbox_style = TextBoxStyleBuilder::new()
            .alignment(HorizontalAlignment::Left)
            .vertical_alignment(VerticalAlignment::Top)
            .build();

        TextBox::with_textbox_style(
            &self.message,
            message_bounds,
            character_style,
            textbox_style,
        )
        .draw(display)?;

        Ok(())
    }
}
