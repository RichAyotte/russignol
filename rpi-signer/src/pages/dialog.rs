use super::Page;
use crate::events::AppEvent;
use crate::fonts;
use crate::widgets::Button;
use crossbeam_channel::Sender;
use embedded_graphics::{Drawable, pixelcolor::BinaryColor, prelude::*, primitives::Rectangle};
use embedded_text::{
    TextBox,
    alignment::{HorizontalAlignment, VerticalAlignment},
    style::TextBoxStyleBuilder,
};
use u8g2_fonts::U8g2TextStyle;

pub struct DialogPage {
    app_sender: Sender<AppEvent>,
    message: String,
    button: Button,
    dismiss_event: AppEvent,
}

impl DialogPage {
    pub fn new(app_sender: Sender<AppEvent>, message: &str, dismiss_event: AppEvent) -> Self {
        Self {
            app_sender,
            message: message.to_string(),
            button: Button::new_text(Size::new(70, 40), "OK"),
            dismiss_event,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for DialogPage {
    fn is_modal(&self) -> bool {
        true
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let display_bounds = display.bounding_box();
        let display_width = display_bounds.size.width.cast_signed();
        let display_height = display_bounds.size.height.cast_signed();
        let display_center = display_bounds.center();

        // Layout constants
        let horizontal_margin = 10;
        let top_margin = 10;
        let button_height = 40;
        let bottom_margin = 5;
        let text_button_gap = 10;

        // Position button at bottom with consistent margin
        let button_top_y = display_height - button_height - bottom_margin;

        // Define text area above button with margins
        let text_bounds = Rectangle::new(
            Point::new(horizontal_margin, top_margin),
            Size::new(
                (display_width - 2 * horizontal_margin).cast_unsigned(),
                (button_top_y - top_margin - text_button_gap).cast_unsigned(),
            ),
        );

        // Draw message text with automatic word-wrapping
        let character_style = U8g2TextStyle::new(fonts::FONT_PROPORTIONAL, BinaryColor::Off);
        let textbox_style = TextBoxStyleBuilder::new()
            .alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Middle)
            .build();

        TextBox::with_textbox_style(&self.message, text_bounds, character_style, textbox_style)
            .draw(display)?;

        // Position and draw OK button
        let button_width = self.button.bounds.size.width.cast_signed();
        self.button.bounds.top_left = Point::new(display_center.x - button_width / 2, button_top_y);
        self.button.draw(display)
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        if self.button.contains(point) {
            let _ = self.app_sender.send(self.dismiss_event.clone());
            true
        } else {
            false
        }
    }
}
