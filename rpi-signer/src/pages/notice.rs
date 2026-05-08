use super::Page as PageTrait;
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

/// A modal notice page: title + message + OK button. Modal so the
/// renderer refuses to draw over it; only a touch on OK dispatches the
/// `dismiss_event`, letting the caller chain the next step.
pub struct Page {
    app_sender: Sender<AppEvent>,
    title: String,
    message: String,
    button: Button,
    dismiss_event: AppEvent,
}

impl Page {
    pub fn new(
        app_sender: Sender<AppEvent>,
        title: &str,
        message: &str,
        dismiss_event: AppEvent,
    ) -> Self {
        Self {
            app_sender,
            title: title.to_string(),
            message: message.to_string(),
            button: Button::new_text(Size::new(70, 40), "OK"),
            dismiss_event,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn is_modal(&self) -> bool {
        true
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let display_bounds = display.bounding_box();
        let display_width = display_bounds.size.width.cast_signed();
        let display_height = display_bounds.size.height.cast_signed();
        let display_center = display_bounds.center();

        let horizontal_margin: i32 = 8;
        let top_margin: i32 = 5;
        let title_height: i32 = 20;
        let title_message_gap: i32 = 5;
        let button_height: i32 = 40;
        let bottom_margin: i32 = 5;
        let text_button_gap: i32 = 6;

        let title_bounds = Rectangle::new(
            Point::new(horizontal_margin, top_margin),
            Size::new(
                (display_width - 2 * horizontal_margin).cast_unsigned(),
                title_height.cast_unsigned(),
            ),
        );
        let title_style = U8g2TextStyle::new(fonts::FONT_PROPORTIONAL, BinaryColor::Off);
        let title_textbox_style = TextBoxStyleBuilder::new()
            .alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Top)
            .build();
        TextBox::with_textbox_style(&self.title, title_bounds, title_style, title_textbox_style)
            .draw(display)?;

        let button_top_y = display_height - button_height - bottom_margin;
        let message_top = top_margin + title_height + title_message_gap;
        let message_bounds = Rectangle::new(
            Point::new(horizontal_margin, message_top),
            Size::new(
                (display_width - 2 * horizontal_margin).cast_unsigned(),
                (button_top_y - message_top - text_button_gap).cast_unsigned(),
            ),
        );
        let message_style = U8g2TextStyle::new(fonts::FONT_PROPORTIONAL, BinaryColor::Off);
        let message_textbox_style = TextBoxStyleBuilder::new()
            .alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Middle)
            .build();
        TextBox::with_textbox_style(
            &self.message,
            message_bounds,
            message_style,
            message_textbox_style,
        )
        .draw(display)?;

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
