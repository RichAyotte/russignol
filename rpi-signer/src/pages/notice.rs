use super::Page as PageTrait;
use crate::events::AppEvent;
use crate::fonts;
use crate::pages::{DISPLAY_HEIGHT, DISPLAY_WIDTH};
use crate::widgets::Button;
use crossbeam_channel::Sender;
use embedded_graphics::{Drawable, pixelcolor::BinaryColor, prelude::*, primitives::Rectangle};
use embedded_text::{
    TextBox,
    alignment::{HorizontalAlignment, VerticalAlignment},
    style::{TextBoxStyle, TextBoxStyleBuilder},
};
use u8g2_fonts::U8g2TextStyle;

const HORIZONTAL_MARGIN: i32 = 8;
const TOP_MARGIN: i32 = 3;
/// Title band height. The title renders in `FONT_PROPORTIONAL` (21 px line);
/// a band shorter than that drops the single title row as a partial row under
/// the text box's full-rows-only clipping.
const TITLE_HEIGHT: i32 = 22;
const TITLE_MESSAGE_GAP: i32 = 2;
const TEXT_BUTTON_GAP: i32 = 3;
const BUTTON_WIDTH: i32 = 70;
const BUTTON_HEIGHT: i32 = 33;
const BOTTOM_MARGIN: i32 = 3;

const MESSAGE_WIDTH: i32 = DISPLAY_WIDTH - 2 * HORIZONTAL_MARGIN;
const MESSAGE_TOP: i32 = TOP_MARGIN + TITLE_HEIGHT + TITLE_MESSAGE_GAP;
const BUTTON_TOP: i32 = DISPLAY_HEIGHT - BUTTON_HEIGHT - BOTTOM_MARGIN;

/// Height available for the wrapped message between the title band and the OK
/// button. The text box clips whole rows that do not fit, so a message taller
/// than this loses its outer lines; callers keep messages within it by
/// checking [`measure_message_height`].
pub(crate) const MESSAGE_BOX_HEIGHT: i32 = BUTTON_TOP - MESSAGE_TOP - TEXT_BUTTON_GAP;

/// The message renders in `FONT_MEDIUM` (helvR10, 18 px line) rather than the
/// 21 px title font so a three-line message — a key hash plus a two-line
/// instruction — fits [`MESSAGE_BOX_HEIGHT`].
fn message_char_style() -> U8g2TextStyle<BinaryColor> {
    U8g2TextStyle::new(fonts::FONT_MEDIUM, BinaryColor::Off)
}

fn message_textbox_style() -> TextBoxStyle {
    TextBoxStyleBuilder::new()
        .alignment(HorizontalAlignment::Center)
        .vertical_alignment(VerticalAlignment::Middle)
        .build()
}

/// Rendered height of `message` wrapped to the message-box width, in the font
/// and layout [`Page::draw`] uses. Callers assert it fits [`MESSAGE_BOX_HEIGHT`]
/// so no line is clipped.
#[cfg(test)]
pub(crate) fn measure_message_height(message: &str) -> u32 {
    message_textbox_style().measure_text_height(
        &message_char_style(),
        message,
        MESSAGE_WIDTH.cast_unsigned(),
    )
}

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
            button: Button::new_text(
                Size::new(BUTTON_WIDTH.cast_unsigned(), BUTTON_HEIGHT.cast_unsigned()),
                "OK",
            ),
            dismiss_event,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn is_modal(&self) -> bool {
        true
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let title_bounds = Rectangle::new(
            Point::new(HORIZONTAL_MARGIN, TOP_MARGIN),
            Size::new(MESSAGE_WIDTH.cast_unsigned(), TITLE_HEIGHT.cast_unsigned()),
        );
        let title_style = U8g2TextStyle::new(fonts::FONT_PROPORTIONAL, BinaryColor::Off);
        let title_textbox_style = TextBoxStyleBuilder::new()
            .alignment(HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Top)
            .build();
        TextBox::with_textbox_style(&self.title, title_bounds, title_style, title_textbox_style)
            .draw(display)?;

        let message_bounds = Rectangle::new(
            Point::new(HORIZONTAL_MARGIN, MESSAGE_TOP),
            Size::new(
                MESSAGE_WIDTH.cast_unsigned(),
                MESSAGE_BOX_HEIGHT.cast_unsigned(),
            ),
        );
        TextBox::with_textbox_style(
            &self.message,
            message_bounds,
            message_char_style(),
            message_textbox_style(),
        )
        .draw(display)?;

        self.button.bounds.top_left = Point::new((DISPLAY_WIDTH - BUTTON_WIDTH) / 2, BUTTON_TOP);
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
