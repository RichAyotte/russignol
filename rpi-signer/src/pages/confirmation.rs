use super::Page as PageTrait;
use crate::events::AppEvent;
use crate::fonts;
use crate::widgets::Button;
use crossbeam_channel::Sender;
use embedded_graphics::{Drawable, pixelcolor::BinaryColor, prelude::*, primitives::Rectangle};
use embedded_text::{
    TextBox,
    alignment::{HorizontalAlignment, VerticalAlignment},
    style::{TextBoxStyle, TextBoxStyleBuilder},
};
use u8g2_fonts::{
    FontRenderer, U8g2TextStyle,
    types::{FontColor, HorizontalAlignment as U8g2HAlign, VerticalPosition},
};

const ICON_MARGIN: i32 = 10;
const ICON_SIZE: i32 = 21; // Streamline icons are 21x21
const TEXT_MARGIN: i32 = 5;
const BUTTON_HEIGHT: i32 = 40;
const TEXT_BUTTON_GAP: i32 = 6;

/// Width of the icon column: a margin each side of the icon, or nothing when
/// no icon is shown.
const fn left_column_width(show_alert_icon: bool) -> i32 {
    if show_alert_icon {
        ICON_MARGIN + ICON_SIZE + ICON_MARGIN
    } else {
        0
    }
}

/// Width left for the message beside the (optional) icon column.
const fn text_area_width(display_width: i32, show_alert_icon: bool) -> i32 {
    display_width - left_column_width(show_alert_icon) - TEXT_MARGIN
}

/// Height available for the message above the buttons. The text box clips
/// whole rows that do not fit, so a message taller than this loses rows;
/// callers keep messages within it by checking [`measure_message_height`].
#[cfg(test)]
pub(crate) const MESSAGE_MAX_HEIGHT: i32 =
    crate::pages::DISPLAY_HEIGHT - BUTTON_HEIGHT - TEXT_BUTTON_GAP;

fn message_char_style() -> U8g2TextStyle<BinaryColor> {
    U8g2TextStyle::new(fonts::FONT_PROPORTIONAL, BinaryColor::Off)
}

fn message_textbox_style() -> TextBoxStyle {
    TextBoxStyleBuilder::new()
        .alignment(HorizontalAlignment::Center)
        .vertical_alignment(VerticalAlignment::Middle)
        .build()
}

/// Rendered height of `message` wrapped to the message column on the 250x122
/// panel, in the font and layout [`Page::draw`] uses. Callers assert it fits
/// [`MESSAGE_MAX_HEIGHT`] so no line is clipped.
#[cfg(test)]
pub(crate) fn measure_message_height(message: &str, show_alert_icon: bool) -> u32 {
    message_textbox_style().measure_text_height(
        &message_char_style(),
        message,
        text_area_width(crate::pages::DISPLAY_WIDTH, show_alert_icon).cast_unsigned(),
    )
}

static CONFIRMATION_PAGE_COUNTER: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

pub struct Page {
    id: u32,
    app_sender: Sender<AppEvent>,
    message: String,
    confirm_event: AppEvent,
    cancel_event: AppEvent,
    yes_button: Button,
    no_button: Button,
    show_alert_icon: bool,
    /// Optional key-value pairs for aligned rendering (title is in message field)
    key_value_pairs: Option<Vec<(String, String)>>,
}

impl Page {
    /// Calculate button width using actual font measurement
    fn measure_button_width(text: &str) -> u32 {
        let font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
        let text_width = font
            .get_rendered_dimensions(text, Point::zero(), VerticalPosition::Baseline)
            .ok()
            .and_then(|d| d.bounding_box.map(|b| b.size.width))
            .unwrap_or(u32::try_from(text.len()).unwrap_or(u32::MAX) * 7);
        // Add padding (10px each side) and ensure minimum width
        (text_width + 20).max(70)
    }

    pub fn new(
        app_sender: Sender<AppEvent>,
        message: &str,
        confirm_event: AppEvent,
        cancel_event: AppEvent,
        show_alert_icon: bool,
        confirm_button_text: &str,
    ) -> Self {
        let id = CONFIRMATION_PAGE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        log::info!("[Page] Creating new Page id={id}");
        let button_width = Self::measure_button_width(confirm_button_text);
        Self {
            id,
            app_sender,
            message: message.to_string(),
            confirm_event,
            cancel_event,
            yes_button: Button::new_text(Size::new(button_width, 40), confirm_button_text),
            no_button: Button::new_text(Size::new(70, 40), "Cancel"),
            show_alert_icon,
            key_value_pairs: None,
        }
    }

    /// Create a confirmation page with a centered title and aligned key-value pairs
    pub fn new_with_pairs(
        app_sender: Sender<AppEvent>,
        title: &str,
        key_value_pairs: Vec<(String, String)>,
        confirm_event: AppEvent,
        cancel_event: AppEvent,
        show_alert_icon: bool,
        confirm_button_text: &str,
    ) -> Self {
        let id = CONFIRMATION_PAGE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        log::info!("[Page] Creating new Page with pairs id={id}");
        let button_width = Self::measure_button_width(confirm_button_text);
        Self {
            id,
            app_sender,
            message: title.to_string(),
            confirm_event,
            cancel_event,
            yes_button: Button::new_text(Size::new(button_width, 40), confirm_button_text),
            no_button: Button::new_text(Size::new(70, 40), "Cancel"),
            show_alert_icon,
            key_value_pairs: Some(key_value_pairs),
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn is_modal(&self) -> bool {
        true
    }

    #[expect(
        clippy::too_many_lines,
        reason = "complex multi-element display layout"
    )]
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        // Get display dimensions
        let display_bounds = display.bounding_box();
        let display_width = display_bounds.size.width.cast_signed();
        let display_height = display_bounds.size.height.cast_signed();

        // For manual baseline rendering (key-value pairs), 16px between baselines is fine
        let manual_line_height = 16;

        // Split layout: narrow left column for icon, right side for text+buttons
        let right_start = left_column_width(self.show_alert_icon);
        let right_width = text_area_width(display_width, self.show_alert_icon);

        // Calculate text block height based on content
        let text_block_height = if let Some(ref pairs) = self.key_value_pairs {
            // Title line + pair lines (manual baseline positioning)
            (i32::try_from(pairs.len()).unwrap_or(0) + 1) * manual_line_height
        } else {
            // The message word-wraps, so budget its measured wrapped height —
            // counting manual newlines undercounts and the text box would clip
            // the overflow rows.
            message_textbox_style()
                .measure_text_height(
                    &message_char_style(),
                    &self.message,
                    right_width.cast_unsigned(),
                )
                .cast_signed()
        };

        // Center the entire block (text + gap + buttons) vertically
        let block_height = text_block_height + TEXT_BUTTON_GAP + BUTTON_HEIGHT;
        let content_top = (display_height - block_height) / 2;
        let button_top_y = content_top + block_height - BUTTON_HEIGHT;

        let text_top = content_top;

        // === LEFT COLUMN: Icon (vertically centered with the text area) ===
        if self.show_alert_icon {
            let icon_font = u8g2_fonts::FontRenderer::new::<fonts::ICON_WARNING>();
            let text_center_y = text_top + text_block_height / 2;
            let _ = icon_font.render_aligned(
                '0',
                Point::new(ICON_MARGIN + ICON_SIZE / 2, text_center_y),
                VerticalPosition::Center,
                U8g2HAlign::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            );
        }

        // TextBox gets full space above buttons for VerticalAlignment::Middle centering
        let textbox_height = button_top_y - TEXT_BUTTON_GAP;
        let text_bounds = Rectangle::new(
            Point::new(right_start, 0),
            Size::new(right_width.cast_unsigned(), textbox_height.cast_unsigned()),
        );

        if let Some(ref pairs) = self.key_value_pairs {
            // Render title centered and key-value pairs with aligned columns
            let font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
            let line_height = manual_line_height;
            let label_value_gap = 4; // Gap between label and value

            // Render title centered
            let title_y = text_top + line_height;
            let content_center_x = right_start + right_width / 2;
            let _ = font.render_aligned(
                self.message.as_str(),
                Point::new(content_center_x, title_y),
                VerticalPosition::Baseline,
                U8g2HAlign::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            );

            // Find the widest label to determine alignment position
            let max_label_width = pairs
                .iter()
                .filter_map(|(label, _)| {
                    font.get_rendered_dimensions(
                        label.as_str(),
                        Point::zero(),
                        VerticalPosition::Baseline,
                    )
                    .ok()
                    .and_then(|d| d.bounding_box.map(|b| b.size.width.cast_signed()))
                })
                .max()
                .unwrap_or(60);

            // Position labels right-aligned at this X, values left-aligned after the gap
            let label_right_x = right_start + max_label_width;
            let value_left_x = label_right_x + label_value_gap;

            // Render each key-value pair
            for (i, (label, value)) in pairs.iter().enumerate() {
                let row_y = title_y + (i32::try_from(i).unwrap() + 1) * line_height;

                // Render label right-aligned
                let _ = font.render_aligned(
                    label.as_str(),
                    Point::new(label_right_x, row_y),
                    VerticalPosition::Baseline,
                    U8g2HAlign::Right,
                    FontColor::Transparent(BinaryColor::Off),
                    display,
                );

                // Render value left-aligned
                let _ = font.render_aligned(
                    value.as_str(),
                    Point::new(value_left_x, row_y),
                    VerticalPosition::Baseline,
                    U8g2HAlign::Left,
                    FontColor::Transparent(BinaryColor::Off),
                    display,
                );
            }
        } else {
            // Draw message text with word-wrapping, centered in text area
            TextBox::with_textbox_style(
                &self.message,
                text_bounds,
                message_char_style(),
                message_textbox_style(),
            )
            .draw(display)?;
        }

        // === BUTTONS: Centered on full display width at bottom ===
        let yes_button_width = self.yes_button.bounds.size.width.cast_signed();
        let no_button_width = self.no_button.bounds.size.width.cast_signed();
        let spacing = 20;
        let total_button_width = yes_button_width + no_button_width + spacing;
        let display_center_x = display_width / 2;
        let buttons_start_x = display_center_x - total_button_width / 2;

        // Update and draw YES button
        self.yes_button.bounds.top_left = Point::new(buttons_start_x, button_top_y);
        log::info!(
            "[Page id={}] draw: yes_button bounds={:?}",
            self.id,
            self.yes_button.bounds
        );
        self.yes_button.draw(display)?;

        // Update and draw NO button
        self.no_button.bounds.top_left =
            Point::new(buttons_start_x + yes_button_width + spacing, button_top_y);
        log::info!(
            "[Page id={}] draw: no_button bounds={:?}",
            self.id,
            self.no_button.bounds
        );
        self.no_button.draw(display)?;

        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        log::info!(
            "[Page id={}] handle_touch at {:?}, yes_bounds={:?}, no_bounds={:?}",
            self.id,
            point,
            self.yes_button.bounds,
            self.no_button.bounds
        );
        if self.yes_button.contains(point) {
            log::info!("[Page id={}] YES button pressed", self.id);
            let _ = self.app_sender.send(self.confirm_event.clone());
            true
        } else if self.no_button.contains(point) {
            log::info!("[Page id={}] NO/Cancel button pressed", self.id);
            let _ = self.app_sender.send(self.cancel_event.clone());
            true
        } else {
            log::info!("[Page id={}] Touch outside buttons", self.id);
            false
        }
    }
}
