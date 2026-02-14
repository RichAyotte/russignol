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
use u8g2_fonts::{
    FontRenderer, U8g2TextStyle,
    types::{FontColor, HorizontalAlignment as U8g2HAlign, VerticalPosition},
};

static CONFIRMATION_PAGE_COUNTER: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

pub struct ConfirmationPage {
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

impl ConfirmationPage {
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
        log::info!("[ConfirmationPage] Creating new ConfirmationPage id={id}");
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
        log::info!("[ConfirmationPage] Creating new ConfirmationPage with pairs id={id}");
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

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for ConfirmationPage {
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

        // Layout constants
        let icon_margin = 10; // Margin around icon
        let text_margin = 5;
        let button_height = 40;
        let bottom_margin = 5;
        let icon_size = 21; // Streamline icons are 21x21

        // Split layout: narrow left column for icon, right side for text+buttons
        // Left column width: margin + icon + margin (doubled margin)
        let left_column_width = if self.show_alert_icon {
            icon_margin + icon_size + icon_margin
        } else {
            0
        };
        let right_start = left_column_width;
        let right_width = display_width - right_start - text_margin;

        // Position buttons fixed at the bottom of the right column
        let button_top_y = display_height - button_height - bottom_margin;

        // === RIGHT COLUMN: Text area above buttons ===
        let text_top = text_margin;
        let text_button_gap = 5;
        let text_height = button_top_y - text_top - text_button_gap;

        // === LEFT COLUMN: Icon (vertically centered with the 3-line text area) ===
        if self.show_alert_icon {
            let icon_font = u8g2_fonts::FontRenderer::new::<fonts::ICON_WARNING>();
            // Center icon vertically with the text area (not full display)
            let text_center_y = text_top + text_height / 2;
            let _ = icon_font.render_aligned(
                '0',
                Point::new(icon_margin + icon_size / 2, text_center_y),
                VerticalPosition::Center,
                U8g2HAlign::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            );
        }

        let text_bounds = Rectangle::new(
            Point::new(right_start, text_top),
            Size::new(right_width.cast_unsigned(), text_height.cast_unsigned()),
        );
        log::info!(
            "[ConfirmationPage id={}] text_bounds={:?}, message_len={}",
            self.id,
            text_bounds,
            self.message.len()
        );

        if let Some(ref pairs) = self.key_value_pairs {
            // Render title centered and key-value pairs with aligned columns
            let font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
            let line_height = 16; // Approximate height for Helvetica 12pt
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
            // Draw message text with automatic word-wrapping (original behavior)
            let character_style = U8g2TextStyle::new(fonts::FONT_PROPORTIONAL, BinaryColor::Off);
            let textbox_style = TextBoxStyleBuilder::new()
                .alignment(HorizontalAlignment::Center)
                .vertical_alignment(VerticalAlignment::Middle)
                .build();

            TextBox::with_textbox_style(&self.message, text_bounds, character_style, textbox_style)
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
            "[ConfirmationPage id={}] draw: yes_button bounds={:?}",
            self.id,
            self.yes_button.bounds
        );
        self.yes_button.draw(display)?;

        // Update and draw NO button
        self.no_button.bounds.top_left =
            Point::new(buttons_start_x + yes_button_width + spacing, button_top_y);
        log::info!(
            "[ConfirmationPage id={}] draw: no_button bounds={:?}",
            self.id,
            self.no_button.bounds
        );
        self.no_button.draw(display)?;

        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        log::info!(
            "[ConfirmationPage id={}] handle_touch at {:?}, yes_bounds={:?}, no_bounds={:?}",
            self.id,
            point,
            self.yes_button.bounds,
            self.no_button.bounds
        );
        if self.yes_button.contains(point) {
            log::info!("[ConfirmationPage id={}] YES button pressed", self.id);
            let _ = self.app_sender.send(self.confirm_event.clone());
            true
        } else if self.no_button.contains(point) {
            log::info!("[ConfirmationPage id={}] NO/Cancel button pressed", self.id);
            let _ = self.app_sender.send(self.cancel_event.clone());
            true
        } else {
            log::info!("[ConfirmationPage id={}] Touch outside buttons", self.id);
            false
        }
    }
}
