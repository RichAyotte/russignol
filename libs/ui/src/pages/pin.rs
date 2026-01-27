//! PIN entry page with numeric keypad
//!
//! This page provides a numeric keypad for PIN entry, supporting
//! create, confirm, and verify modes.

use crate::{fonts, widgets::Button};
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{Circle, PrimitiveStyle},
};
use embedded_layout::{
    layout::linear::{FixedMargin, LinearLayout},
    prelude::*,
};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

const BACKSPACE_ICON: &[u8] = include_bytes!("../../assets/backspace.bmp");
const CLEAR_ICON: &[u8] = include_bytes!("../../assets/clear.bmp");

/// Minimum PIN length (5 digits = ~17 bits entropy)
pub const MIN_PIN_LENGTH: usize = 5;
/// Maximum PIN length
pub const MAX_PIN_LENGTH: usize = 10;

/// PIN entry mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinMode {
    /// Creating a new PIN (first entry)
    Create,
    /// Confirming the PIN (second entry during creation)
    Confirm,
    /// Verifying an existing PIN
    Verify,
}

/// Events emitted by the PIN page
#[derive(Clone, Debug)]
pub enum PinEvent {
    /// PIN entered (first entry during creation)
    FirstPinEntered(Vec<u8>),
    /// PIN entered (confirmation or verification)
    PinEntered(Vec<u8>),
    /// PIN too short (during creation/confirmation)
    PinTooShort,
    /// Request display refresh
    DirtyDisplay,
}

/// Generic PIN entry page
///
/// Uses a callback to emit events, making it usable across different applications.
pub struct PinPage<F: FnMut(PinEvent)> {
    buttons: [Button; 13],
    pin: Vec<u8>,
    title: String,
    mode: PinMode,
    on_event: F,
}

impl<F: FnMut(PinEvent)> PinPage<F> {
    /// Create a new PIN page
    ///
    /// - `title`: Title shown above the PIN dots (e.g., "Enter\n PIN" or "Create\nnew PIN")
    /// - `mode`: Whether this is creation, confirmation, or verification
    /// - `on_event`: Callback invoked when events occur
    pub fn new(title: &str, mode: PinMode, on_event: F) -> Self {
        let std_size = Size::new(40, 40);
        let wide_size = Size::new(82, 40);

        let buttons = [
            // Row 1
            Button::new_text(std_size, "1"),
            Button::new_text(std_size, "2"),
            Button::new_text(std_size, "3"),
            Button::new_text(std_size, "4"),
            // Row 2
            Button::new_text(std_size, "5"),
            Button::new_text(std_size, "6"),
            Button::new_text(std_size, "7"),
            Button::new_text(std_size, "8"),
            // Row 3
            Button::new_text(wide_size, "Enter"),
            Button::new_text(std_size, "9"),
            Button::new_text(std_size, "0"),
            Button::new_bmp(std_size, BACKSPACE_ICON),
            Button::new_bmp(std_size, CLEAR_ICON),
        ];

        Self {
            buttons,
            pin: Vec::new(),
            title: title.to_string(),
            mode,
            on_event,
        }
    }

    /// Get the current PIN mode
    pub fn mode(&self) -> PinMode {
        self.mode
    }
}

impl<F, D> super::Page<D> for PinPage<F>
where
    F: FnMut(PinEvent),
    D: DrawTarget<Color = BinaryColor>,
{
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let button_width = 40;
        let h_space = 2;
        let v_space = 1;

        // Draw Title and PIN dots
        let title_font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
        title_font
            .render_aligned(
                self.title.as_str(),
                Point::new(41, 25),
                VerticalPosition::Center,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .map_err(|e| match e {
                u8g2_fonts::Error::DisplayError(e) => e,
                _ => panic!("unexpected error"),
            })?;

        if !self.pin.is_empty() {
            let circle_style = PrimitiveStyle::with_fill(BinaryColor::Off);
            let mut circles: Vec<_> = (0..self.pin.len())
                .map(|_| Circle::new(Point::zero(), 8).into_styled(circle_style))
                .collect();

            let circles_per_line = 5;
            let line_height = 18;
            let start_pos = Point::new(10, 45);

            for (i, chunk) in circles.chunks_mut(circles_per_line).enumerate() {
                let mut row_layout = LinearLayout::horizontal(Views::new(chunk))
                    .with_spacing(FixedMargin(5))
                    .with_alignment(vertical::Center)
                    .arrange();

                let row_pos = start_pos + Point::new(0, i32::try_from(i * line_height).unwrap());
                row_layout.translate_mut(row_pos).draw(display)?;
            }
        }

        // Draw Button Grid
        let row_1_y = 0;
        let row_2_y = button_width + v_space;
        let row_3_y = 2 * (button_width + v_space);
        let top_rows_x_offset = 2 * button_width + 2 * h_space;

        // Row 1: 4 buttons
        let mut row_1_layout = LinearLayout::horizontal(Views::new(&mut self.buttons[0..4]))
            .with_spacing(FixedMargin(h_space))
            .arrange();
        row_1_layout
            .translate_mut(Point::new(top_rows_x_offset, row_1_y))
            .draw(display)?;

        // Row 2: 4 buttons
        let mut row_2_layout = LinearLayout::horizontal(Views::new(&mut self.buttons[4..8]))
            .with_spacing(FixedMargin(h_space))
            .arrange();
        row_2_layout
            .translate_mut(Point::new(top_rows_x_offset, row_2_y))
            .draw(display)?;

        // Row 3: 5 buttons
        let mut row_3_layout = LinearLayout::horizontal(Views::new(&mut self.buttons[8..13]))
            .with_spacing(FixedMargin(h_space))
            .arrange();
        row_3_layout
            .translate_mut(Point::new(0, row_3_y))
            .draw(display)?;

        Ok(())
    }

    fn handle_touch(&mut self, point: Point) {
        for (i, button) in self.buttons.iter().enumerate() {
            if button.contains(point) {
                match i {
                    11 => {
                        // Backspace
                        self.pin.pop();
                        (self.on_event)(PinEvent::DirtyDisplay);
                    }
                    12 => {
                        // Clear
                        self.pin.clear();
                        (self.on_event)(PinEvent::DirtyDisplay);
                    }
                    _ => {
                        if let Some(text) = &button.text {
                            match text.as_str() {
                                "Enter" => {
                                    let is_too_short = self.pin.len() < MIN_PIN_LENGTH;
                                    let is_creation =
                                        matches!(self.mode, PinMode::Create | PinMode::Confirm);

                                    if is_too_short && is_creation {
                                        (self.on_event)(PinEvent::PinTooShort);
                                        self.pin.clear();
                                    } else {
                                        let event = match self.mode {
                                            PinMode::Create => {
                                                PinEvent::FirstPinEntered(self.pin.clone())
                                            }
                                            PinMode::Confirm | PinMode::Verify => {
                                                PinEvent::PinEntered(self.pin.clone())
                                            }
                                        };
                                        (self.on_event)(event);
                                        self.pin.clear();
                                    }
                                }
                                _ => {
                                    if let Ok(digit) = text.parse::<u8>()
                                        && self.pin.len() < MAX_PIN_LENGTH
                                    {
                                        self.pin.push(digit);
                                        (self.on_event)(PinEvent::DirtyDisplay);
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
    }
}
