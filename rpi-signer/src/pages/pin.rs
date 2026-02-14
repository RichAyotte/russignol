use super::Page;
use crate::{events::AppEvent, fonts, widgets::Button};
use crossbeam_channel::Sender;
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

/// Maximum PIN length
const MAX_PIN_LENGTH: usize = 10;

/// Minimum PIN length (5 digits = ~17 bits entropy)
const MIN_PIN_LENGTH: usize = 5;

/// PIN mode
#[derive(Clone, Copy, PartialEq)]
pub enum PinMode {
    /// Create new PIN (first entry during setup)
    Create,
    /// Confirm PIN (second entry during setup)
    Confirm,
    /// Verify existing PIN (normal operation)
    Verify,
}

pub struct PinPage {
    buttons: [Button; 13],
    pin: Vec<u8>,
    title: String,
    mode: PinMode,
    app_sender: Sender<AppEvent>,
}

impl PinPage {
    pub fn new(app_sender: Sender<AppEvent>, title: &str, mode: PinMode) -> Self {
        let std_size = Size::new(40, 40);
        let wide_size = Size::new(82, 40); // 2 * 40px + 2px gap

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
            Button::new_bmp(std_size, BACKSPACE_ICON), // Backspace
            Button::new_bmp(std_size, CLEAR_ICON),     // Clear
        ];

        Self {
            buttons,
            pin: Vec::new(),
            title: title.to_string(),
            mode,
            app_sender,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for PinPage {
    fn is_modal(&self) -> bool {
        true
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let button_width = 40;
        let h_space = 2;
        let v_space = 1;

        // --- Draw Title and PIN dots in Empty Space ---
        let title_font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
        title_font
            .render_aligned(
                self.title.as_str(),
                Point::new(41, 25), // Center of the top half of the 82x81 empty block
                VerticalPosition::Center,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok(); // Ignore font errors (BackgroundColorNotSupported can't happen with Transparent)

        if !self.pin.is_empty() {
            let circle_style = PrimitiveStyle::with_fill(BinaryColor::Off);
            let mut circles: Vec<_> = (0..self.pin.len())
                .map(|_| Circle::new(Point::zero(), 8).into_styled(circle_style))
                .collect();

            let circles_per_line = 5;
            let line_height = 18; // Circle diameter is 16px
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

        // --- Draw Button Grid ---
        let row_1_y = 0;
        let row_2_y = button_width + v_space;
        let row_3_y = 2 * (button_width + v_space);

        // Rows 1 & 2 start at column 3
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

        // Row 3: 5 buttons (1 wide, 4 standard)
        let mut row_3_layout = LinearLayout::horizontal(Views::new(&mut self.buttons[8..13]))
            .with_spacing(FixedMargin(h_space))
            .arrange();
        row_3_layout
            .translate_mut(Point::new(0, row_3_y))
            .draw(display)?;

        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        for (i, button) in self.buttons.iter().enumerate() {
            if button.contains(point) {
                match i {
                    11 => {
                        // Backspace
                        self.pin.pop();
                        if self.app_sender.send(AppEvent::DirtyDisplay).is_err() {
                            log::error!("Could not send AppEvent::DirtyDisplay");
                        }
                    }
                    12 => {
                        // Clear
                        self.pin.clear();
                        if self.app_sender.send(AppEvent::DirtyDisplay).is_err() {
                            log::error!("Could not send AppEvent::DirtyDisplay");
                        }
                    }
                    _ => {
                        // Text buttons
                        if let Some(text) = &button.text {
                            match text.as_str() {
                                "Enter" => {
                                    match self.mode {
                                        PinMode::Create => {
                                            // During creation, enforce minimum length
                                            if self.pin.len() >= MIN_PIN_LENGTH {
                                                if self
                                                    .app_sender
                                                    .send(AppEvent::FirstPinEntered(
                                                        self.pin.clone(),
                                                    ))
                                                    .is_err()
                                                {
                                                    log::error!(
                                                        "Could not send FirstPinEntered event"
                                                    );
                                                }
                                            } else {
                                                log::warn!(
                                                    "PIN too short (min {MIN_PIN_LENGTH} digits)"
                                                );
                                            }
                                            self.pin.clear();
                                        }
                                        PinMode::Confirm | PinMode::Verify => {
                                            // During confirm/verify, let short PINs fail
                                            // so they count toward the bad PIN limit.
                                            if self
                                                .app_sender
                                                .send(AppEvent::PinEntered(self.pin.clone()))
                                                .is_err()
                                            {
                                                log::error!("Could not send PIN event");
                                            }
                                            self.pin.clear();
                                        }
                                    }
                                }
                                _ => {
                                    if let Ok(digit) = text.parse::<u8>() {
                                        if self.pin.len() < MAX_PIN_LENGTH {
                                            self.pin.push(digit);
                                            if self.app_sender.send(AppEvent::DirtyDisplay).is_err()
                                            {
                                                log::error!(
                                                    "PIN could not send AppEvent::DirtyDisplay"
                                                );
                                            }
                                        } else {
                                            log::warn!("PIN buffer full");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return true;
            }
        }
        false
    }
}
