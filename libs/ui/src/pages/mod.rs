use embedded_graphics::{
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point},
};

pub mod error;
pub mod pin;
pub mod progress;

pub use error::ErrorPage;
pub use pin::{MAX_PIN_LENGTH, MIN_PIN_LENGTH, PinEvent, PinMode, PinPage};
pub use progress::ProgressPage;

/// Trait for UI pages that can be drawn on a display
pub trait Page<D: DrawTarget<Color = BinaryColor>> {
    /// Draw the page content to the display
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error>;

    /// Handle a touch event at the given point.
    /// Returns `true` if the touch was consumed by an interactive element (button),
    /// `false` if the touch landed on empty space.
    fn handle_touch(&mut self, _point: Point) -> bool {
        false
    }

    /// Clear the display and draw the page (convenience method)
    fn show(&mut self, display: &mut D) -> Result<(), D::Error> {
        display.clear(BinaryColor::On)?;
        self.draw(display)
    }

    /// Returns true if this page is modal (requires user input before it can be dismissed).
    /// Modal pages cannot be replaced by external events - only user interaction can dismiss them.
    fn is_modal(&self) -> bool {
        false
    }
}
