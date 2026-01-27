use super::Page;
use crate::fonts;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point, Primitive, Size},
    primitives::{PrimitiveStyle, Rectangle},
};
use std::time::{Duration, Instant};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

/// Progress bar dimensions
const PROGRESS_BAR_WIDTH: u32 = 200;
const PROGRESS_BAR_HEIGHT: u32 = 16;

/// Target duration per frame in milliseconds for smooth animation
const TARGET_FRAME_DURATION_MS: u64 = 600;

/// Progress mode determines how the progress bar advances
enum ProgressMode {
    /// Manual control - caller sets percentage directly via `set_progress()`
    Manual,
    /// Time-based auto-advance - bar fills over estimated duration
    Timed {
        estimated_duration: Duration,
        start_time: Instant,
    },
}

/// `ProgressPage` displays a message with a progress bar.
///
/// Supports two modes:
/// - **Manual mode** (`new()`): Call `set_progress()` to update the percentage
/// - **Timed mode** (`new_timed()`): Progress auto-advances based on elapsed time
pub struct ProgressPage {
    message: String,
    percent: u8,
    mode: ProgressMode,
    is_modal: bool,
}

impl ProgressPage {
    /// Create a manually-controlled progress bar
    ///
    /// Use `set_progress()` to update the message and percentage.
    #[must_use]
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            percent: 0,
            mode: ProgressMode::Manual,
            is_modal: false,
        }
    }

    /// Create a time-based auto-advancing progress bar
    ///
    /// The progress bar will reach 100% after approximately `estimated_duration`.
    /// Call `draw()` periodically (use `animation_interval()` for timing) to update.
    #[must_use]
    pub fn new_timed(message: &str, estimated_duration: Duration) -> Self {
        Self {
            message: message.to_string(),
            percent: 0,
            mode: ProgressMode::Timed {
                estimated_duration,
                start_time: Instant::now(),
            },
            is_modal: false,
        }
    }

    /// Set whether this page is modal (cannot be dismissed by external events)
    #[must_use]
    pub fn with_modal(mut self, modal: bool) -> Self {
        self.is_modal = modal;
        self
    }

    /// Update the progress message and percentage (manual mode only)
    pub fn set_progress(&mut self, message: &str, percent: u8) {
        self.message = message.to_string();
        self.percent = percent.min(100);
    }

    /// Get current progress percentage
    #[must_use]
    pub fn percent(&self) -> u8 {
        self.percent
    }

    /// Returns the recommended interval between `draw()` calls for timed mode
    ///
    /// In manual mode, returns 1 second (animation not typically needed).
    #[must_use]
    pub fn animation_interval(&self) -> Duration {
        match &self.mode {
            ProgressMode::Manual => Duration::from_secs(1),
            ProgressMode::Timed {
                estimated_duration, ..
            } => {
                // Target ~600ms per frame, minimum 3 updates, maximum 100
                let num_frames = (u64::try_from(estimated_duration.as_millis())
                    .unwrap_or(u64::MAX)
                    / TARGET_FRAME_DURATION_MS)
                    .clamp(3, 100);
                // Safe: clamp ensures value is 3-100, which fits in u32
                let num_frames = u32::try_from(num_frames).unwrap_or(100);
                *estimated_duration / num_frames
            }
        }
    }

    /// Check if the progress has reached 100%
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.percent >= 100
    }
}

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for ProgressPage {
    fn is_modal(&self) -> bool {
        self.is_modal
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        // Auto-calculate percent for timed mode
        if let ProgressMode::Timed {
            estimated_duration,
            start_time,
        } = &self.mode
        {
            let elapsed = start_time.elapsed();
            // Calculate percentage, capped at 100
            let pct = elapsed.as_millis().saturating_mul(100) / estimated_duration.as_millis();
            // Safe: min(100) ensures value fits in u8
            self.percent = u8::try_from(pct.min(100)).unwrap_or(100);
        }

        let font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
        let display_bounds = display.bounding_box();
        let display_center = display_bounds.center();
        let display_height = display_bounds.size.height.cast_signed();

        // Layout for 250x122 display with even vertical spacing:
        // - Text height ~12px, bar height 16px, percent text ~12px
        // - Total content height: 12 + gap + 16 + gap + 12 = 40 + 2*gap
        // - With gap=12: total = 64px, margins = (122-64)/2 = 29px each
        let text_height = 12;
        let gap = 12;
        let top_margin = (display_height
            - (text_height + gap + PROGRESS_BAR_HEIGHT.cast_signed() + gap + text_height))
            / 2;

        let message_y = top_margin + text_height; // baseline position
        let bar_y = message_y + gap;
        let percent_y = bar_y + PROGRESS_BAR_HEIGHT.cast_signed() + gap + text_height;

        // Draw message text
        font.render_aligned(
            self.message.as_str(),
            Point::new(display_center.x, message_y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .map_err(|e| match e {
            u8g2_fonts::Error::DisplayError(e) => e,
            _ => panic!("unexpected font rendering error"),
        })?;

        // Calculate progress bar position (centered horizontally)
        let bar_x = display_center.x - (PROGRESS_BAR_WIDTH.cast_signed() / 2);

        // Draw progress bar outline
        let outline_rect = Rectangle::new(
            Point::new(bar_x, bar_y),
            Size::new(PROGRESS_BAR_WIDTH, PROGRESS_BAR_HEIGHT),
        );
        let outline_style = PrimitiveStyle::with_stroke(BinaryColor::Off, 1);
        outline_rect.into_styled(outline_style).draw(display)?;

        // Draw filled portion of progress bar
        if self.percent > 0 {
            let fill_width = (PROGRESS_BAR_WIDTH - 4) * u32::from(self.percent) / 100;
            if fill_width > 0 {
                let fill_rect = Rectangle::new(
                    Point::new(bar_x + 2, bar_y + 2),
                    Size::new(fill_width, PROGRESS_BAR_HEIGHT - 4),
                );
                let fill_style = PrimitiveStyle::with_fill(BinaryColor::Off);
                fill_rect.into_styled(fill_style).draw(display)?;
            }
        }

        // Draw percentage text below progress bar
        let percent_text = format!("{}%", self.percent);
        font.render_aligned(
            percent_text.as_str(),
            Point::new(display_center.x, percent_y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .map_err(|e| match e {
            u8g2_fonts::Error::DisplayError(e) => e,
            _ => panic!("unexpected font rendering error"),
        })?;

        Ok(())
    }
}
