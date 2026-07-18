use crate::common::{BUFFER_SIZE, HEIGHT, Rotation, WIDTH};
use crate::display_driver::{Epd2in13v4, PushOutcome, WaitPolicy};
use crate::error::EpdResult;
use crate::refresh_policy::{self, RefreshAction, RefreshOpportunity};
use embedded_graphics::{
    geometry::Dimensions,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, OriginDimensions, Pixel, PointsIter, Size},
    primitives::Rectangle,
};

/// Outcome of a non-blocking update attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The frame was pushed, or the policy decided no push was needed.
    Done,
    /// The panel is mid-refresh; nothing was pushed or recorded — retry later.
    Busy,
}

pub trait AsFillByte {
    fn as_byte(&self) -> u8;
}

impl AsFillByte for BinaryColor {
    fn as_byte(&self) -> u8 {
        if self.is_on() { 0xFF } else { 0x00 }
    }
}

pub struct Display {
    driver: Epd2in13v4,
    buffer: Box<[u8]>,
    partials_since_full: u16,
    has_ever_pushed: bool,
    rotation: Rotation,
}

impl Display {
    #[must_use]
    pub fn new(driver: Epd2in13v4, rotation: Rotation) -> Self {
        let buffer: Box<[u8]> = vec![BinaryColor::On.as_byte(); BUFFER_SIZE].into_boxed_slice();
        Self {
            rotation,
            driver,
            buffer,
            partials_since_full: 0,
            has_ever_pushed: false,
        }
    }

    /// Repaint the page already on screen. Skips the push when the frame is
    /// unchanged; never performs a full refresh after the boot push.
    ///
    /// # Errors
    ///
    /// Returns an error if the display driver fails to update.
    pub fn update(&mut self) -> EpdResult<()> {
        self.push(RefreshOpportunity::InPlace, WaitPolicy::Block)
            .map(|_| ())
    }

    /// Non-blocking [`Self::update`]: defers instead of waiting when the
    /// panel is mid-refresh, leaving all state untouched for the retry.
    ///
    /// # Errors
    ///
    /// Returns an error if the display driver fails to update.
    pub fn try_update(&mut self) -> EpdResult<UpdateOutcome> {
        self.push(RefreshOpportunity::InPlace, WaitPolicy::Bail)
    }

    /// Repaint for a page transition. Performs an anti-ghosting full refresh
    /// when enough partial updates have accumulated.
    ///
    /// # Errors
    ///
    /// Returns an error if the display driver fails to update.
    pub fn update_transition(&mut self) -> EpdResult<()> {
        self.push(RefreshOpportunity::Transition, WaitPolicy::Block)
            .map(|_| ())
    }

    /// Non-blocking [`Self::update_transition`]: defers instead of waiting
    /// when the panel is mid-refresh, leaving all state untouched for the
    /// retry.
    ///
    /// # Errors
    ///
    /// Returns an error if the display driver fails to update.
    pub fn try_update_transition(&mut self) -> EpdResult<UpdateOutcome> {
        self.push(RefreshOpportunity::Transition, WaitPolicy::Bail)
    }

    /// Force a full display update (not partial)
    ///
    /// # Errors
    ///
    /// Returns an error if the display driver fails to update.
    pub fn update_full(&mut self) -> EpdResult<()> {
        self.push(RefreshOpportunity::ForcedFull, WaitPolicy::Block)
            .map(|_| ())
    }

    fn push(
        &mut self,
        opportunity: RefreshOpportunity,
        policy: WaitPolicy,
    ) -> EpdResult<UpdateOutcome> {
        let decision = refresh_policy::decide(
            self.driver.frame_differs(&self.buffer),
            self.has_ever_pushed,
            self.partials_since_full,
            opportunity,
        );
        if let RefreshAction::Push(mode) = decision.action {
            if self
                .driver
                .display_with_policy(&self.buffer, mode, policy)?
                == PushOutcome::Busy
            {
                return Ok(UpdateOutcome::Busy);
            }
            self.has_ever_pushed = true;
        }
        self.partials_since_full = decision.partials_since_full;
        Ok(UpdateOutcome::Done)
    }

    pub(crate) fn sleep(&mut self) -> EpdResult<()> {
        self.driver.sleep()
    }

    pub(crate) fn wake(&mut self) -> EpdResult<()> {
        self.driver.wake()
    }
}

impl DrawTarget for Display {
    type Color = BinaryColor;
    type Error = crate::error::Error;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let Size { width, height } = self.size();
        let row_pitch_bytes = WIDTH.div_ceil(8);

        for Pixel(coord, color) in pixels {
            let (orig_x, orig_y) = coord.into();

            if orig_x < 0
                || orig_x >= width.cast_signed()
                || orig_y < 0
                || orig_y >= height.cast_signed()
            {
                continue;
            }

            let (x, y) = match self.rotation {
                Rotation::Deg0 => (orig_x, orig_y),
                Rotation::Deg90 => (WIDTH.cast_signed() - 1 - orig_y, orig_x),
            };

            if !(0..WIDTH.cast_signed()).contains(&x) || !(0..HEIGHT.cast_signed()).contains(&y) {
                continue;
            }

            let index = (y.cast_unsigned() * row_pitch_bytes + x.cast_unsigned() / 8) as usize;
            let bit = 7 - (x % 8);

            if color.is_on() {
                self.buffer[index] |= 1 << bit;
            } else {
                self.buffer[index] &= !(1 << bit);
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        let clipped_area = area.intersection(&self.bounding_box());

        if clipped_area.is_zero_sized() {
            return Ok(());
        }

        self.draw_iter(clipped_area.points().map(|p| Pixel(p, color)))
    }

    fn clear(&mut self, color: BinaryColor) -> Result<(), Self::Error> {
        self.buffer.fill(color.as_byte());
        Ok(())
    }
}

impl OriginDimensions for Display {
    fn size(&self) -> Size {
        match self.rotation {
            Rotation::Deg0 => Size::new(WIDTH, HEIGHT),
            Rotation::Deg90 => Size::new(HEIGHT, WIDTH),
        }
    }
}
