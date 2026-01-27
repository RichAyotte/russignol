use crate::common::{BUFFER_SIZE, HEIGHT, Rotation, WIDTH};
use crate::display_driver::{DisplayMode, Epd2in13v4};
use crate::error::EpdResult;
use embedded_graphics::{
    geometry::Dimensions,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, OriginDimensions, Pixel, PointsIter, Size},
    primitives::Rectangle,
};

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
    partial_update_count: u8,
    rotation: Rotation,

    // For SSD1680 e-paper displays, it is recommended to perform a full update
    // every 10 partial updates or every 30 minutes to prevent ghosting and
    // maintain display quality.
    pub max_partial_updates: u8,
}

impl Display {
    #[must_use]
    pub fn new(driver: Epd2in13v4, rotation: Rotation) -> Self {
        let buffer: Box<[u8]> = vec![BinaryColor::On.as_byte(); BUFFER_SIZE].into_boxed_slice();
        Self {
            rotation,
            driver,
            buffer,
            partial_update_count: 0,
            max_partial_updates: 255,
        }
    }

    pub fn update(&mut self) -> EpdResult<()> {
        if self.partial_update_count >= self.max_partial_updates {
            self.partial_update_count = 0;
        }

        let mode = match self.partial_update_count {
            0 => DisplayMode::Full,
            _ => DisplayMode::Partial,
        };

        let result = self.driver.display(&self.buffer, mode);

        if result.is_ok() {
            self.partial_update_count += 1;
        }
        result
    }

    /// Force a full display update (not partial)
    pub fn update_full(&mut self) -> EpdResult<()> {
        self.partial_update_count = 0;
        self.update()
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
