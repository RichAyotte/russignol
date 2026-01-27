use crate::fonts;
use embedded_graphics::{
    Drawable,
    image::Image,
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle, RoundedRectangle},
};
use embedded_layout::View;
use tinybmp::Bmp;
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

#[derive(Clone)]
pub struct Button {
    pub text: Option<String>,
    pub bmp: Option<Bmp<'static, BinaryColor>>,
    pub bounds: Rectangle,
}

impl Button {
    #[must_use]
    pub fn new_text(size: Size, text: &str) -> Self {
        Self {
            bounds: Rectangle::new(Point::zero(), size),
            text: Some(text.to_string()),
            bmp: None,
        }
    }

    #[must_use]
    pub fn new_bmp(size: Size, bmp_data: &'static [u8]) -> Self {
        let bmp = Bmp::from_slice(bmp_data).unwrap();
        Self {
            bounds: Rectangle::new(Point::zero(), size),
            text: None,
            bmp: Some(bmp),
        }
    }

    #[must_use]
    pub fn contains(&self, point: Point) -> bool {
        self.bounds.contains(point)
    }
}

impl View for Button {
    fn bounds(&self) -> Rectangle {
        self.bounds
    }

    fn translate_impl(&mut self, by: Point) {
        self.bounds.top_left += by;
    }
}

impl Drawable for Button {
    type Color = BinaryColor;
    type Output = ();

    fn draw<D>(&self, display: &mut D) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Self::Color>,
    {
        let rect = self.bounds;
        let style = PrimitiveStyle::with_stroke(BinaryColor::Off, 1);
        let shape = RoundedRectangle::with_equal_corners(rect, Size::new(5, 5)).into_styled(style);

        shape.draw(display)?;

        if let Some(text) = &self.text {
            let font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
            font.render_aligned(
                text.as_str(),
                rect.center(),
                VerticalPosition::Center,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .map_err(|e| match e {
                u8g2_fonts::Error::DisplayError(e) => e,
                _ => panic!("unexpected error"),
            })?;
        } else if let Some(bmp) = &self.bmp {
            let image = Image::new(bmp, rect.center() - bmp.size() / 2);
            image.draw(display)?;
        }

        Ok(())
    }
}
