use crate::events::{AppEvent, BackTarget};
use crate::fonts;

use super::Page as PageTrait;
use crossbeam_channel::Sender;
use embedded_graphics::{image::Image, pixelcolor::BinaryColor, prelude::*, primitives::Rectangle};
use tinybmp::Bmp;
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
const LOGO_DATA: &[u8] = include_bytes!("../../assets/russignol-61h.bmp");

pub struct Page {
    app_sender: Sender<AppEvent>,
    /// Logo hit-box, set on each draw so a tap can open the Image screen.
    logo_bounds: Rectangle,
}

use super::{DISPLAY_HEIGHT, DISPLAY_WIDTH};

impl Page {
    pub fn new(app_sender: Sender<AppEvent>) -> Self {
        Self {
            app_sender,
            logo_bounds: Rectangle::new(Point::zero(), Size::zero()),
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let font_medium = FontRenderer::new::<fonts::FONT_MEDIUM>();
        let font_prop = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
        let font_small = FontRenderer::new::<fonts::FONT_SMALL>();

        // Left half: logo centered vertically
        let half_width = DISPLAY_WIDTH / 2;
        let logo_result: Result<Bmp<BinaryColor>, _> = Bmp::from_slice(LOGO_DATA);
        let logo_size = logo_result
            .as_ref()
            .map_or(Size::new(64, 64), |l| l.bounding_box().size);
        let logo_x = (half_width - logo_size.width.cast_signed()) / 2;
        let logo_y = (DISPLAY_HEIGHT - logo_size.height.cast_signed()) / 2;
        self.logo_bounds = Rectangle::new(Point::new(logo_x, logo_y), logo_size);
        if let Ok(logo) = logo_result {
            Image::new(&logo, Point::new(logo_x, logo_y)).draw(display)?;
        }

        // Right half: text block vertically centered
        let right_center = half_width + half_width / 2;
        let version_str = format!("v{VERSION}");

        // 3 lines: ~14px (prop) + 10px gap + ~10px (small) + 12px gap + ~13px (medium) ≈ 59px
        let block_top = (DISPLAY_HEIGHT - 59) / 2;

        font_prop
            .render_aligned(
                "Russignol",
                Point::new(right_center, block_top + 14),
                VerticalPosition::Baseline,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();

        font_small
            .render_aligned(
                version_str.as_str(),
                Point::new(right_center, block_top + 28),
                VerticalPosition::Baseline,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();

        font_medium
            .render_aligned(
                "russignol.com",
                Point::new(right_center, block_top + 46),
                VerticalPosition::Baseline,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();

        // Footer: copyright + license centered across full display width
        font_small
            .render_aligned(
                format!("\u{00a9} 2026 {AUTHOR} \u{00b7} MIT License").as_str(),
                Point::new(DISPLAY_WIDTH / 2, 116),
                VerticalPosition::Center,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();

        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        if self.logo_bounds.contains(point) {
            // Tapping the logo opens the Image screen; its Back returns here.
            let _ = self.app_sender.send(AppEvent::ShowImage {
                back: BackTarget::About,
            });
            true
        } else {
            let _ = self.app_sender.send(AppEvent::ShowMenu);
            false
        }
    }
}
