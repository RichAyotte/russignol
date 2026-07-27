use crate::chain_info;
use crate::events::AppEvent;
use crate::fonts;
use crate::tezos_signer;

use super::Page as PageTrait;
use crossbeam_channel::Sender;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point, Primitive},
    primitives::{Line, PrimitiveStyle},
};
use russignol_signer_lib::KeyRole;
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

pub struct Page {
    app_sender: Sender<AppEvent>,
    chain_name: String,
    chain_id: String,
    /// Pkh per role ([`KeyRole::ALL`] order).
    pkh_by_role: [Option<String>; KeyRole::COUNT],
}

use super::DISPLAY_WIDTH;
const MARGIN: i32 = 3;
const TITLE_Y: i32 = 18;
const LINE_Y: i32 = 26;
const CHAIN_NAME_Y: i32 = 44;
const CHAIN_ID_Y: i32 = 62;
const ICON_GAP: i32 = 8;

/// Baseline Y of the key row for a role.
const fn key_row_y(role: KeyRole) -> i32 {
    match role {
        KeyRole::Consensus => 84,
        KeyRole::Companion => 108,
    }
}

impl Page {
    pub fn new(app_sender: Sender<AppEvent>) -> Self {
        let keys = tezos_signer::get_keys();
        let pkh_by_role = KeyRole::map_all(|role| {
            keys.iter()
                .find(|k| k.name == role.device_alias())
                .map(|k| k.value.clone())
        });

        let (chain_name, chain_id) = match chain_info::read_chain_info() {
            Ok(info) => (info.name, info.id),
            Err(e) => {
                log::error!("Failed to read chain info: {e} - using defaults");
                ("Unknown".to_string(), "Unknown".to_string())
            }
        };

        Self {
            app_sender,
            chain_name,
            chain_id,
            pkh_by_role,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

        // Title
        font.render_aligned(
            "Tezos Blockchain",
            Point::new(DISPLAY_WIDTH / 2, TITLE_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

        // Separator
        Line::new(
            Point::new(MARGIN, LINE_Y),
            Point::new(DISPLAY_WIDTH - MARGIN, LINE_Y),
        )
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::Off, 1))
        .draw(display)?;

        // Chain name
        font.render_aligned(
            self.chain_name.as_str(),
            Point::new(DISPLAY_WIDTH / 2, CHAIN_NAME_Y),
            VerticalPosition::Center,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

        // Chain ID
        font.render_aligned(
            self.chain_id.as_str(),
            Point::new(DISPLAY_WIDTH / 2, CHAIN_ID_Y),
            VerticalPosition::Center,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

        // Key rows in KeyRole::ALL order
        for role in KeyRole::ALL {
            draw_key_row(
                display,
                self.pkh_by_role[role.index()].as_deref(),
                super::key_icon(role),
                key_row_y(role),
            );
        }

        Ok(())
    }

    fn handle_touch(&mut self, _point: Point) -> bool {
        let _ = self.app_sender.send(AppEvent::ShowMenu);
        false
    }
}

fn draw_key_row<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    pkh: Option<&str>,
    icon_char: &str,
    row_y: i32,
) {
    let text_font = FontRenderer::new::<fonts::FONT_MONO_SMALL>();
    let icon_font = FontRenderer::new::<fonts::ICON_KEY>();

    let key_display = pkh.map_or_else(
        || "Not found".to_string(),
        |key| crate::text::truncate_middle(key, 10, 6),
    );

    let icon_width = icon_font
        .get_rendered_dimensions(icon_char, Point::zero(), VerticalPosition::Center)
        .ok()
        .and_then(|d| d.bounding_box.map(|b| b.size.width.cast_signed()))
        .unwrap_or(16);

    let text_width = text_font
        .get_rendered_dimensions(
            key_display.as_str(),
            Point::zero(),
            VerticalPosition::Center,
        )
        .ok()
        .and_then(|d| d.bounding_box.map(|b| b.size.width.cast_signed()))
        .unwrap_or(0);

    let total_width = icon_width + ICON_GAP + text_width;
    let icon_x = (DISPLAY_WIDTH - total_width) / 2;
    let text_x = icon_x + icon_width + ICON_GAP;

    icon_font
        .render_aligned(
            icon_char,
            Point::new(icon_x, row_y),
            VerticalPosition::Center,
            HorizontalAlignment::Left,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

    text_font
        .render_aligned(
            key_display.as_str(),
            Point::new(text_x, row_y),
            VerticalPosition::Center,
            HorizontalAlignment::Left,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();
}
