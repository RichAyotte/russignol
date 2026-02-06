//! Status page showing system information
//!
//! Displays version, chain info, keys, and network status.

use crate::chain_info;
use crate::events::AppEvent;
use crate::fonts;
use crate::network_status::NetworkStatus;
use crate::tezos_signer;

use super::Page;
use crossbeam_channel::Sender;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point, Primitive},
    primitives::{Line, PrimitiveStyle},
};
use russignol_signer_lib::signing_activity::SigningActivity;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use u8g2_fonts::FontRenderer;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Truncate a key hash for display
/// Shows first 8 and last 6 characters: "tz4Abcde...123456"
fn truncate_key(key: &str) -> String {
    if key.len() <= 17 {
        key.to_string()
    } else {
        format!("{}...{}", &key[..8], &key[key.len() - 6..])
    }
}

pub struct StatusPage {
    app_sender: Sender<AppEvent>,
    network_status: Arc<Mutex<NetworkStatus>>,
    // Cached values
    chain_name: String,
    chain_id: String,
    consensus_pkh: Option<String>,
    companion_pkh: Option<String>,
}

impl StatusPage {
    pub fn new(
        app_sender: Sender<AppEvent>,
        signing_activity: Arc<Mutex<SigningActivity>>,
    ) -> Self {
        // Load keys once at construction
        let keys = tezos_signer::get_keys();
        let consensus_pkh = keys
            .iter()
            .find(|k| k.name.contains("consensus"))
            .map(|k| k.value.clone());
        let companion_pkh = keys
            .iter()
            .find(|k| k.name.contains("companion"))
            .map(|k| k.value.clone());

        // Load chain info (created during first boot)
        let (chain_name, chain_id) = match chain_info::read_chain_info() {
            Ok(info) => (info.name, info.id),
            Err(e) => {
                log::error!("Failed to read chain info: {e} - using defaults");
                ("Unknown".to_string(), "Unknown".to_string())
            }
        };

        // Seed with a fast interface check so the first draw shows "Offline" vs
        // "No Host" correctly. The slow ping runs on the background thread.
        let initial = NetworkStatus {
            interface_configured: crate::network_status::check_interface_configured(),
            ..NetworkStatus::default()
        };
        let network_status = Arc::new(Mutex::new(initial));

        // Spawn background thread to check network status periodically.
        // The thread holds a Weak ref to network_status — when StatusPage drops
        // (page navigation, dialog overlay, etc.), the Weak fails to upgrade
        // and the thread exits on its own.
        let ns_weak = Arc::downgrade(&network_status);
        let tx = app_sender.clone();
        std::thread::spawn(move || {
            loop {
                let Some(ns) = ns_weak.upgrade() else {
                    return;
                };

                let last_sig_time = signing_activity.lock().ok().and_then(|activity| {
                    let ct = activity.consensus.as_ref().map(|c| c.timestamp);
                    let cpt = activity.companion.as_ref().map(|c| c.timestamp);
                    match (ct, cpt) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (Some(t), None) | (None, Some(t)) => Some(t),
                        (None, None) => None,
                    }
                });

                let status = NetworkStatus::check(last_sig_time);
                if let Ok(mut guard) = ns.lock() {
                    *guard = status;
                }
                // Drop the strong ref before sleeping so StatusPage can be dropped mid-sleep
                drop(ns);

                let _ = tx.send(AppEvent::DirtyDisplay);
                std::thread::sleep(Duration::from_secs(1));
            }
        });

        Self {
            app_sender,
            network_status,
            chain_name,
            chain_id,
            consensus_pkh,
            companion_pkh,
        }
    }
}

// Layout constants for 250x122 display
const MARGIN: i32 = 3;
const DISPLAY_WIDTH: i32 = 250;
const ROW_1: i32 = 18;
const LINE_Y: i32 = 28;
const CONTENT_ROW_1: i32 = 45;
const CONTENT_ROW_2: i32 = 65;
const CONTENT_ROW_3: i32 = 87;
const CONTENT_ROW_4: i32 = 109;
const ICON_GAP: i32 = 8;

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for StatusPage {
    fn handle_touch(&mut self, _point: Point) {
        let _ = self.app_sender.send(AppEvent::ShowSignatures);
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let network_status = self
            .network_status
            .lock()
            .map_or_else(|e| *e.into_inner(), |guard| *guard);

        draw_header(display, network_status);
        draw_separator(display)?;
        draw_chain_info(display, &self.chain_name, &self.chain_id);
        draw_key_row(display, self.consensus_pkh.as_ref(), "1", CONTENT_ROW_3);
        draw_key_row(display, self.companion_pkh.as_ref(), "0", CONTENT_ROW_4);

        Ok(())
    }
}

fn draw_header<D: DrawTarget<Color = BinaryColor>>(display: &mut D, network_status: NetworkStatus) {
    let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

    let version_str = format!("Russignol v{VERSION}");
    font.render_aligned(
        version_str.as_str(),
        Point::new(MARGIN, ROW_1),
        u8g2_fonts::types::VerticalPosition::Baseline,
        u8g2_fonts::types::HorizontalAlignment::Left,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    )
    .ok();

    let status_str = if !network_status.interface_configured {
        "Offline"
    } else if !network_status.host_reachable {
        "No Host"
    } else if network_status.baker_active {
        "Active"
    } else {
        "Ready"
    };
    font.render_aligned(
        status_str,
        Point::new(DISPLAY_WIDTH - MARGIN, ROW_1),
        u8g2_fonts::types::VerticalPosition::Baseline,
        u8g2_fonts::types::HorizontalAlignment::Right,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    )
    .ok();
}

fn draw_separator<D: DrawTarget<Color = BinaryColor>>(display: &mut D) -> Result<(), D::Error> {
    Line::new(
        Point::new(MARGIN, LINE_Y),
        Point::new(DISPLAY_WIDTH - MARGIN, LINE_Y),
    )
    .into_styled(PrimitiveStyle::with_stroke(BinaryColor::Off, 1))
    .draw(display)
}

fn draw_chain_info<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    chain_name: &str,
    chain_id: &str,
) {
    let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

    font.render_aligned(
        chain_name,
        Point::new(DISPLAY_WIDTH / 2, CONTENT_ROW_1),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Center,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    )
    .ok();

    font.render_aligned(
        chain_id,
        Point::new(DISPLAY_WIDTH / 2, CONTENT_ROW_2),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Center,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    )
    .ok();
}

fn draw_key_row<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    pkh: Option<&String>,
    icon_char: &str,
    row_y: i32,
) {
    let font = FontRenderer::new::<fonts::FONT_MEDIUM>();
    let icon_font = FontRenderer::new::<fonts::ICON_KEY>();

    let key_display = pkh.map_or_else(|| "Not found".to_string(), |k| truncate_key(k));

    let icon_width = icon_font
        .get_rendered_dimensions(
            icon_char,
            Point::zero(),
            u8g2_fonts::types::VerticalPosition::Center,
        )
        .ok()
        .and_then(|d| d.bounding_box.map(|b| b.size.width.cast_signed()))
        .unwrap_or(16);

    let text_width = font
        .get_rendered_dimensions(
            key_display.as_str(),
            Point::zero(),
            u8g2_fonts::types::VerticalPosition::Center,
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
            u8g2_fonts::types::VerticalPosition::Center,
            u8g2_fonts::types::HorizontalAlignment::Left,
            u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

    font.render_aligned(
        key_display.as_str(),
        Point::new(text_x, row_y),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Left,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    )
    .ok();
}
