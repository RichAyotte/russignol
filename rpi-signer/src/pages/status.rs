use crate::events::AppEvent;
use crate::fonts;
use crate::network_status::NetworkStatus;

use super::Page as PageTrait;
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
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

pub struct Page {
    app_sender: Sender<AppEvent>,
    network_status: Arc<Mutex<Option<NetworkStatus>>>,
    signing_activity: Arc<Mutex<SigningActivity>>,
}

impl Page {
    pub fn new(
        app_sender: Sender<AppEvent>,
        signing_activity: Arc<Mutex<SigningActivity>>,
    ) -> Self {
        let network_status: Arc<Mutex<Option<NetworkStatus>>> = Arc::new(Mutex::new(None));

        let ns_weak = Arc::downgrade(&network_status);
        let tx = app_sender.clone();
        let signing_activity_bg = signing_activity.clone();
        std::thread::spawn(move || {
            loop {
                let Some(ns) = ns_weak.upgrade() else {
                    return;
                };

                let last_sig_time = signing_activity_bg.lock().ok().and_then(|activity| {
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
                    *guard = Some(status);
                }
                drop(ns);

                let _ = tx.send(AppEvent::Invalidate);
                std::thread::sleep(Duration::from_secs(1));
            }
        });

        Self {
            app_sender,
            network_status,
            signing_activity,
        }
    }
}

// Layout constants for 250x122 display
const MARGIN: i32 = 6;
use super::DISPLAY_WIDTH;
const TITLE_Y: i32 = 18;
const LINE_Y: i32 = 28;
const ROW_1_Y: i32 = 48;
const ROW_2_Y: i32 = 69;
const ROW_3_Y: i32 = 90;
const ROW_4_Y: i32 = 111;
const VALUE_COL_X: i32 = 108;

fn read_temperature() -> Option<f32> {
    let raw = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp").ok()?;
    let millideg: f32 = raw.trim().parse().ok()?;
    Some(millideg / 1000.0)
}

// Coarse resolution (whole degrees, minutes) keeps these rows' rendered text
// stable between 1 Hz ticks, so unchanged frames die in the display's
// frame-skip instead of repainting the panel every second.

fn format_temperature(temp: Option<f32>) -> String {
    temp.map_or_else(|| "N/A".into(), |t| format!("{:.0}\u{00b0}C", t.round()))
}

fn read_uptime_secs() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/uptime").ok()?;
    let field = raw.split_whitespace().next()?;
    // /proc/uptime is "seconds.fractional ...", parse integer part
    field.split('.').next()?.parse().ok()
}

fn format_uptime(secs: u64) -> String {
    let minutes = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    let days = secs / 86400;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn handle_touch(&mut self, _point: Point) -> bool {
        let _ = self.app_sender.send(AppEvent::ShowMenu);
        false
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let network_status = self
            .network_status
            .lock()
            .map_or_else(|e| *e.into_inner(), |guard| *guard);

        // Title
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();
        font.render_aligned(
            "System",
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

        // Baker row
        let status_str = match network_status.as_ref() {
            None => "Checking...",
            Some(s) if !s.interface_configured => "Offline",
            Some(s) if !s.host_reachable => "Unreachable",
            Some(s) if s.baker_active => "Active",
            Some(_) => "Idle",
        };
        draw_label_value(display, "Baker", status_str, ROW_1_Y);

        // Temperature row
        let temp_str = format_temperature(read_temperature());
        draw_label_value(display, "CPU Temp", temp_str.as_str(), ROW_2_Y);

        // Uptime row
        let uptime_str = read_uptime_secs().map_or_else(|| "N/A".into(), format_uptime);
        draw_label_value(display, "Uptime", uptime_str.as_str(), ROW_3_Y);

        // Signatures row
        let sig_count = self
            .signing_activity
            .lock()
            .map_or(0, |a| a.total_signatures);
        let sig_str = format!("{sig_count} since boot");
        draw_label_value(display, "Signatures", sig_str.as_str(), ROW_4_Y);

        Ok(())
    }
}

fn draw_label_value<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    label: &str,
    value: &str,
    y: i32,
) {
    let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

    font.render_aligned(
        label,
        Point::new(MARGIN, y),
        VerticalPosition::Baseline,
        HorizontalAlignment::Left,
        FontColor::Transparent(BinaryColor::Off),
        display,
    )
    .ok();

    font.render_aligned(
        value,
        Point::new(VALUE_COL_X, y),
        VerticalPosition::Baseline,
        HorizontalAlignment::Left,
        FontColor::Transparent(BinaryColor::Off),
        display,
    )
    .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_formats_at_minute_resolution() {
        assert_eq!(format_uptime(0), "0m");
        assert_eq!(format_uptime(59), "0m");
        assert_eq!(format_uptime(60), "1m");
        assert_eq!(format_uptime(3599), "59m");
        assert_eq!(format_uptime(3600), "1h 0m");
        assert_eq!(format_uptime(86399), "23h 59m");
        assert_eq!(format_uptime(86400), "1d 0h 0m");
        assert_eq!(format_uptime(90061), "1d 1h 1m");
    }

    #[test]
    fn temperature_formats_whole_degrees() {
        assert_eq!(format_temperature(Some(48.4)), "48\u{00b0}C");
        assert_eq!(format_temperature(Some(48.5)), "49\u{00b0}C");
        assert_eq!(format_temperature(Some(48.6)), "49\u{00b0}C");
        assert_eq!(format_temperature(None), "N/A");
    }
}
