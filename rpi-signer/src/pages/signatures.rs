use crate::events::AppEvent;
use crate::fonts;
use russignol_signer_lib::signing_activity::{KeyType, OperationType, SigningActivity};

use super::Page;
use crossbeam_channel::Sender;
use embedded_graphics::{
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point},
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use u8g2_fonts::FontRenderer;

/// Record of a signing operation for display in the table
#[derive(Clone, Debug)]
struct SigningRecord {
    key: String,            // Signing key (will be truncated for display)
    level: u32,             // Block height/level
    op_type: OperationType, // Type of operation (Block, Attestation, etc.)
    sign_time: Duration,    // Time it took to sign
}

pub fn format_key_short(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    if len <= 7 {
        s.to_string()
    } else {
        // Show first 7 characters only
        chars[0..7].iter().collect()
    }
}

pub struct SignaturesPage {
    // Event sender for navigation
    app_sender: Sender<AppEvent>,
    // Reference to shared signing activity for reading latest state
    signing_activity_shared: Arc<Mutex<SigningActivity>>,
    // Public key hashes for consensus and companion keys
    consensus_pkh: Option<String>,
    companion_pkh: Option<String>,
}

impl SignaturesPage {
    pub fn new(
        app_sender: Sender<AppEvent>,
        signing_activity: Arc<Mutex<SigningActivity>>,
    ) -> Self {
        // Load keys to get their public key hashes
        let keys = crate::tezos_signer::get_keys();
        let consensus_pkh = keys
            .iter()
            .find(|k| k.name == "consensus")
            .map(|k| k.value.clone());
        let companion_pkh = keys
            .iter()
            .find(|k| k.name == "companion")
            .map(|k| k.value.clone());

        Self {
            app_sender,
            signing_activity_shared: signing_activity,
            consensus_pkh,
            companion_pkh,
        }
    }

    /// Build display records from shared state's ring buffer
    fn build_records(&self, activity: &SigningActivity) -> Vec<SigningRecord> {
        activity
            .recent_events
            .iter()
            .filter_map(|event| {
                let (Some(level), Some(duration), Some(op_type)) = (
                    event.activity.level,
                    event.activity.duration,
                    event.activity.operation_type,
                ) else {
                    return None;
                };

                let key = match event.key_type {
                    KeyType::Consensus => {
                        if let Some(ref pkh) = self.consensus_pkh {
                            format!("C{pkh}")
                        } else {
                            "C???".to_string()
                        }
                    }
                    KeyType::Companion => {
                        if let Some(ref pkh) = self.companion_pkh {
                            format!("P{pkh}")
                        } else {
                            "P???".to_string()
                        }
                    }
                };

                Some(SigningRecord {
                    key,
                    level,
                    op_type,
                    sign_time: duration,
                })
            })
            .collect()
    }
}

// Layout constants for 250x122 display
const ROW_HEIGHT: i32 = 24;
const ROW_1_Y: i32 = 13;
const COL_LEVEL_X: i32 = 30;
const COL_TYPE_X: i32 = 90;
const COL_KEY_X: i32 = 120;
const COL_TIME_X: i32 = 228;

impl<D: DrawTarget<Color = BinaryColor>> Page<D> for SignaturesPage {
    fn handle_touch(&mut self, _point: Point) -> bool {
        // Any touch shows the status page
        let _ = self.app_sender.send(AppEvent::ShowStatus);
        false // Whole-page listener, not a specific button
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let activity = match self.signing_activity_shared.lock() {
            Ok(a) => *a,
            Err(_) => return Ok(()),
        };

        let records = self.build_records(&activity);

        if records.is_empty() {
            draw_empty_state(display);
            return Ok(());
        }

        // Ring buffer already yields oldest-first; display oldest at top, newest at bottom
        let num_records = records.len();
        let start_row = 5 - num_records;

        for (index, record) in records.iter().enumerate() {
            let row_y = ROW_1_Y + (i32::try_from(start_row + index).unwrap() * ROW_HEIGHT);
            draw_signing_record_row(display, record, row_y);
        }

        Ok(())
    }
}

fn draw_empty_state<D: DrawTarget<Color = BinaryColor>>(display: &mut D) {
    let header_font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
    header_font
        .render_aligned(
            "Waiting for signing requests...",
            Point::new(125, 61),
            u8g2_fonts::types::VerticalPosition::Center,
            u8g2_fonts::types::HorizontalAlignment::Center,
            u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();
}

fn draw_signing_record_row<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    record: &SigningRecord,
    row_y: i32,
) {
    let text_y = row_y + 1;
    let data_font = FontRenderer::new::<fonts::FONT_MONOSPACE>();
    let key_font = FontRenderer::new::<fonts::FONT_MONO_SMALL>();
    let icon_key = FontRenderer::new::<fonts::ICON_KEY>();

    // Level (center-aligned)
    let level_str = format!("{}", record.level);
    data_font
        .render_aligned(
            level_str.as_str(),
            Point::new(COL_LEVEL_X, text_y),
            u8g2_fonts::types::VerticalPosition::Center,
            u8g2_fonts::types::HorizontalAlignment::Center,
            u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

    // Operation type (3-char codes)
    let type_str = match record.op_type {
        OperationType::Block => "BLK",
        OperationType::PreAttestation => "PRE",
        OperationType::Attestation => "ATT",
    };
    data_font
        .render_aligned(
            type_str,
            Point::new(COL_TYPE_X, text_y),
            u8g2_fonts::types::VerticalPosition::Center,
            u8g2_fonts::types::HorizontalAlignment::Center,
            u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

    // Key - render icon and PKH
    if let Some(first_char) = record.key.chars().next() {
        let pkh = &record.key[1..];
        let icon_char = if first_char == 'C' { "1" } else { "0" };

        icon_key
            .render_aligned(
                icon_char,
                Point::new(COL_KEY_X, row_y),
                u8g2_fonts::types::VerticalPosition::Center,
                u8g2_fonts::types::HorizontalAlignment::Left,
                u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();

        let pkh_display = format_key_short(pkh);
        let pkh_x = COL_KEY_X + 22;
        key_font
            .render_aligned(
                pkh_display.as_str(),
                Point::new(pkh_x, row_y),
                u8g2_fonts::types::VerticalPosition::Center,
                u8g2_fonts::types::HorizontalAlignment::Left,
                u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();
    }

    // Time (center-aligned)
    let time_micros = record.sign_time.as_micros();
    let (divisor, unit) = if time_micros >= 1_000_000 {
        (1_000_000, "s")
    } else {
        (1000, "ms")
    };
    let whole = time_micros / divisor;
    let tenths = (time_micros % divisor) / (divisor / 10);
    let time_str = format!("{whole}.{tenths}{unit}");
    data_font
        .render_aligned(
            time_str.as_str(),
            Point::new(COL_TIME_X, text_y),
            u8g2_fonts::types::VerticalPosition::Center,
            u8g2_fonts::types::HorizontalAlignment::Center,
            u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::signing_activity::{KeyType, SignatureActivity, SigningEvent};
    use std::time::{Duration, SystemTime};

    fn make_activity(consensus_pkh: Option<&str>, companion_pkh: Option<&str>) -> SignaturesPage {
        let shared = Arc::new(Mutex::new(SigningActivity::default()));
        let (sender, _receiver) = crossbeam_channel::unbounded();
        SignaturesPage {
            app_sender: sender,
            signing_activity_shared: shared,
            consensus_pkh: consensus_pkh.map(String::from),
            companion_pkh: companion_pkh.map(String::from),
        }
    }

    fn make_event(key_type: KeyType, level: u32) -> SigningEvent {
        SigningEvent {
            key_type,
            activity: SignatureActivity {
                level: Some(level),
                timestamp: SystemTime::now(),
                duration: Some(Duration::from_millis(42)),
                operation_type: Some(OperationType::Attestation),
                data_size: Some(128),
            },
        }
    }

    #[test]
    fn renders_events_from_shared_state() {
        let page = make_activity(Some("tz4consensus"), Some("tz4companion"));

        // Push events into shared state
        {
            let mut activity = page.signing_activity_shared.lock().unwrap();
            activity
                .recent_events
                .push(make_event(KeyType::Consensus, 100));
            activity
                .recent_events
                .push(make_event(KeyType::Companion, 101));
        }

        let activity = page.signing_activity_shared.lock().unwrap();
        let records = page.build_records(&activity);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].level, 100);
        assert!(records[0].key.starts_with('C'));
        assert_eq!(records[1].level, 101);
        assert!(records[1].key.starts_with('P'));
    }

    #[test]
    fn events_missing_fields_are_skipped() {
        let page = make_activity(Some("tz4consensus"), None);

        {
            let mut activity = page.signing_activity_shared.lock().unwrap();
            // Event with no level — should be filtered out
            activity.recent_events.push(SigningEvent {
                key_type: KeyType::Consensus,
                activity: SignatureActivity {
                    level: None,
                    timestamp: SystemTime::now(),
                    duration: Some(Duration::from_millis(42)),
                    operation_type: Some(OperationType::Block),
                    data_size: Some(128),
                },
            });
            // Valid event
            activity
                .recent_events
                .push(make_event(KeyType::Consensus, 200));
        }

        let activity = page.signing_activity_shared.lock().unwrap();
        let records = page.build_records(&activity);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, 200);
    }
}
