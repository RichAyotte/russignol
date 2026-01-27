use crate::events::AppEvent;
use crate::fonts;
use russignol_signer_lib::signing_activity::{OperationType, SigningActivity};

use super::Page;
use crossbeam_channel::Sender;
use embedded_graphics::{
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point},
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use u8g2_fonts::FontRenderer;

/// Record of a signing operation for display in the table
#[derive(Clone, Debug)]
pub struct SigningRecord {
    pub key: String,            // Signing key (will be truncated for display)
    pub level: u32,             // Block height/level
    pub op_type: OperationType, // Type of operation (Block, Attestation, etc.)
    pub sign_time: Duration,    // Time it took to sign
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
    signing_activity: SigningActivity,
    signing_records: VecDeque<SigningRecord>,
    // Reference to shared signing activity for reading latest state
    signing_activity_shared: Arc<Mutex<SigningActivity>>,
    // Track previous signing activity to detect new signatures
    last_signing_activity: SigningActivity,
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
            signing_activity: SigningActivity::default(),
            signing_records: VecDeque::with_capacity(5),
            signing_activity_shared: signing_activity,
            last_signing_activity: SigningActivity::default(),
            consensus_pkh,
            companion_pkh,
        }
    }

    /// Update state by polling current signing activity
    fn update_state(&mut self) {
        // Update signing activity from shared state
        let current = if let Ok(activity) = self.signing_activity_shared.lock() {
            *activity
        } else {
            return; // Mutex poisoned, can't update
        };

        // Detect new signatures for the signing records table
        if current != self.last_signing_activity {
            // Check consensus key for new signature
            if let Some(ref current_consensus) = current.consensus {
                let is_new = if let Some(ref last_consensus) = self.last_signing_activity.consensus
                {
                    current_consensus.timestamp > last_consensus.timestamp
                } else {
                    true
                };

                if is_new {
                    log::debug!(
                        "New consensus signature: level={:?}, duration={:?}, op_type={:?}",
                        current_consensus.level,
                        current_consensus.duration,
                        current_consensus.operation_type
                    );

                    if let (Some(level), Some(duration), Some(op_type)) = (
                        current_consensus.level,
                        current_consensus.duration,
                        current_consensus.operation_type,
                    ) {
                        // Use 'C' to indicate consensus (will be rendered with icon)
                        let key_display = if let Some(ref pkh) = self.consensus_pkh {
                            format!("C{pkh}")
                        } else {
                            "C???".to_string()
                        };
                        let record = SigningRecord {
                            key: key_display,
                            level,
                            op_type,
                            sign_time: duration,
                        };
                        self.add_signing_record(record);
                    }
                }
            }

            // Check companion key for new signature
            if let Some(ref current_companion) = current.companion {
                let is_new = if let Some(ref last_companion) = self.last_signing_activity.companion
                {
                    current_companion.timestamp > last_companion.timestamp
                } else {
                    true
                };

                if is_new {
                    log::debug!(
                        "New companion signature: level={:?}, duration={:?}, op_type={:?}",
                        current_companion.level,
                        current_companion.duration,
                        current_companion.operation_type
                    );

                    if let (Some(level), Some(duration), Some(op_type)) = (
                        current_companion.level,
                        current_companion.duration,
                        current_companion.operation_type,
                    ) {
                        // Use 'P' to indicate companion (will be rendered with icon)
                        let key_display = if let Some(ref pkh) = self.companion_pkh {
                            format!("P{pkh}")
                        } else {
                            "P???".to_string()
                        };
                        let record = SigningRecord {
                            key: key_display,
                            level,
                            op_type,
                            sign_time: duration,
                        };
                        self.add_signing_record(record);
                    }
                }
            }

            self.last_signing_activity = current;
        }

        self.signing_activity = current;
    }

    // Private method to add a signing record
    fn add_signing_record(&mut self, record: SigningRecord) {
        // Skip if we already have a record for this exact key+level+op_type combination
        if self
            .signing_records
            .iter()
            .any(|r| r.key == record.key && r.level == record.level && r.op_type == record.op_type)
        {
            return;
        }

        // Insert in sorted order by level (descending)
        let insert_pos = self
            .signing_records
            .iter()
            .position(|r| r.level < record.level)
            .unwrap_or(self.signing_records.len());

        self.signing_records.insert(insert_pos, record);

        // Keep only the last 5 records
        if self.signing_records.len() > 5 {
            self.signing_records.pop_back();
        }
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
    fn handle_touch(&mut self, _point: Point) {
        // Any touch shows the status page
        let _ = self.app_sender.send(AppEvent::ShowStatus);
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        self.update_state();

        if self.signing_records.is_empty() {
            draw_empty_state(display);
            return Ok(());
        }

        // Show oldest at top, newest at bottom (content scrolls up as new signatures arrive)
        let records: Vec<_> = self.signing_records.iter().take(5).rev().collect();
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
