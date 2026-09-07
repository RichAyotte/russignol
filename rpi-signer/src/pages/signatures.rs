use crate::events::AppEvent;
use crate::fonts;
use russignol_signer_lib::signing_activity::{OperationType, SigningActivity};
use russignol_signer_lib::{DeviceKey, KeyRole};

use super::Page as PageTrait;
use super::drawn;
use crossbeam_channel::Sender;
use embedded_graphics::{
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point},
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use u8g2_fonts::FontRenderer;

#[derive(Clone, Debug)]
struct SigningRecord<'a> {
    role: KeyRole,
    /// The key column's label for this record's role.
    pkh_short: &'a str,
    level: u32,
    op_type: OperationType,
    sign_time: Duration,
}

/// The width of the activity table's key column, in characters.
const KEY_LABEL_CHARS: usize = 7;

/// What the key column shows where the wallet would not read. It is not the
/// card lacking the key: the signer may be serving signatures under a key this
/// page cannot name.
const UNKNOWN: &str = "Unknown";

/// What the key column shows for a role the card names no key in.
const NOT_FOUND: &str = "???";

const _: () = assert!(UNKNOWN.len() <= KEY_LABEL_CHARS && NOT_FOUND.len() <= KEY_LABEL_CHARS);

/// The first characters of a public key hash that fit the key column.
#[must_use]
pub fn format_key_short(s: &str) -> String {
    s.chars().take(KEY_LABEL_CHARS).collect()
}

pub struct Page {
    app_sender: Sender<AppEvent>,
    signing_activity_shared: Arc<Mutex<SigningActivity>>,
    /// Precomputed short labels per role ([`KeyRole::ALL`] order).
    short_by_role: [String; KeyRole::COUNT],
}

impl Page {
    pub fn new(
        app_sender: Sender<AppEvent>,
        signing_activity: Arc<Mutex<SigningActivity>>,
    ) -> Self {
        Self::with_keys(
            app_sender,
            signing_activity,
            &crate::tezos_signer::get_keys(),
        )
    }

    /// The label each role is drawn under is derived here alone, so a page
    /// built over the card's list and one built over a test's derive it the
    /// same way.
    fn with_keys(
        app_sender: Sender<AppEvent>,
        signing_activity: Arc<Mutex<SigningActivity>>,
        keys: &crate::tezos_signer::CardKeys,
    ) -> Self {
        let short_by_role = match keys {
            crate::tezos_signer::CardKeys::Unreadable => KeyRole::map_all(|_| UNKNOWN.to_string()),
            crate::tezos_signer::CardKeys::Listed(keys) => KeyRole::map_all(|role| {
                keys.iter()
                    .find(|k| k.name == DeviceKey::Bls(role).device_alias())
                    .map_or_else(|| NOT_FOUND.to_string(), |k| format_key_short(&k.value))
            }),
        };

        Self {
            app_sender,
            signing_activity_shared: signing_activity,
            short_by_role,
        }
    }

    /// The activity to draw, taken back from a poisoned lock: it is plain data,
    /// so a table drawn after another thread's panic is still the table, where
    /// a blank panel reads as a card that has signed nothing.
    fn snapshot(&self) -> SigningActivity {
        *self
            .signing_activity_shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Build display records from shared state's ring buffer
    fn build_records(&self, activity: &SigningActivity) -> Vec<SigningRecord<'_>> {
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

                let pkh_short = self.short_by_role[event.role.index()].as_str();

                Some(SigningRecord {
                    role: event.role,
                    pkh_short,
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

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn handle_touch(&mut self, _point: Point) -> bool {
        let _ = self.app_sender.send(AppEvent::ShowMenu);
        false // Whole-page listener, not a specific button
    }

    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let records = self.build_records(&self.snapshot());

        if records.is_empty() {
            return draw_empty_state(display);
        }

        // Ring buffer already yields oldest-first; display oldest at top, newest at bottom
        let num_records = records.len();
        let start_row = 5 - num_records;

        for (index, record) in records.iter().enumerate() {
            let row_y = ROW_1_Y + (i32::try_from(start_row + index).unwrap() * ROW_HEIGHT);
            draw_signing_record_row(display, record, row_y)?;
        }

        Ok(())
    }
}

fn draw_empty_state<D: DrawTarget<Color = BinaryColor>>(display: &mut D) -> Result<(), D::Error> {
    let header_font = FontRenderer::new::<fonts::FONT_PROPORTIONAL>();
    drawn(header_font.render_aligned(
        "Waiting for signing requests...",
        Point::new(125, 61),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Center,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;
    Ok(())
}

fn draw_signing_record_row<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    record: &SigningRecord<'_>,
    row_y: i32,
) -> Result<(), D::Error> {
    let text_y = row_y + 1;
    let data_font = FontRenderer::new::<fonts::FONT_MONOSPACE>();
    let key_font = FontRenderer::new::<fonts::FONT_MONO_SMALL>();
    let icon_key = FontRenderer::new::<fonts::ICON_KEY>();

    let level_str = format!("{}", record.level);
    drawn(data_font.render_aligned(
        level_str.as_str(),
        Point::new(COL_LEVEL_X, text_y),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Center,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;

    let type_str = match record.op_type {
        OperationType::Block => "BLK",
        OperationType::PreAttestation => "PRE",
        OperationType::Attestation => "ATT",
    };
    drawn(data_font.render_aligned(
        type_str,
        Point::new(COL_TYPE_X, text_y),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Center,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;

    let icon_char = super::key_icon(record.role);
    drawn(icon_key.render_aligned(
        icon_char,
        Point::new(COL_KEY_X, row_y),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Left,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;

    let pkh_x = COL_KEY_X + 22;
    drawn(key_font.render_aligned(
        record.pkh_short,
        Point::new(pkh_x, row_y),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Left,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;

    let time_micros = record.sign_time.as_micros();
    let (divisor, unit) = if time_micros >= 1_000_000 {
        (1_000_000, "s")
    } else {
        (1000, "ms")
    };
    let whole = time_micros / divisor;
    let tenths = (time_micros % divisor) / (divisor / 10);
    let time_str = format!("{whole}.{tenths}{unit}");
    drawn(data_font.render_aligned(
        time_str.as_str(),
        Point::new(COL_TIME_X, text_y),
        u8g2_fonts::types::VerticalPosition::Center,
        u8g2_fonts::types::HorizontalAlignment::Center,
        u8g2_fonts::types::FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::signing_activity::{SignatureActivity, SigningEvent};
    use std::time::{Duration, SystemTime};

    fn make_activity(consensus_pkh: Option<&str>, companion_pkh: Option<&str>) -> Page {
        let shared = Arc::new(Mutex::new(SigningActivity::default()));
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let keys = [
            (KeyRole::Consensus, consensus_pkh),
            (KeyRole::Companion, companion_pkh),
        ]
        .into_iter()
        .filter_map(|(role, pkh)| {
            pkh.map(|value| crate::tezos_signer::TezosKey {
                name: DeviceKey::Bls(role).device_alias().to_string(),
                value: value.to_string(),
            })
        })
        .collect();
        Page::with_keys(sender, shared, &crate::tezos_signer::CardKeys::Listed(keys))
    }

    fn make_event(role: KeyRole, level: u32) -> SigningEvent {
        SigningEvent {
            role,
            activity: SignatureActivity {
                level: Some(level),
                timestamp: SystemTime::now(),
                duration: Some(Duration::from_millis(42)),
                operation_type: Some(OperationType::Attestation),
                data_size: Some(128),
            },
        }
    }

    /// A wallet that would not read leaves every role's key unknown, which is
    /// not the card lacking it: the signer may be serving signatures under a
    /// key this page cannot name. The two readings are spelled out here rather
    /// than taken from the constants the page draws, so the assertion holds
    /// however they are worded, the day they are worded the same included.
    #[test]
    fn an_unreadable_wallet_is_not_a_card_missing_its_keys() {
        let labels = |page: &Page| {
            let mut activity = SigningActivity::default();
            for role in KeyRole::ALL {
                activity.recent_events.push(make_event(role, 1));
            }
            page.build_records(&activity)
                .into_iter()
                .map(|record| record.pkh_short.to_string())
                .collect::<Vec<_>>()
        };
        let shared = Arc::new(Mutex::new(SigningActivity::default()));
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let unread = Page::with_keys(sender, shared, &crate::tezos_signer::CardKeys::Unreadable);

        assert_eq!(labels(&unread), ["Unknown"; KeyRole::COUNT]);
        assert_eq!(labels(&make_activity(None, None)), ["???"; KeyRole::COUNT]);
    }

    /// A role the card holds no key for is drawn as missing rather than under a
    /// label borrowed from another role.
    #[test]
    fn a_role_without_a_key_is_labelled_missing() {
        let page = make_activity(Some("tz4consensus"), None);
        page.signing_activity_shared
            .lock()
            .unwrap()
            .recent_events
            .push(make_event(KeyRole::Companion, 7));

        let activity = page.signing_activity_shared.lock().unwrap();
        let records = page.build_records(&activity);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pkh_short, "???");
    }

    /// A snapshot taken while another thread has poisoned the lock still holds
    /// the events, so the table is drawn rather than the panel left blank.
    #[test]
    fn a_poisoned_lock_still_snapshots_the_activity() {
        let page = make_activity(Some("tz4consensus"), None);
        {
            let mut activity = page.signing_activity_shared.lock().unwrap();
            for level in 1..=3 {
                activity
                    .recent_events
                    .push(make_event(KeyRole::Consensus, level));
            }
        }
        let poisoner = Arc::clone(&page.signing_activity_shared);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock().unwrap();
            panic!("poison the activity lock");
        })
        .join();
        assert!(page.signing_activity_shared.is_poisoned());

        assert_eq!(page.build_records(&page.snapshot()).len(), 3);
    }

    #[test]
    fn build_records_reads_events_from_shared_state() {
        let page = make_activity(Some("tz4consensus"), Some("tz4companion"));

        // Push events into shared state
        {
            let mut activity = page.signing_activity_shared.lock().unwrap();
            activity
                .recent_events
                .push(make_event(KeyRole::Consensus, 100));
            activity
                .recent_events
                .push(make_event(KeyRole::Companion, 101));
        }

        let activity = page.signing_activity_shared.lock().unwrap();
        let records = page.build_records(&activity);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].level, 100);
        assert_eq!(records[0].role, KeyRole::Consensus);
        assert_eq!(records[0].pkh_short, "tz4cons");
        assert_eq!(records[1].level, 101);
        assert_eq!(records[1].role, KeyRole::Companion);
        assert_eq!(records[1].pkh_short, "tz4comp");
    }

    #[test]
    fn format_key_short_ascii_prefix() {
        assert_eq!(format_key_short(""), "");
        assert_eq!(format_key_short("abc"), "abc");
        assert_eq!(format_key_short("1234567"), "1234567");
        assert_eq!(format_key_short("12345678"), "1234567");
        assert_eq!(format_key_short("tz4ABCDEFG"), "tz4ABCD");
    }

    /// A label is cut between characters, so a value that is not ASCII is
    /// shortened rather than panicking the draw on a byte inside one.
    #[test]
    fn format_key_short_cuts_between_characters() {
        assert_eq!(format_key_short("ééééééééé"), "ééééééé");
    }

    /// Rows need `level`, `duration`, and `operation_type`; any missing field drops the row.
    #[test]
    fn events_missing_fields_are_skipped() {
        let page = make_activity(Some("tz4consensus"), None);
        let now = SystemTime::now();

        {
            let mut activity = page.signing_activity_shared.lock().unwrap();
            for sa in [
                SignatureActivity {
                    level: None,
                    timestamp: now,
                    duration: Some(Duration::from_millis(42)),
                    operation_type: Some(OperationType::Block),
                    data_size: Some(128),
                },
                SignatureActivity {
                    level: Some(1),
                    timestamp: now,
                    duration: None,
                    operation_type: Some(OperationType::Attestation),
                    data_size: Some(128),
                },
                SignatureActivity {
                    level: Some(2),
                    timestamp: now,
                    duration: Some(Duration::from_millis(42)),
                    operation_type: None,
                    data_size: Some(128),
                },
            ] {
                activity.recent_events.push(SigningEvent {
                    role: KeyRole::Consensus,
                    activity: sa,
                });
            }
            activity
                .recent_events
                .push(make_event(KeyRole::Consensus, 200));
        }

        let activity = page.signing_activity_shared.lock().unwrap();
        let records = page.build_records(&activity);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, 200);
    }
}
