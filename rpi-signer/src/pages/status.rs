use crate::events::AppEvent;
use crate::fonts;
use crate::network_status::NetworkStatus;
use crate::tezos_signer;

use super::Page as PageTrait;
use super::drawn;
use crossbeam_channel::Sender;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point, Primitive},
    primitives::{Line, PrimitiveStyle},
};
use russignol_signer_lib::signing_activity::SigningActivity;
use russignol_signer_lib::{EpochBudget, HighWatermark, PublicKeyHash};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

pub struct Page {
    app_sender: Sender<AppEvent>,
    rows: Arc<Mutex<Rows>>,
}

/// What the rows show, taken off the draw path: the sampler thread takes one
/// every two seconds and the constructor the first, so no frame is drawn
/// against an empty one.
#[derive(Clone, PartialEq, Eq)]
struct Rows {
    baker: NetworkStatus,
    temperature: String,
    uptime: String,
    signatures: u64,
    epochs: Option<String>,
}

impl Rows {
    fn sample(signing_activity: &Mutex<SigningActivity>, epochs: &EpochRow) -> Self {
        // Taken back from a poisoned lock: the activity is plain data, and a
        // count read after another thread's panic is still the count.
        let activity = signing_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let last_signature = russignol_signer_lib::KeyRole::ALL
            .iter()
            .filter_map(|role| activity.last(*role).map(|a| a.timestamp))
            .max();
        let signatures = activity.total_signatures;
        drop(activity);
        Self {
            baker: NetworkStatus::check(last_signature),
            temperature: format_temperature(read_temperature()),
            uptime: read_uptime_secs().map_or_else(|| "N/A".into(), format_uptime),
            signatures,
            epochs: epochs.value(),
        }
    }
}

/// The card's keys and the store that says what each has left to spend.
///
/// Held rather than read per draw so the row and the repaint check ask the
/// same question of the same store: a second reading of it here is a second
/// place the row's text is decided.
#[derive(Clone)]
struct EpochRow {
    watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    keys: Vec<PublicKeyHash>,
    /// Set where a stored key's address would not parse. The store cannot be
    /// asked about a key this page cannot address, so an epoch counter it
    /// carries is one the row would otherwise report as absent.
    unreadable: bool,
}

impl EpochRow {
    fn new(
        watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
        card: &tezos_signer::CardKeys,
    ) -> Self {
        let listed = match card {
            tezos_signer::CardKeys::Unreadable => {
                return Self {
                    watermark,
                    keys: Vec::new(),
                    unreadable: true,
                };
            }
            tezos_signer::CardKeys::Listed(listed) => listed,
        };
        let mut unreadable = false;
        let keys = listed
            .iter()
            .filter_map(|key| match PublicKeyHash::from_b58check(&key.value) {
                Ok(pkh) => Some(pkh),
                Err(e) => {
                    log::error!("Key {} has an unreadable address: {e}", key.name);
                    unreadable = true;
                    None
                }
            })
            .collect();
        Self {
            watermark,
            keys,
            unreadable,
        }
    }

    /// The row's value, and `None` where no key on this card spends an epoch
    /// per signature — where the row is not drawn at all rather than drawn
    /// empty, a tz4-only card having no epoch to report on.
    fn value(&self) -> Option<String> {
        let guard = match self.watermark.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let wm = match guard.as_ref()?.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match self.keys.iter().find(|pkh| wm.spends_epochs(pkh)) {
            Some(pkh) => Some(format_epochs(wm.epoch_budget(pkh))),
            // Nothing here spends epochs, which is a claim the page can only
            // make about keys it could address.
            None => self.unreadable.then(|| format_epochs(None)),
        }
    }
}

/// What this page draws where it cannot answer. A glyph the font does not
/// hold is refused by the renderer, leaving the cell blank, which reads as a
/// row the page had nothing to say about at all.
const UNKNOWN: &str = "N/A";

/// What one key's counter has left: epochs left, epochs it was born with, and
/// the days those cover.
///
/// A key whose counter is not established reads as unknown rather than as
/// nothing left. It has signed at no epoch and stands where a fresh card
/// stands, which is the opposite of the exhausted key this row exists to make
/// visible.
fn format_epochs(budget: Option<EpochBudget>) -> String {
    budget.map_or_else(
        || UNKNOWN.to_string(),
        |budget| {
            format!(
                "{}/{} {}d",
                compact(budget.remaining()),
                compact(budget.total()),
                budget.days_remaining()
            )
        },
    )
}

/// A count in five characters at most, which is what holds three figures
/// inside the value column at any range a key can be generated with.
///
/// Truncated rather than rounded, so a countdown never reports more left than
/// the key holds.
fn compact(count: u64) -> String {
    match count {
        0..10_000 => count.to_string(),
        10_000..1_000_000 => format!("{}k", count / 1_000),
        1_000_000..100_000_000 => {
            format!("{}.{}M", count / 1_000_000, (count % 1_000_000) / 100_000)
        }
        100_000_000..1_000_000_000 => format!("{}M", count / 1_000_000),
        _ => format!(
            "{}.{}G",
            count / 1_000_000_000,
            (count % 1_000_000_000) / 100_000_000
        ),
    }
}

impl Page {
    pub fn new(
        app_sender: Sender<AppEvent>,
        signing_activity: Arc<Mutex<SigningActivity>>,
        watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    ) -> Self {
        let epochs = EpochRow::new(watermark, &tezos_signer::get_keys());
        let rows = Arc::new(Mutex::new(Rows::sample(&signing_activity, &epochs)));
        let rows_weak = Arc::downgrade(&rows);
        let tx = app_sender.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let Some(rows) = rows_weak.upgrade() else {
                    return;
                };
                let sample = Rows::sample(&signing_activity, &epochs);
                // Invalidate only when a row flips, so an idle Status page does
                // not force a panel update every tick.
                let mut current = rows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if *current != sample {
                    *current = sample;
                    drop(current);
                    let _ = tx.send(AppEvent::Invalidate);
                }
            }
        });

        Self { app_sender, rows }
    }
}

// Layout constants for 250x122 display
const MARGIN: i32 = 6;
use super::{DISPLAY_HEIGHT, DISPLAY_WIDTH};
const TITLE_Y: i32 = 18;
const LINE_Y: i32 = 28;
/// Rows this page carries: baker, temperature, uptime, signatures, epochs.
const ROWS: i32 = 5;
const ROW_START_Y: i32 = 46;
const ROW_PITCH: i32 = 18;
const VALUE_COL_X: i32 = 108;

/// Baseline of a row, from the start and the pitch rather than a constant per
/// row: a row added between two of those leaves the rest where they were, and
/// the one pushed past the panel is drawn to nobody.
const fn row_y(row: i32) -> i32 {
    ROW_START_Y + row * ROW_PITCH
}

const _: () = assert!(row_y(ROWS - 1) < DISPLAY_HEIGHT);

fn read_temperature() -> Option<f32> {
    let raw = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp").ok()?;
    let millideg: f32 = raw.trim().parse().ok()?;
    Some(millideg / 1000.0)
}

// Coarse resolution (whole degrees, minutes) keeps these rows' rendered text
// stable between status poll ticks (2s), so unchanged frames die in the
// display's frame-skip instead of repainting the panel every poll.

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
        let rows = self
            .rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();
        drawn(font.render_aligned(
            "System",
            Point::new(DISPLAY_WIDTH / 2, TITLE_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        ))?;

        Line::new(
            Point::new(MARGIN, LINE_Y),
            Point::new(DISPLAY_WIDTH - MARGIN, LINE_Y),
        )
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::Off, 1))
        .draw(display)?;

        let baker = rows.baker;
        let status_str = if !baker.interface_configured {
            "Offline"
        } else if !baker.host_reachable {
            "Unreachable"
        } else if baker.baker_active {
            "Active"
        } else {
            "Idle"
        };
        draw_label_value(display, "Baker", status_str, row_y(0))?;
        draw_label_value(display, "CPU Temp", rows.temperature.as_str(), row_y(1))?;
        draw_label_value(display, "Uptime", rows.uptime.as_str(), row_y(2))?;
        let sig_str = format!("{} since boot", rows.signatures);
        draw_label_value(display, "Signatures", sig_str.as_str(), row_y(3))?;
        if let Some(epochs) = rows.epochs.as_deref() {
            draw_label_value(display, "Epochs", epochs, row_y(4))?;
        }

        Ok(())
    }
}

fn draw_label_value<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    label: &str,
    value: &str,
    y: i32,
) -> Result<(), D::Error> {
    let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

    drawn(font.render_aligned(
        label,
        Point::new(MARGIN, y),
        VerticalPosition::Baseline,
        HorizontalAlignment::Left,
        FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;

    drawn(font.render_aligned(
        value,
        Point::new(VALUE_COL_X, y),
        VerticalPosition::Baseline,
        HorizontalAlignment::Left,
        FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russignol_signer_lib::test_utils::new_mixed_watermark;
    use russignol_signer_lib::{Scheme, xmss::Epoch};
    use std::ops::RangeInclusive;
    use tempfile::TempDir;

    /// The 2^24 epochs a provisioned key holds, so what these pin is the row
    /// a reader will see.
    const DEPLOYED: RangeInclusive<Epoch> = 0..=16_777_215;

    /// The store takes an address and a range rather than key material, so no
    /// key is generated for these.
    fn address(scheme: Scheme, byte: u8) -> PublicKeyHash {
        PublicKeyHash::from_bytes(scheme, &[byte; 20]).expect("20 bytes is a hash")
    }

    fn row(keys: Vec<PublicKeyHash>, watermark: HighWatermark) -> EpochRow {
        EpochRow {
            watermark: Arc::new(RwLock::new(Some(Arc::new(RwLock::new(watermark))))),
            keys,
            unreadable: false,
        }
    }

    /// The count the activity lock protects is what the sampler reports after
    /// another thread panicked holding that lock, not a zero standing in for it.
    #[test]
    fn a_poisoned_activity_lock_still_counts_signatures() {
        let activity = Arc::new(Mutex::new(SigningActivity::default()));
        activity.lock().unwrap().total_signatures = 7;
        let poisoner = Arc::clone(&activity);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock().unwrap();
            panic!("poison the activity lock");
        })
        .join();
        assert!(activity.is_poisoned());

        let dir = TempDir::new().unwrap();
        let tz4 = address(Scheme::Bls, 9);
        let watermark = new_mixed_watermark(dir.path(), &[(tz4, None)]).unwrap();

        assert_eq!(
            Rows::sample(&activity, &row(vec![tz4], watermark)).signatures,
            7
        );
    }

    /// The row answers for the key that spends epochs rather than for the first
    /// key the card lists, which on a provisioned card is a tz4 one holding no
    /// epoch counter at all.
    #[test]
    fn the_row_reports_the_key_that_spends_epochs() {
        let dir = TempDir::new().unwrap();
        let tz4 = address(Scheme::Bls, 1);
        let tz6 = address(Scheme::Xmss, 2);
        let mut watermark =
            new_mixed_watermark(dir.path(), &[(tz4, None), (tz6, Some(DEPLOYED))]).unwrap();
        watermark.seed_epoch_floor(&tz6, 0).unwrap();

        assert_eq!(
            row(vec![tz4, tz6], watermark).value(),
            Some("16.7M/16.7M 388d".to_string())
        );
    }

    /// A card holding no key that spends epochs has no epoch to report on, and
    /// the value it answers with is what leaves the row undrawn rather than
    /// drawn empty.
    #[test]
    fn a_card_spending_no_epochs_has_no_epoch_value() {
        let dir = TempDir::new().unwrap();
        let tz4 = address(Scheme::Bls, 3);
        let watermark = new_mixed_watermark(dir.path(), &[(tz4, None)]).unwrap();

        assert_eq!(row(vec![tz4], watermark).value(), None);
    }

    /// A wallet the page could not read is not a card holding no key that
    /// spends epochs: the row is drawn, saying it cannot answer, where a card
    /// that really holds none leaves it out. The signer may be serving
    /// signatures from that card while its wallet files will not read.
    #[test]
    fn an_unreadable_wallet_leaves_the_row_saying_it_cannot_answer() {
        let dir = TempDir::new().unwrap();
        let tz4 = address(Scheme::Bls, 5);
        let watermark = new_mixed_watermark(dir.path(), &[(tz4, None)]).unwrap();
        let held = Arc::new(RwLock::new(Some(Arc::new(RwLock::new(watermark)))));

        let unreadable = EpochRow::new(held.clone(), &crate::tezos_signer::CardKeys::Unreadable);
        let listed = EpochRow::new(
            held,
            &crate::tezos_signer::CardKeys::Listed(vec![crate::tezos_signer::TezosKey {
                name: "consensus_tz4".to_string(),
                value: tz4.to_b58check(),
            }]),
        );

        assert_eq!(unreadable.value(), Some(UNKNOWN.to_string()));
        assert_eq!(
            listed.value(),
            None,
            "a card whose keys read and spend no epochs has no row"
        );
    }

    /// A key this page cannot address is not a key the card does not hold:
    /// the row would otherwise read exactly as it does on a card holding no
    /// epoch-spending key at all.
    #[test]
    fn an_unreadable_address_is_not_a_card_that_spends_no_epochs() {
        let dir = TempDir::new().unwrap();
        let tz4 = address(Scheme::Bls, 6);
        let watermark = new_mixed_watermark(dir.path(), &[(tz4, None)]).unwrap();
        let mut row = row(vec![tz4], watermark);
        row.unreadable = true;

        assert_eq!(row.value(), Some(UNKNOWN.to_string()));
    }

    /// A counter not established is not a counter run down: the key has signed
    /// at no epoch and holds every one it was generated with, so the row says
    /// it cannot tell rather than reporting nothing left.
    #[test]
    fn an_unestablished_counter_is_not_an_exhausted_one() {
        let dir = TempDir::new().unwrap();
        let tz6 = address(Scheme::Xmss, 4);
        let watermark = new_mixed_watermark(dir.path(), &[(tz6, Some(DEPLOYED))]).unwrap();

        assert_eq!(row(vec![tz6], watermark).value(), Some(UNKNOWN.to_string()));
    }

    /// A countdown reporting more than is left is one nobody rotates a key in
    /// time against, so the shortening truncates. No count it produces is wider
    /// than five characters, which is what holds three figures inside the value
    /// column at any range a key can carry.
    #[test]
    fn a_shortened_count_truncates_and_stays_narrow() {
        for (count, shown) in [
            (0u64, "0"),
            (9_999, "9999"),
            (10_000, "10k"),
            (999_999, "999k"),
            (1_000_000, "1.0M"),
            (16_777_216, "16.7M"),
            (99_999_999, "99.9M"),
            (100_000_000, "100M"),
            (999_999_999, "999M"),
            (1_000_000_000, "1.0G"),
            (u64::from(u32::MAX) + 1, "4.2G"),
        ] {
            assert_eq!(compact(count), shown);
            assert!(
                shown.len() <= 5,
                "{shown} is wider than the column was measured for"
            );
        }
    }

    /// The row a card holding `range` draws, through the store that produces it
    /// rather than through a second copy of the format.
    fn value_for(range: RangeInclusive<Epoch>) -> String {
        let dir = TempDir::new().unwrap();
        let tz6 = address(Scheme::Xmss, 5);
        let mut watermark = new_mixed_watermark(dir.path(), &[(tz6, Some(range))]).unwrap();
        watermark.seed_epoch_floor(&tz6, 0).unwrap();

        row(vec![tz6], watermark)
            .value()
            .expect("a key that spends epochs")
    }

    /// Every row has to land on the panel and clear of the one below it, which
    /// the layout constants do not settle on their own: a glyph's height and a
    /// value's width are the font's. One range per width the count ladder
    /// produces, so the fit holds for any range a key is generated with rather
    /// than for the one deployed today.
    #[test]
    fn every_row_lands_on_the_panel_clear_of_the_next() {
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();
        let mut drawn: Vec<(String, i32)> = ["Baker", "CPU Temp", "Uptime", "Signatures", "Epochs"]
            .into_iter()
            .map(|label| (label.to_string(), MARGIN))
            .collect();
        for last in [9_999, 999_999, 99_999_999, 999_999_999, Epoch::MAX] {
            drawn.push((value_for(0..=last), VALUE_COL_X));
        }
        drawn.push((format_epochs(None), VALUE_COL_X));

        for (text, x) in drawn {
            let bounds = font
                .get_rendered_dimensions_aligned(
                    text.as_str(),
                    Point::new(x, row_y(ROWS - 1)),
                    VerticalPosition::Baseline,
                    HorizontalAlignment::Left,
                )
                .expect("the font renders these glyphs")
                .expect("a non-empty string has a bounding box");
            let corner = bounds.bottom_right().expect("a non-empty bounding box");

            assert!(
                corner.x < DISPLAY_WIDTH,
                "{text:?} reaches x={} past the {DISPLAY_WIDTH}px panel",
                corner.x
            );
            assert!(
                corner.y < DISPLAY_HEIGHT,
                "{text:?} reaches y={} past the {DISPLAY_HEIGHT}px panel",
                corner.y
            );
            assert!(
                bounds.size.height <= ROW_PITCH.unsigned_abs(),
                "{text:?} stands {}px tall against a {ROW_PITCH}px row pitch",
                bounds.size.height
            );
        }
    }

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
