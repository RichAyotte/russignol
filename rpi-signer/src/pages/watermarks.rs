use crate::fonts;
use crate::tezos_signer;

use embedded_graphics::{
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point},
};
use russignol_signer_lib::{HighWatermark, PublicKeyHash};
use std::sync::{Arc, RwLock};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

use super::{capitalize, drawn};

struct KeyInfo {
    alias: String,
    pkh: PublicKeyHash,
}

/// The keys this view has rows for, or the fact that the card's wallet would
/// not read. A table with no rows says the card holds no keys, which is what a
/// card before setup looks like, and the store may hold marks for keys an
/// unreadable wallet cannot name.
enum Keys {
    Listed(Vec<KeyInfo>),
    Unreadable,
}

/// One of the two views the keys page carries: the level each key's
/// double-signing guard stands at, in memory and on disk.
pub struct View {
    watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    keys: Keys,
}

impl View {
    pub fn new(
        keys: &tezos_signer::CardKeys,
        watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    ) -> Self {
        let keys = match keys {
            tezos_signer::CardKeys::Unreadable => Keys::Unreadable,
            tezos_signer::CardKeys::Listed(listed) => {
                let parsed: Result<Vec<KeyInfo>, String> = listed
                    .iter()
                    .map(|k| {
                        PublicKeyHash::from_b58check(&k.value)
                            .map(|pkh| KeyInfo {
                                alias: capitalize(&k.name),
                                pkh,
                            })
                            .map_err(|e| format!("Key {} has an unreadable address: {e}", k.name))
                    })
                    .collect();
                match parsed {
                    Ok(keys) => Keys::Listed(keys),
                    // Dropping the one row would read as a key the device
                    // does not hold, so the wallet is drawn unreadable whole.
                    Err(e) => {
                        log::error!("{e}");
                        Keys::Unreadable
                    }
                }
            }
        };

        Self { watermark, keys }
    }

    /// Every key's in-memory and on-disk level, read under one pair of locks
    /// and returned before a glyph is drawn.
    ///
    /// A guard taken per row would take the store's read lock once per key, and
    /// one held across the rendering would stall the signing path's own write
    /// for the length of a panel draw.
    fn read_levels(&self, keys: &[KeyInfo]) -> Vec<(Option<u32>, Option<u32>)> {
        let guard = match self.watermark.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(wm_arc) = guard.as_ref() else {
            return vec![(None, None); keys.len()];
        };
        let wm = match wm_arc.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        keys.iter()
            .map(|key| (wm.get_max_level(&key.pkh), wm.get_persisted_level(&key.pkh)))
            .collect()
    }
}

// Layout constants for 250×122 display
use super::DISPLAY_HEIGHT;
/// Baseline of the column headers. Glyphs rise about eleven pixels above it,
/// so a baseline any higher puts their tops inside the tab bar drawn over this
/// view; `nothing_drawn_reaches_under_the_tab_bar` is what this answers to.
const HEADER_ROW_Y: i32 = 44;
const DATA_START_Y: i32 = 66;
const DATA_ROW_GAP: i32 = 28;
const COL_KEY_X: i32 = 6;
/// Centres of the two level columns, placed so that an alias, a level and a
/// level clear each other on a 250px panel. A glyph's width is the font's, so
/// `the_three_cells_of_a_row_clear_each_other` is what these answer to.
const COL_MEM_X: i32 = 141;
const COL_DISK_X: i32 = 209;

/// Data rows whose baseline lands on the panel, from the layout above rather
/// than counted against it: the two drift the first time a row gap or a start
/// offset moves, and the row that falls off is drawn to nobody.
const MAX_DATA_ROWS: usize = 1 + ((DISPLAY_HEIGHT - DATA_START_Y) / DATA_ROW_GAP) as usize;

/// Every key the device provisions has to have a row: a tz6 key whose marks
/// are not on this page is one whose double-sign protection nobody can read.
const _: () = assert!(MAX_DATA_ROWS >= russignol_signer_lib::DeviceKey::COUNT);

/// What a cell holds where the store reports no level.
///
/// Every glyph in it has to be one the font holds: the renderer refuses one it
/// does not, and this page drops that refusal, so the cell would be left blank
/// and read as a level of nothing rather than as one nobody has written yet.
const UNKNOWN: &str = "N/A";

/// What the first data row says where the wallet would not read, in place of
/// rows: the store may hold marks for keys this page cannot name, and no rows
/// reads as a card holding no keys.
const UNREADABLE: &str = "Wallet unreadable";

/// The keys this page can show, and the ones it cannot.
///
/// A row past the last pixel row is drawn and seen by nobody, so a key beyond
/// the fit has to be reported as missing rather than emitted into the void: the
/// page's whole subject is what a key's marks are, and a key silently absent
/// reads as a key the device does not hold.
fn rows_that_fit(keys: usize) -> (usize, usize) {
    let shown = keys.min(MAX_DATA_ROWS);
    (shown, keys - shown)
}

impl View {
    /// Draw each key's watermark levels.
    pub fn draw<D: DrawTarget<Color = BinaryColor>>(
        &self,
        display: &mut D,
    ) -> Result<(), D::Error> {
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

        let keys: &[KeyInfo] = match &self.keys {
            Keys::Listed(keys) => keys,
            Keys::Unreadable => &[],
        };
        let (shown, hidden) = rows_that_fit(keys.len());

        // The Key column header carries the count the rows cannot: a key with
        // no row is a key whose marks this view does not answer for, and
        // saying so is the only thing separating that from a key the device
        // does not hold.
        let key_header = if hidden == 0 {
            "Key".to_string()
        } else {
            format!("Key ({shown} of {})", keys.len())
        };
        drawn(font.render_aligned(
            key_header.as_str(),
            Point::new(COL_KEY_X, HEADER_ROW_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Left,
            FontColor::Transparent(BinaryColor::Off),
            display,
        ))?;
        drawn(font.render_aligned(
            "Mem",
            Point::new(COL_MEM_X, HEADER_ROW_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        ))?;
        drawn(font.render_aligned(
            "Disk",
            Point::new(COL_DISK_X, HEADER_ROW_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        ))?;

        if matches!(self.keys, Keys::Unreadable) {
            return drawn(font.render_aligned(
                UNREADABLE,
                Point::new(COL_KEY_X, DATA_START_Y),
                VerticalPosition::Baseline,
                HorizontalAlignment::Left,
                FontColor::Transparent(BinaryColor::Off),
                display,
            ));
        }

        let shown_keys = &keys[..shown];
        for (i, (key, (mem_level, disk_level))) in shown_keys
            .iter()
            .zip(self.read_levels(shown_keys))
            .enumerate()
        {
            let y = DATA_START_Y + i32::try_from(i).unwrap_or(0) * DATA_ROW_GAP;

            let level_text = |level: Option<u32>| -> std::borrow::Cow<'static, str> {
                level.map_or(std::borrow::Cow::Borrowed(UNKNOWN), |l| {
                    std::borrow::Cow::Owned(l.to_string())
                })
            };
            let mem_str = level_text(mem_level);
            let disk_str = level_text(disk_level);

            drawn(font.render_aligned(
                key.alias.as_str(),
                Point::new(COL_KEY_X, y),
                VerticalPosition::Baseline,
                HorizontalAlignment::Left,
                FontColor::Transparent(BinaryColor::Off),
                display,
            ))?;
            drawn(font.render_aligned(
                &*mem_str,
                Point::new(COL_MEM_X, y),
                VerticalPosition::Baseline,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            ))?;
            drawn(font.render_aligned(
                &*disk_str,
                Point::new(COL_DISK_X, y),
                VerticalPosition::Baseline,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            ))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COL_DISK_X, COL_KEY_X, COL_MEM_X, DATA_ROW_GAP, DATA_START_Y, DISPLAY_HEIGHT, FontRenderer,
        MAX_DATA_ROWS, Point, UNKNOWN, UNREADABLE, VerticalPosition, capitalize, fonts,
        rows_that_fit,
    };
    use crate::pages::{DISPLAY_WIDTH, TABS_BOTTOM};
    use crate::tezos_signer::CardKeys;

    fn no_store() -> std::sync::Arc<
        std::sync::RwLock<
            Option<std::sync::Arc<std::sync::RwLock<russignol_signer_lib::HighWatermark>>>,
        >,
    > {
        std::sync::Arc::new(std::sync::RwLock::new(None))
    }

    /// The ink the view leaves for `card`.
    fn ink_of(card: &CardKeys) -> std::collections::BTreeSet<(i32, i32)> {
        let mut ink = crate::pages::test_ink::Ink::default();
        super::View::new(card, no_store())
            .draw(&mut ink)
            .expect("the ink target cannot fail");
        ink.0
    }

    /// The ink of the unreadable marker on the first data row, spelled out
    /// rather than taken from the constant the page draws.
    fn marker_ink() -> std::collections::BTreeSet<(i32, i32)> {
        let mut marker = crate::pages::test_ink::Ink::default();
        FontRenderer::new::<fonts::FONT_MEDIUM>()
            .render_aligned(
                "Wallet unreadable",
                Point::new(COL_KEY_X, DATA_START_Y),
                VerticalPosition::Baseline,
                u8g2_fonts::types::HorizontalAlignment::Left,
                u8g2_fonts::types::FontColor::Transparent(
                    embedded_graphics::pixelcolor::BinaryColor::Off,
                ),
                &mut marker,
            )
            .expect("the font draws the marker");
        assert!(!marker.0.is_empty());
        marker.0
    }

    /// A wallet that would not read draws the unreadable marker on the first
    /// data row, where a card naming no keys leaves that row blank: the two
    /// are told apart on the panel rather than only in the page's state.
    #[test]
    fn an_unreadable_wallet_is_not_a_card_with_no_keys() {
        assert!(
            marker_ink().is_subset(&ink_of(&CardKeys::Unreadable)),
            "the unreadable wallet did not draw the marker on the first data row"
        );
        assert!(
            marker_ink().is_disjoint(&ink_of(&CardKeys::Listed(Vec::new()))),
            "a card naming no keys drew on the first data row"
        );
    }

    /// A wallet naming an address that will not decode is drawn as unreadable
    /// whole: a row dropped for it would read as a key the device does not
    /// hold.
    #[test]
    fn an_address_that_will_not_read_makes_the_wallet_unreadable() {
        let card = CardKeys::Listed(vec![crate::tezos_signer::TezosKey {
            name: "consensus_tz4".to_string(),
            value: "tz4nope".to_string(),
        }]);
        assert!(
            marker_ink().is_subset(&ink_of(&card)),
            "an address that will not read was dropped rather than reported"
        );
    }

    /// The margin the two level columns are held inside.
    const MARGIN: i32 = 6;

    /// Nothing this view draws reaches under the tab bar above it, measured
    /// from the ink rather than from the constants the rows are placed by: ink
    /// under the bar is drawn behind a button and read by nobody.
    #[test]
    fn nothing_drawn_reaches_under_the_tab_bar() {
        use crate::pages::test_ink::Ink;
        use russignol_signer_lib::DeviceKey;

        let card = CardKeys::Listed(
            DeviceKey::ALL
                .into_iter()
                .map(|key| crate::tezos_signer::TezosKey {
                    name: key.device_alias().to_string(),
                    value: russignol_signer_lib::PublicKeyHash::from_bytes(
                        russignol_signer_lib::Scheme::Bls,
                        &[7u8; 20],
                    )
                    .expect("twenty bytes are an address")
                    .to_b58check(),
                })
                .collect(),
        );
        let view = super::View::new(&card, no_store());
        let mut ink = Ink::default();

        view.draw(&mut ink).expect("the ink target cannot fail");

        assert!(
            ink.top_row().is_some_and(|row| row > TABS_BOTTOM),
            "the view reached row {:?}, at or above a tab bar ending at {TABS_BOTTOM}",
            ink.top_row()
        );
    }

    /// The baseline of the last row this page will draw has to land on the
    /// panel, and the one after it has to not: a count taken independently of
    /// the layout constants drifts from them the first time either moves.
    #[test]
    fn the_row_count_is_the_number_the_layout_leaves_room_for() {
        let baseline = |row: usize| {
            DATA_START_Y + i32::try_from(row).expect("a row index fits") * DATA_ROW_GAP
        };

        assert!(
            baseline(MAX_DATA_ROWS - 1) <= DISPLAY_HEIGHT,
            "row {} has its baseline at {}, past the {DISPLAY_HEIGHT}px panel",
            MAX_DATA_ROWS - 1,
            baseline(MAX_DATA_ROWS - 1)
        );
        assert!(
            baseline(MAX_DATA_ROWS) > DISPLAY_HEIGHT,
            "row {MAX_DATA_ROWS} fits at {}, so the page is showing fewer keys than it could",
            baseline(MAX_DATA_ROWS)
        );
    }

    /// A row is an alias and two centred levels, and a glyph's width is the
    /// font's rather than the layout's — so three cells that clear each other
    /// on a 250px panel is a measurement, not an arithmetic the constants
    /// carry. An alias overrunning the Mem cell prints one over the other and
    /// leaves neither readable.
    #[test]
    fn the_three_cells_of_a_row_clear_each_other() {
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();
        let width = |text: &str| {
            let pixels = font
                .get_rendered_dimensions(text, Point::zero(), VerticalPosition::Baseline)
                .expect("the font draws these glyphs")
                .bounding_box
                .expect("a non-empty string has a bounding box")
                .size
                .width;
            i32::try_from(pixels).expect("a width on this panel")
        };

        // A level is a u32, but ten digits twice will not sit beside an alias
        // here. Eight covers a mainnet level for as long as this device runs —
        // 10^8 blocks is nineteen years at six seconds a block — so that is
        // what the columns are placed around rather than the type's range.
        let level = width("99999999").max(width(UNKNOWN));
        let cell = |centre: i32| (centre - level / 2, centre - level / 2 + level);
        let (mem_left, mem_right) = cell(COL_MEM_X);
        let (disk_left, disk_right) = cell(COL_DISK_X);

        for key in russignol_signer_lib::DeviceKey::ALL {
            let alias = capitalize(key.device_alias());
            let right = COL_KEY_X + width(&alias);
            assert!(
                right < mem_left,
                "{alias:?} reaches x={right}, into a Mem cell starting at {mem_left}"
            );
        }
        assert!(
            mem_right < disk_left,
            "the Mem cell reaches x={mem_right}, into a Disk cell starting at {disk_left}"
        );
        assert!(
            disk_right <= DISPLAY_WIDTH - MARGIN,
            "the Disk cell reaches x={disk_right}, past the {MARGIN}px margin"
        );
    }

    /// The marker for a level the store cannot report has to be a string this
    /// font draws: the renderer refuses a glyph it does not hold, and the page
    /// drops that refusal by design.
    #[test]
    fn the_unknown_marker_is_a_string_the_font_draws() {
        for marker in [UNKNOWN, UNREADABLE] {
            FontRenderer::new::<fonts::FONT_MEDIUM>()
                .get_rendered_dimensions(marker, Point::zero(), VerticalPosition::Baseline)
                .expect("the font draws every glyph in the marker");
        }
    }

    #[test]
    fn keys_beyond_the_fit_are_counted_not_dropped() {
        assert_eq!(rows_that_fit(0), (0, 0));
        assert_eq!(rows_that_fit(MAX_DATA_ROWS), (MAX_DATA_ROWS, 0));
        assert_eq!(rows_that_fit(MAX_DATA_ROWS + 2), (MAX_DATA_ROWS, 2));
    }
}
