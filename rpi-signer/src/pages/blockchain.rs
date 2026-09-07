use crate::chain_info;
use crate::fonts;
use crate::tezos_signer;

use super::drawn;
use embedded_graphics::{
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point},
};
use russignol_signer_lib::{DeviceKey, KeyRole};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

/// One of the two views the keys page carries: which address each role
/// answers at, and on which chain.
pub struct View {
    /// The chain this card is provisioned for, or `None` where its record
    /// would not read — which is not a chain that happens to be named for the
    /// marker an unread one draws.
    chain: Option<chain_info::ChainInfo>,
    /// What each role's row shows ([`KeyRole::ALL`] order): its address, or
    /// why this page has none to draw.
    key_rows: [String; KeyRole::COUNT],
}

/// What a row shows for a role the card names no key in.
const NOT_FOUND: &str = "Not found";

/// What this page draws where it could not read the answer at all: the card's
/// wallet files, or the record of the chain it is provisioned for. It is a
/// different statement from [`NOT_FOUND`], which tells the operator the card
/// is missing a key it may well be holding.
const UNKNOWN: &str = "Unknown";

use super::DISPLAY_WIDTH;
const CHAIN_NAME_Y: i32 = 44;
const CHAIN_ID_Y: i32 = 62;
const ICON_GAP: i32 = 8;

/// Vertical centre of the key row for a role, which is where its glyphs are
/// placed from.
const fn key_row_y(role: KeyRole) -> i32 {
    match role {
        KeyRole::Consensus => 84,
        KeyRole::Companion => 108,
    }
}

impl View {
    pub fn new(keys: &tezos_signer::CardKeys) -> Self {
        let key_rows = KeyRole::map_all(|role| key_row(keys, role));

        let chain = chain_info::read_chain_info()
            .inspect_err(|e| log::error!("Failed to read chain info: {e}"))
            .ok();

        Self { chain, key_rows }
    }

    fn chain_name(&self) -> &str {
        self.chain
            .as_ref()
            .map_or(UNKNOWN, |info| info.name.as_str())
    }

    fn chain_id(&self) -> &str {
        self.chain.as_ref().map_or(UNKNOWN, |info| info.id.as_str())
    }

    /// Draw each key's address and the chain they answer on.
    ///
    /// # Errors
    ///
    /// Returns an error if a write to the panel fails.
    pub fn draw<D: DrawTarget<Color = BinaryColor>>(
        &self,
        display: &mut D,
    ) -> Result<(), D::Error> {
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

        drawn(font.render_aligned(
            self.chain_name(),
            Point::new(DISPLAY_WIDTH / 2, CHAIN_NAME_Y),
            VerticalPosition::Center,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        ))?;

        drawn(font.render_aligned(
            self.chain_id(),
            Point::new(DISPLAY_WIDTH / 2, CHAIN_ID_Y),
            VerticalPosition::Center,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        ))?;

        for role in KeyRole::ALL {
            draw_key_row(display, &self.key_rows[role.index()], role)?;
        }
        Ok(())
    }
}

/// What one role's row shows.
///
/// A wallet that would not read leaves what the card holds unknown, which is
/// not the card missing that key: telling an operator a key is not found sends
/// them after a key the device may be signing with.
fn key_row(keys: &tezos_signer::CardKeys, role: KeyRole) -> String {
    match keys {
        tezos_signer::CardKeys::Unreadable => UNKNOWN.to_string(),
        tezos_signer::CardKeys::Listed(keys) => keys
            .iter()
            .find(|k| k.name == DeviceKey::Bls(role).device_alias())
            .map_or_else(
                || NOT_FOUND.to_string(),
                |k| crate::text::truncate_middle(&k.value, 10, 6),
            ),
    }
}

/// The icon and the row's y come from the role rather than from the caller:
/// both are strings or numbers a caller could pass in the other's place, and
/// the role is what decides each of them.
fn draw_key_row<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    key_display: &str,
    role: KeyRole,
) -> Result<(), D::Error> {
    let (icon_char, row_y) = (super::key_icon(role), key_row_y(role));
    let text_font = FontRenderer::new::<fonts::FONT_MONO_SMALL>();
    let icon_font = FontRenderer::new::<fonts::ICON_KEY>();

    let icon_width = icon_font
        .get_rendered_dimensions(icon_char, Point::zero(), VerticalPosition::Center)
        .ok()
        .and_then(|d| d.bounding_box.map(|b| b.size.width.cast_signed()))
        .unwrap_or(16);

    let text_width = text_font
        .get_rendered_dimensions(key_display, Point::zero(), VerticalPosition::Center)
        .ok()
        .and_then(|d| d.bounding_box.map(|b| b.size.width.cast_signed()))
        .unwrap_or(0);

    let total_width = icon_width + ICON_GAP + text_width;
    let icon_x = (DISPLAY_WIDTH - total_width) / 2;
    let text_x = icon_x + icon_width + ICON_GAP;

    drawn(icon_font.render_aligned(
        icon_char,
        Point::new(icon_x, row_y),
        VerticalPosition::Center,
        HorizontalAlignment::Left,
        FontColor::Transparent(BinaryColor::Off),
        display,
    ))?;

    drawn(text_font.render_aligned(
        key_display,
        Point::new(text_x, row_y),
        VerticalPosition::Center,
        HorizontalAlignment::Left,
        FontColor::Transparent(BinaryColor::Off),
        display,
    ))
}

#[cfg(test)]
mod tests {
    use super::{View, key_row};
    use crate::chain_info::ChainInfo;
    use crate::tezos_signer::{CardKeys, TezosKey};
    use russignol_signer_lib::{DeviceKey, KeyRole};

    fn page(chain: Option<ChainInfo>) -> View {
        View {
            chain,
            key_rows: KeyRole::map_all(|_| String::new()),
        }
    }

    /// Nothing this view draws reaches under the tab bar above it, measured
    /// from the ink rather than from the constants the rows are placed by: ink
    /// under the bar is drawn behind a button and read by nobody.
    #[test]
    fn nothing_drawn_reaches_under_the_tab_bar() {
        use crate::pages::TABS_BOTTOM;
        use crate::pages::test_ink::Ink;

        let view = View {
            chain: Some(ChainInfo {
                id: "NetXdQprcVkpaWU".to_string(),
                name: "Mainnet".to_string(),
                blocks_per_cycle: None,
            }),
            key_rows: KeyRole::map_all(|_| "tz4HVR43NNbNhLGTHUNCGWEUjYmDT1RGcNjZ".to_string()),
        };
        let mut ink = Ink::default();

        view.draw(&mut ink).expect("the ink target cannot fail");

        assert!(
            ink.top_row().is_some_and(|row| row > TABS_BOTTOM),
            "the view reached row {:?}, at or above a tab bar ending at {TABS_BOTTOM}",
            ink.top_row()
        );
    }

    /// The two chain rows show what the card's record says, and a record that
    /// would not read leaves them saying the page has no answer rather than
    /// naming a chain. Both spellings are pinned as the operator reads them.
    #[test]
    fn the_chain_rows_show_the_record_or_say_there_is_none() {
        let read = page(Some(ChainInfo {
            id: "NetXdQprcVkpaWU".to_string(),
            name: "Mainnet".to_string(),
            blocks_per_cycle: None,
        }));
        assert_eq!(read.chain_name(), "Mainnet");
        assert_eq!(read.chain_id(), "NetXdQprcVkpaWU");

        let unread = page(None);
        assert_eq!(unread.chain_name(), "Unknown");
        assert_eq!(unread.chain_id(), "Unknown");
    }

    /// A wallet the device could not read leaves what the card holds unknown.
    /// Saying a key is not found instead sends an operator after a key the
    /// signer may be serving signatures with.
    ///
    /// The two readings are spelled out here rather than taken from the
    /// constants the page draws: an assertion against those holds however they
    /// are worded, the day they are worded the same included.
    #[test]
    fn an_unreadable_wallet_is_not_a_card_missing_its_keys() {
        for role in KeyRole::ALL {
            assert_eq!(key_row(&CardKeys::Unreadable, role), "Unknown");
            assert_eq!(key_row(&CardKeys::Listed(Vec::new()), role), "Not found");
        }
    }

    /// A row shows the address of the key filed under its own role's alias,
    /// and nothing of the key filed under the other's: two rows drawing one
    /// address is a card that reads as holding one key twice.
    #[test]
    fn a_row_shows_the_address_filed_under_its_role() {
        let address = |role: KeyRole| format!("tz4{}0000000000000000000", role.index());
        let card = CardKeys::Listed(
            KeyRole::ALL
                .into_iter()
                .map(|role| TezosKey {
                    name: DeviceKey::Bls(role).device_alias().to_string(),
                    value: address(role),
                })
                .collect(),
        );

        for role in KeyRole::ALL {
            assert!(
                key_row(&card, role).starts_with(&address(role)[..8]),
                "the {role:?} row does not show its own address: {}",
                key_row(&card, role)
            );
        }

        for role in KeyRole::ALL {
            let only_other = CardKeys::Listed(vec![TezosKey {
                name: DeviceKey::Bls(role).device_alias().to_string(),
                value: address(role),
            }]);
            for absent in KeyRole::ALL.into_iter().filter(|r| *r != role) {
                assert_eq!(key_row(&only_other, absent), "Not found");
            }
        }
    }
}
