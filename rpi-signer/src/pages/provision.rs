//! The keys this device can provision, one button each.
//!
//! Tapping one asks for it; nothing reaches the card until the confirmation
//! behind it and the PIN behind that are both answered.

use crate::events::AppEvent;
use crate::fonts;
use crate::widgets::Button;

use super::Page as PageTrait;
use super::{DISPLAY_WIDTH, capitalize, drawn};
use crossbeam_channel::Sender;
use embedded_graphics::{Drawable, pixelcolor::BinaryColor, prelude::*};
use russignol_signer_lib::DeviceKey;
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

const TITLE_Y: i32 = 16;
const BUTTON_W: u32 = 200;
const BUTTON_H: u32 = 26;
const BUTTON_GAP: i32 = 5;
const FIRST_BUTTON_Y: i32 = 28;

/// Top edge of each key's button, one row per [`DeviceKey::ALL`] entry.
///
/// Laid out here rather than counted at construction, so no row index has to
/// be narrowed to a coordinate and no button can be placed on a fallback row.
const BUTTON_Y: [i32; DeviceKey::COUNT] = {
    let mut rows = [FIRST_BUTTON_Y; DeviceKey::COUNT];
    let mut row = 1;
    while row < DeviceKey::COUNT {
        rows[row] = rows[row - 1] + BUTTON_H.cast_signed() + BUTTON_GAP;
        row += 1;
    }
    rows
};

/// What the button for `key` is labelled.
fn button_label(key: DeviceKey) -> String {
    capitalize(key.device_alias())
}

pub struct Page {
    app_sender: Sender<AppEvent>,
    buttons: Vec<(Button, DeviceKey)>,
}

impl Page {
    pub fn new(app_sender: Sender<AppEvent>) -> Self {
        let x = (DISPLAY_WIDTH - BUTTON_W.cast_signed()) / 2;
        let buttons = DeviceKey::ALL
            .into_iter()
            .zip(BUTTON_Y)
            .map(|(key, y)| {
                let mut button =
                    Button::new_text(Size::new(BUTTON_W, BUTTON_H), &button_label(key));
                button.bounds.top_left = Point::new(x, y);
                (button, key)
            })
            .collect();

        Self {
            app_sender,
            buttons,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        drawn(FontRenderer::new::<fonts::FONT_MEDIUM>().render_aligned(
            "Replace a key",
            Point::new(DISPLAY_WIDTH / 2, TITLE_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        ))?;

        for (button, _) in &self.buttons {
            button.draw(display)?;
        }
        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        for (button, key) in &self.buttons {
            if button.contains(point) {
                let _ = self.app_sender.send(AppEvent::ProvisionKey(*key));
                return true;
            }
        }
        let _ = self.app_sender.send(AppEvent::ShowMenu);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{BUTTON_W, Page, PageTrait, TITLE_Y, button_label};
    use crate::events::AppEvent;
    use crate::pages::test_ink::Ink;
    use crate::pages::{DISPLAY_HEIGHT, DISPLAY_WIDTH, assert_label_fits};
    use embedded_graphics::prelude::Point;
    use russignol_signer_lib::DeviceKey;

    /// The points that pick one key.
    #[derive(Default)]
    struct Region {
        taps: usize,
        left: i32,
        right: i32,
        top: i32,
        bottom: i32,
    }

    impl Region {
        fn add(&mut self, point: Point) {
            if self.taps == 0 {
                (self.left, self.right) = (point.x, point.x);
                (self.top, self.bottom) = (point.y, point.y);
            } else {
                self.left = self.left.min(point.x);
                self.right = self.right.max(point.x);
                self.top = self.top.min(point.y);
                self.bottom = self.bottom.max(point.y);
            }
            self.taps += 1;
        }

        fn width(&self) -> i32 {
            self.right - self.left + 1
        }

        fn height(&self) -> i32 {
            self.bottom - self.top + 1
        }
    }

    /// Tap every point on the panel and record which key each one picks.
    ///
    /// Driven through `handle_touch` alone, so what it measures is what a
    /// finger reaches rather than where the buttons were put.
    fn sweep() -> [Region; DeviceKey::COUNT] {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut page = Page::new(tx);
        let mut regions: [Region; DeviceKey::COUNT] = Default::default();

        for y in 0..DISPLAY_HEIGHT {
            for x in 0..DISPLAY_WIDTH {
                let point = Point::new(x, y);
                let consumed = PageTrait::<Ink>::handle_touch(&mut page, point);
                match rx.try_recv() {
                    Ok(AppEvent::ProvisionKey(key)) => {
                        assert!(consumed, "a tap that picked {key:?} was not consumed");
                        regions[key.index()].add(point);
                    }
                    Ok(AppEvent::ShowMenu) => assert!(!consumed, "a miss was consumed"),
                    other => panic!("a tap at {point:?} answered with {other:?}"),
                }
                assert!(
                    rx.try_recv().is_err(),
                    "one tap at {point:?} sent more than one event"
                );
            }
        }
        regions
    }

    /// Each key answers for one solid rectangle of the panel, the three are
    /// the same size, centred, clear of the title and stacked in
    /// `DeviceKey::ALL` order. What is read here is where the taps landed
    /// rather than where the layout says the buttons are, so a layout that
    /// puts one button over another, off the panel or out of order is a
    /// rectangle that comes back dented, clipped or in the wrong place.
    ///
    /// A key short of its own rectangle is one a finger cannot fully reach,
    /// and a key answering inside another's is a finger asking to replace a
    /// key the operator did not pick.
    #[test]
    fn each_key_is_picked_by_the_whole_of_its_own_button() {
        let regions = sweep();
        let first = &regions[DeviceKey::ALL[0].index()];

        for key in DeviceKey::ALL {
            let region = &regions[key.index()];
            assert!(region.taps > 0, "no tap on the panel reaches {key:?}");
            assert_eq!(
                region.taps,
                (region.width() * region.height()).cast_unsigned() as usize,
                "{key:?} answers for a dented rectangle, so something overlaps it"
            );
            assert_eq!(
                (region.width(), region.height()),
                (first.width(), first.height()),
                "{key:?} is a different size from the first key's button"
            );
            assert_eq!(
                region.left + region.right,
                DISPLAY_WIDTH - 1,
                "{key:?} is not centred on the panel"
            );
            assert!(
                region.top > TITLE_Y,
                "{key:?} is picked at y={}, over a title with its baseline at {TITLE_Y}",
                region.top
            );
        }

        for pair in DeviceKey::ALL.windows(2) {
            let (above, below) = (&regions[pair[0].index()], &regions[pair[1].index()]);
            assert!(
                above.bottom < below.top,
                "{:?} is picked below {:?}, which is not the order they are listed in",
                pair[0],
                pair[1]
            );
        }
    }

    /// Every key this page offers fits the button naming it.
    #[test]
    fn every_key_label_fits_its_button() {
        for key in DeviceKey::ALL {
            assert_label_fits(&button_label(key), BUTTON_W);
        }
    }
}
