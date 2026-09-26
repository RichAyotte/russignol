//! The lifetimes a tz6 key can be generated for, one button each.
//!
//! Tapping one asks for the key over that lifetime; as on `pages::provision`,
//! nothing reaches the card until the confirmation and the PIN behind it are
//! both answered.

use crate::events::AppEvent;
use crate::fonts;
use crate::provision::{Lifetime, Request};
use crate::widgets::Button;

use super::Page as PageTrait;
use super::{DISPLAY_WIDTH, drawn};
use crossbeam_channel::Sender;
use embedded_graphics::{Drawable, pixelcolor::BinaryColor, prelude::*};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

// The title and first row sit where `pages::provision` puts them, so the two
// pages line up. Four labels in one column would overrun the panel under the
// title, so they sit two to a row: two 110 px buttons and their gap span most
// of the panel's width, and two 40 px rows fill what is left of its height.
const TITLE_Y: i32 = 16;
const BUTTON_W: u32 = 110;
const BUTTON_H: u32 = 40;
const BUTTON_GAP: i32 = 8;
const FIRST_BUTTON_Y: i32 = 28;
const COLUMNS: usize = 2;

pub struct Page {
    app_sender: Sender<AppEvent>,
    buttons: Vec<(Button, Lifetime)>,
}

impl Page {
    pub fn new(app_sender: Sender<AppEvent>) -> Self {
        let step_x = BUTTON_W.cast_signed() + BUTTON_GAP;
        let step_y = BUTTON_H.cast_signed() + BUTTON_GAP;
        let left = (DISPLAY_WIDTH - (step_x + BUTTON_W.cast_signed())) / 2;
        let mut buttons = Vec::with_capacity(Lifetime::COUNT);
        let mut position = Point::new(left, FIRST_BUTTON_Y);
        for (index, lifetime) in Lifetime::ALL.into_iter().enumerate() {
            let mut button = Button::new_text(Size::new(BUTTON_W, BUTTON_H), lifetime.label());
            button.bounds.top_left = position;
            buttons.push((button, lifetime));
            position = if (index + 1) % COLUMNS == 0 {
                Point::new(left, position.y + step_y)
            } else {
                Point::new(position.x + step_x, position.y)
            };
        }

        Self {
            app_sender,
            buttons,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        drawn(FontRenderer::new::<fonts::FONT_MEDIUM>().render_aligned(
            "tz6 key lifetime",
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
        for (button, lifetime) in &self.buttons {
            if button.contains(point) {
                let _ = self
                    .app_sender
                    .send(AppEvent::ProvisionKey(Request::Xmss(*lifetime)));
                return true;
            }
        }
        let _ = self.app_sender.send(AppEvent::ShowProvision);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{BUTTON_W, Page, PageTrait, TITLE_Y};
    use crate::events::AppEvent;
    use crate::pages::test_ink::Ink;
    use crate::pages::{DISPLAY_HEIGHT, DISPLAY_WIDTH, assert_label_fits};
    use crate::provision::{Lifetime, Request};
    use embedded_graphics::prelude::Point;

    /// The points that pick one lifetime.
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

    fn position(lifetime: Lifetime) -> usize {
        Lifetime::ALL
            .iter()
            .position(|l| *l == lifetime)
            .expect("every lifetime is listed")
    }

    fn sweep() -> [Region; Lifetime::COUNT] {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut page = Page::new(tx);
        let mut regions: [Region; Lifetime::COUNT] = Default::default();

        for y in 0..DISPLAY_HEIGHT {
            for x in 0..DISPLAY_WIDTH {
                let point = Point::new(x, y);
                let consumed = PageTrait::<Ink>::handle_touch(&mut page, point);
                match rx.try_recv() {
                    Ok(AppEvent::ProvisionKey(Request::Xmss(lifetime))) => {
                        assert!(consumed, "a tap that picked {lifetime:?} was not consumed");
                        regions[position(lifetime)].add(point);
                    }
                    Ok(AppEvent::ShowProvision) => assert!(!consumed, "a miss was consumed"),
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

    #[test]
    fn each_lifetime_is_picked_by_the_whole_of_its_own_button() {
        let regions = sweep();
        let first = &regions[0];

        for (lifetime, region) in Lifetime::ALL.into_iter().zip(&regions) {
            assert!(region.taps > 0, "no tap on the panel reaches {lifetime:?}");
            assert_eq!(
                region.taps,
                (region.width() * region.height()).cast_unsigned() as usize,
                "{lifetime:?} answers for a dented rectangle, so something overlaps it"
            );
            assert_eq!(
                (region.width(), region.height()),
                (first.width(), first.height()),
                "{lifetime:?} is a different size from the first lifetime's button"
            );
            assert!(
                region.top > TITLE_Y,
                "{lifetime:?} is picked at y={}, over the title",
                region.top
            );
        }

        for row in regions.chunks(2) {
            assert_eq!(row[0].top, row[1].top, "a row's buttons are not level");
            assert!(row[0].right < row[1].left, "a row is not in listed order");
        }
        assert!(
            regions[1].bottom < regions[2].top,
            "the second row is not below the first"
        );
    }

    #[test]
    fn every_lifetime_label_fits_its_button() {
        for lifetime in Lifetime::ALL {
            assert_label_fits(lifetime.label(), BUTTON_W);
        }
    }
}
