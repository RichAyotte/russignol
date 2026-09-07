//! The card's keys under two tabs: where each one answers, and where its
//! double-signing guard stands.
//!
//! One subject over the same two or three keys, so the two views share a page
//! and the menu keeps the slot the second would have taken.

use crate::events::AppEvent;
use crate::widgets::Button;

use super::Page as PageTrait;
use super::{blockchain, watermarks};
use crossbeam_channel::Sender;
use embedded_graphics::{Drawable, pixelcolor::BinaryColor, prelude::*};
use russignol_signer_lib::HighWatermark;
use std::sync::{Arc, RwLock};

/// The tab labels, left to right.
pub(crate) const TABS: [&str; 2] = ["Blockchain", "Watermarks"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Blockchain,
    Watermarks,
}

pub struct Page {
    app_sender: Sender<AppEvent>,
    view: View,
    blockchain_tab: Button,
    watermarks_tab: Button,
    blockchain: blockchain::View,
    watermarks: watermarks::View,
}

impl Page {
    pub fn new(
        app_sender: Sender<AppEvent>,
        watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    ) -> Self {
        let (blockchain_tab, watermarks_tab) = super::tab_pair(TABS[0], TABS[1]);
        // One read of the card for both views: two would let the tabs disagree
        // about which keys the card holds, since the second read can land on
        // the other side of the cache the first one fills.
        let keys = crate::tezos_signer::get_keys();
        Self {
            app_sender,
            view: View::Blockchain,
            blockchain_tab,
            watermarks_tab,
            blockchain: blockchain::View::new(&keys),
            watermarks: watermarks::View::new(&keys, watermark),
        }
    }

    /// The view a tap at `point` selects, or `None` where it missed both tabs.
    fn tab_at(&self, point: Point) -> Option<View> {
        if self.blockchain_tab.contains(point) {
            Some(View::Blockchain)
        } else if self.watermarks_tab.contains(point) {
            Some(View::Watermarks)
        } else {
            None
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        self.blockchain_tab.filled = self.view == View::Blockchain;
        self.watermarks_tab.filled = self.view == View::Watermarks;
        self.blockchain_tab.draw(display)?;
        self.watermarks_tab.draw(display)?;

        match self.view {
            View::Blockchain => self.blockchain.draw(display),
            View::Watermarks => self.watermarks.draw(display),
        }
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        let Some(view) = self.tab_at(point) else {
            let _ = self.app_sender.send(AppEvent::ShowMenu);
            return false;
        };
        // Repaint only on an actual view change to spare the e-paper a refresh.
        if self.view != view {
            self.view = view;
            let _ = self.app_sender.send(AppEvent::Invalidate);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{Page, PageTrait};
    use crate::pages::test_ink::Ink;
    use crossbeam_channel::{Receiver, Sender};
    use embedded_graphics::prelude::Point;
    use russignol_signer_lib::HighWatermark;
    use std::sync::{Arc, RwLock};

    fn page() -> (
        Page,
        Sender<crate::events::AppEvent>,
        Receiver<crate::events::AppEvent>,
    ) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>> =
            Arc::new(RwLock::new(None));
        (Page::new(tx.clone(), watermark), tx, rx)
    }

    /// What the page puts on the panel below the tab bar, which is the part
    /// the open view owns: the bar is drawn either way and would otherwise
    /// make every frame overlap every other.
    fn body(page: &mut Page) -> std::collections::BTreeSet<(i32, i32)> {
        let mut ink = Ink::default();
        PageTrait::draw(page, &mut ink).expect("the ink target cannot fail");
        ink.0
            .into_iter()
            .filter(|&(_, y)| y > crate::pages::TABS_BOTTOM)
            .collect()
    }

    /// A tab draws its own view and none of the other's. A page drawing both
    /// prints one over the other, and a page drawing the wrong one answers a
    /// question the operator did not ask.
    #[test]
    fn each_tab_draws_its_own_view_and_not_the_other() {
        let (mut page, _tx, _rx) = page();
        let (left, right) = (
            page.blockchain_tab.bounds.center(),
            page.watermarks_tab.bounds.center(),
        );

        let chain = body(&mut page);
        PageTrait::<Ink>::handle_touch(&mut page, right);
        let marks = body(&mut page);

        assert!(!chain.is_empty(), "the blockchain view drew nothing");
        assert!(!marks.is_empty(), "the watermarks view drew nothing");
        assert!(
            chain.difference(&marks).next().is_some(),
            "the two views put the same ink on the panel"
        );
        PageTrait::<Ink>::handle_touch(&mut page, left);
        assert_eq!(
            body(&mut page),
            chain,
            "the first tab drew something else the second time it was opened"
        );
    }

    /// A tap on a tab switches the view and repaints; a tap anywhere else
    /// leaves this page for the menu.
    #[test]
    fn a_tap_switches_a_tab_and_anything_else_leaves() {
        let (mut page, _tx, rx) = page();
        let (left, right) = (
            page.blockchain_tab.bounds.center(),
            page.watermarks_tab.bounds.center(),
        );
        let opened_on = body(&mut page);

        assert!(PageTrait::<Ink>::handle_touch(&mut page, right));
        assert!(matches!(
            rx.try_recv(),
            Ok(crate::events::AppEvent::Invalidate)
        ));
        assert_ne!(body(&mut page), opened_on, "the tap drew the same view");

        assert!(PageTrait::<Ink>::handle_touch(&mut page, right));
        assert!(
            rx.try_recv().is_err(),
            "a tap on the open tab repaints an unchanged panel"
        );

        assert!(PageTrait::<Ink>::handle_touch(&mut page, left));
        assert!(matches!(
            rx.try_recv(),
            Ok(crate::events::AppEvent::Invalidate)
        ));
        assert_eq!(body(&mut page), opened_on, "the tap drew the other view");

        let below = Point::new(left.x, crate::pages::DISPLAY_HEIGHT - 1);
        assert!(!PageTrait::<Ink>::handle_touch(&mut page, below));
        assert!(matches!(
            rx.try_recv(),
            Ok(crate::events::AppEvent::ShowMenu)
        ));
    }
}
