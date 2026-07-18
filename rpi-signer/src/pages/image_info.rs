//! Flashed-image provenance screen, reached from About or the greeting.
//!
//! Two sub-views share one page: a posture summary (version, hardened/dev mode,
//! signature verdict, flash date) and the recorded checksums (image and rootfs
//! SHA-256, host version, card id). Two tabs across the top switch between them;
//! a tap below the tabs returns to whichever page opened this one.

use crate::events::{AppEvent, BackTarget};
use crate::fonts;
use crate::image_info;
use crate::text;
use crate::widgets::Button;

use super::Page as PageTrait;
use crossbeam_channel::Sender;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::{DrawTarget, Point, Size},
};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Posture,
    Checksums,
}

pub struct Page {
    app_sender: Sender<AppEvent>,
    back: BackTarget,
    view: View,
    summary_tab: Button,
    checksums_tab: Button,
    posture_rows: Vec<image_info::Row>,
    checksum_rows: Vec<image_info::Row>,
}

const MARGIN: i32 = 6;
const TAB_Y: i32 = 2;
const TAB_W: u32 = 116;
const TAB_H: u32 = 30;
const TAB_GAP: i32 = 6;
const VALUE_COL_X: i32 = 92;
const ROW_Y: [i32; 4] = [52, 72, 92, 112];

impl Page {
    pub fn new(app_sender: Sender<AppEvent>, back: BackTarget) -> Self {
        let info = image_info::image_info();
        let mut summary_tab = Button::new_text(Size::new(TAB_W, TAB_H), "Summary");
        summary_tab.bounds.top_left = Point::new(MARGIN, TAB_Y);
        let mut checksums_tab = Button::new_text(Size::new(TAB_W, TAB_H), "Checksums");
        checksums_tab.bounds.top_left = Point::new(MARGIN + TAB_W.cast_signed() + TAB_GAP, TAB_Y);
        Self {
            app_sender,
            back,
            view: View::Posture,
            summary_tab,
            checksums_tab,
            posture_rows: info.posture_rows(),
            checksum_rows: info.checksum_rows(),
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        self.summary_tab.filled = self.view == View::Posture;
        self.checksums_tab.filled = self.view == View::Checksums;
        self.summary_tab.draw(display)?;
        self.checksums_tab.draw(display)?;

        let (rows, mono) = match self.view {
            View::Posture => (&self.posture_rows, false),
            View::Checksums => (&self.checksum_rows, true),
        };
        for (row, &y) in rows.iter().zip(ROW_Y.iter()) {
            draw_label_value(display, row.label, row.value.as_str(), y, mono);
        }

        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        let tapped = if self.summary_tab.contains(point) {
            Some(View::Posture)
        } else if self.checksums_tab.contains(point) {
            Some(View::Checksums)
        } else {
            None
        };

        if let Some(view) = tapped {
            // Repaint only on an actual view change to spare the e-paper a refresh.
            if self.view != view {
                self.view = view;
                let _ = self.app_sender.send(AppEvent::Invalidate);
            }
            true
        } else {
            let event = match self.back {
                BackTarget::About => AppEvent::ShowAbout,
                BackTarget::Greeting => AppEvent::ShowGreeting,
            };
            let _ = self.app_sender.send(event);
            false
        }
    }
}

/// Draw a label at the left margin and its value in the value column. Checksum
/// values are long hex, so they render in the monospace font and truncate in
/// the middle to fit the narrow panel.
fn draw_label_value<D: DrawTarget<Color = BinaryColor>>(
    display: &mut D,
    label: &str,
    value: &str,
    y: i32,
    mono_value: bool,
) {
    FontRenderer::new::<fonts::FONT_MEDIUM>()
        .render_aligned(
            label,
            Point::new(MARGIN, y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Left,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

    let value_point = Point::new(VALUE_COL_X, y);
    if mono_value {
        FontRenderer::new::<fonts::FONT_MONO_SMALL>()
            .render_aligned(
                text::truncate_middle(value, 10, 6).as_str(),
                value_point,
                VerticalPosition::Baseline,
                HorizontalAlignment::Left,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();
    } else {
        FontRenderer::new::<fonts::FONT_MEDIUM>()
            .render_aligned(
                value,
                value_point,
                VerticalPosition::Baseline,
                HorizontalAlignment::Left,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();
    }
}
