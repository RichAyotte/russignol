use crate::events::AppEvent;
use crate::widgets::Button;

use super::Page as PageTrait;
use crossbeam_channel::Sender;
use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};

pub struct Page {
    app_sender: Sender<AppEvent>,
    buttons: Vec<(Button, AppEvent)>,
}

// Layout: 2x3 grid on 250x122 display
use super::{DISPLAY_HEIGHT, DISPLAY_WIDTH};
const BUTTON_W: u32 = 110;
const BUTTON_H: u32 = 34;
const GAP_X: i32 = 10;
const GAP_Y: i32 = 6;

impl Page {
    pub fn new(app_sender: Sender<AppEvent>) -> Self {
        let bw = BUTTON_W.cast_signed();
        let bh = BUTTON_H.cast_signed();
        let grid_w = bw * 2 + GAP_X;
        let grid_h = bh * 3 + GAP_Y * 2;
        let x0 = (DISPLAY_WIDTH - grid_w) / 2;
        let y0 = (DISPLAY_HEIGHT - grid_h) / 2;

        let size = Size::new(BUTTON_W, BUTTON_H);
        let mut buttons = vec![
            (Button::new_text(size, "System"), AppEvent::ShowStatus),
            (Button::new_text(size, "Activity"), AppEvent::ShowSignatures),
            (Button::new_text(size, "Keys"), AppEvent::ShowKeys),
            (Button::new_text(size, "Provision"), AppEvent::ShowProvision),
            (Button::new_text(size, "About"), AppEvent::ShowAbout),
            (
                Button::new_text(size, "Shutdown"),
                AppEvent::RequestShutdown,
            ),
        ];

        for (i, (button, _)) in buttons.iter_mut().enumerate() {
            let col = i32::try_from(i % 2).unwrap_or(0);
            let row = i32::try_from(i / 2).unwrap_or(0);
            button.bounds.top_left = Point::new(x0 + col * (bw + GAP_X), y0 + row * (bh + GAP_Y));
        }

        Self {
            app_sender,
            buttons,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        for (button, _) in &self.buttons {
            button.draw(display)?;
        }
        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        for (button, event) in &self.buttons {
            if button.contains(point) {
                let _ = self.app_sender.send(event.clone());
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{BUTTON_W, Page};
    use crate::pages::assert_label_fits;

    /// Every menu entry fits the button carrying it. A label that overruns is
    /// drawn past the button's edge, and the entry beside it is what the
    /// operator reads it as.
    #[test]
    fn every_menu_label_fits_its_button() {
        let (tx, _rx) = crossbeam_channel::unbounded();

        for (button, _) in &Page::new(tx).buttons {
            let label = button.text.as_ref().expect("a text button");
            assert_label_fits(label, BUTTON_W);
        }
    }
}
