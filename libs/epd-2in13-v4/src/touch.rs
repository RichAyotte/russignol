use crate::common::{HEIGHT, Rotation, WIDTH};
use crate::error::EpdResult;
use crate::touch_driver::{self, TouchDriver};
use crossbeam_channel::Receiver;
use embedded_graphics::geometry::Point;
use linux_embedded_hal::gpio_cdev::{EventRequestFlags, Line, LineRequestFlags};

pub struct Touch {
    driver: TouchDriver,
    _int_pin: Line,
}

impl Touch {
    pub fn new(
        driver: TouchDriver,
        int_pin: Line,
        rotation: Rotation,
    ) -> EpdResult<(Self, Receiver<Point>)> {
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let events = int_pin.events(
            LineRequestFlags::INPUT,
            EventRequestFlags::FALLING_EDGE,
            "touchscreen-int",
        )?;

        let i2c_arc = driver.i2c_arc();

        std::thread::spawn(move || {
            let touch_event_to_point: fn(touch_driver::Event) -> Point = match rotation {
                Rotation::Deg0 => |touch_event| {
                    Point::new(
                        WIDTH.cast_signed() - 1 - touch_event.x,
                        HEIGHT.cast_signed() - 1 - touch_event.y,
                    )
                },
                Rotation::Deg90 => |touch_event| {
                    Point::new(HEIGHT.cast_signed() - 1 - touch_event.y, touch_event.x)
                },
            };

            for _ in events.flatten() {
                match touch_driver::read_and_clear_touch_data(&i2c_arc) {
                    Ok(Some(touch_event)) => {
                        let point = touch_event_to_point(touch_event);
                        event_tx.send(point).unwrap();
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log::error!("Error reading touch data: {e}");
                    }
                }
            }
        });
        let touch = Self {
            driver,
            _int_pin: int_pin,
        };

        Ok((touch, event_rx))
    }

    pub(crate) fn sleep(&mut self) -> EpdResult<()> {
        self.driver.sleep()
    }
}
