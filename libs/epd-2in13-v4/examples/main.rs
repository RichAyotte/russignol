use chrono::{Local, Timelike};
use crossbeam_channel::Receiver;
use embedded_graphics::primitives::Circle;
use embedded_graphics::{
    mono_font::{MonoTextStyleBuilder, ascii::FONT_10X20},
    pixelcolor::BinaryColor,
    prelude::{Size, *},
    primitives::{PrimitiveStyle, Rectangle},
    text::{Alignment, Baseline, Text, TextStyleBuilder},
};
use epd_2in13_v4::{Device, DeviceConfig};

const TIME_TEXT_POS: Point = Point::new(20, 95);
const EXIT_BUTTON_RECT: Rectangle = Rectangle::new(Point::new(11, 10), Size::new(100, 50));

enum AppEvent {
    ClockTick,
    Touch(Point),
}

fn main() -> epd_2in13_v4::EpdResult<()> {
    env_logger::init();
    log::info!("EPD_2in13_V4_test Demo");

    let (mut device, touch_events) = Device::new(DeviceConfig::default())?;
    initialize_display(&mut device)?;

    let rx = setup_event_channels(touch_events);

    log::info!("Application started. Touch the screen to draw or press the exit button.");
    run_event_loop(&mut device, rx)?;

    device.sleep()?;
    Ok(())
}

fn initialize_display(device: &mut Device) -> epd_2in13_v4::EpdResult<()> {
    log::info!("Drawing");
    device.display.clear(BinaryColor::On)?;

    let style = PrimitiveStyle::with_stroke(BinaryColor::Off, 1);
    let bounding_box = device.display.bounding_box();
    log::debug!(
        "left: {}, size: {}",
        bounding_box.top_left,
        bounding_box.size
    );

    Rectangle::new(bounding_box.top_left, bounding_box.size)
        .into_styled(style)
        .draw(&mut device.display)?;

    EXIT_BUTTON_RECT
        .into_styled(style)
        .draw(&mut device.display)?;

    let character_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::Off)
        .build();
    let text_style = TextStyleBuilder::new()
        .alignment(Alignment::Center)
        .baseline(Baseline::Middle)
        .build();
    Text::with_text_style(
        "Exit",
        EXIT_BUTTON_RECT.center(),
        character_style,
        text_style,
    )
    .draw(&mut device.display)?;

    device.display.update()
}

fn setup_event_channels(touch_events: Receiver<Point>) -> Receiver<AppEvent> {
    let (tx, rx) = crossbeam_channel::unbounded();

    let clock_tx = tx.clone();
    std::thread::spawn(move || {
        loop {
            clock_tx.send(AppEvent::ClockTick).unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });

    std::thread::spawn(move || {
        for touch_point in touch_events {
            tx.send(AppEvent::Touch(touch_point)).unwrap();
        }
    });

    rx
}

fn run_event_loop(device: &mut Device, rx: Receiver<AppEvent>) -> epd_2in13_v4::EpdResult<()> {
    loop {
        match rx.recv() {
            Ok(first_event) => {
                let all_events: Vec<AppEvent> =
                    std::iter::once(first_event).chain(rx.try_iter()).collect();

                if handle_events(device, all_events)? {
                    return Ok(());
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

fn handle_events(device: &mut Device, events: Vec<AppEvent>) -> epd_2in13_v4::EpdResult<bool> {
    let mut should_exit = false;

    for event in events {
        match event {
            AppEvent::ClockTick => {
                draw_clock(&mut device.display)?;
            }
            AppEvent::Touch(touch_point) => {
                log::debug!("Touch at: {touch_point:?}");
                if EXIT_BUTTON_RECT.contains(touch_point) {
                    should_exit = true;
                    break;
                }
                let circle_style = PrimitiveStyle::with_fill(BinaryColor::Off);
                Circle::new(touch_point, 10)
                    .into_styled(circle_style)
                    .draw(&mut device.display)?;
            }
        }
    }

    if should_exit {
        log::info!("Exit button touched. Shutting down.");
        device.display.clear(BinaryColor::On)?;
        device.display.update()?;
        Ok(true)
    } else {
        device.display.update()?;
        Ok(false)
    }
}

fn draw_clock<D: DrawTarget<Color = BinaryColor>>(display: &mut D) -> Result<(), D::Error> {
    let time_text_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::Off)
        .background_color(BinaryColor::On)
        .build();
    let now = Local::now();
    let time_str = format!("{:02}:{:02}:{:02}", now.hour(), now.minute(), now.second());
    Text::new(&time_str, TIME_TEXT_POS, time_text_style).draw(display)?;
    Ok(())
}
