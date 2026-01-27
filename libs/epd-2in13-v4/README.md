# epd-2in13-v4

A Rust driver for the Waveshare 2.13-inch e-Paper display (V4) with touch support.

This driver is built on top of the `embedded-hal` crate and provides a high-level interface for drawing on the display and handling touch input.

## Features

- Drawing graphics and text on the display.
- Handling touch input events.
- Partial and full screen updates.
- Low-level access to the display controller.

## Installation

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
epd-2in13-v4 = "0.1.2"
```

## Usage

Here's a simple example of how to use the library to initialize the display, draw some text, and handle touch input:

```rust
use epd_2in13_v4::{Device, DeviceConfig};
use embedded_graphics::{
    mono_font::{MonoTextStyleBuilder, ascii::FONT_10X20},
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Alignment, Baseline, Text, TextStyleBuilder},
};

fn main() -> epd_2in13_v4::EpdResult<()> {
    let (mut device, mut touch_events) = Device::new(DeviceConfig::default())?;

    device.display.clear(BinaryColor::On)?;

    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::Off)
        .build();

    Text::new("Hello, world!", Point::new(20, 30), text_style)
        .draw(&mut device.display)?;

    device.display.update()?;

    println!("Application started. Touch the screen to draw.");

    for touch in touch_events {
        println!("Touch at: {:?}", touch);
    }

    device.sleep()?;

    Ok(())
}
```

## Examples

For more detailed examples, please see the [examples](examples) directory.

## License

This project is licensed under the MIT License.