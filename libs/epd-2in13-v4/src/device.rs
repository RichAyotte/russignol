use crate::display_driver::Epd2in13v4;
pub use crate::error::{EpdResult, Error};
use crate::touch;
use crate::touch_driver::TouchDriver;
use crate::{common::Rotation, display::Display};
use crossbeam_channel::Receiver;
use embedded_graphics::geometry::Point;
use linux_embedded_hal::{
    CdevPin, Delay, I2cdev, SpidevBus,
    gpio_cdev::{Chip, LineRequestFlags},
    spidev::{SpiModeFlags, SpidevOptions},
};
use log::info;

const DEFAULT_SPI_BUS_PATH: &str = "/dev/spidev0.0";
const DEFAULT_SPI_BITS_PER_WORD: u8 = 8;
const DEFAULT_SPI_MAX_SPEED_HZ: u32 = 20_000_000;
const DEFAULT_GPIO_CHIP_PATH: &str = "/dev/gpiochip0";
const DEFAULT_BUSY_PIN: u32 = 24;
const DEFAULT_DC_PIN: u32 = 25;
const DEFAULT_RST_PIN: u32 = 17;
const DEFAULT_I2C_BUS_PATH: &str = "/dev/i2c-1";
const DEFAULT_TOUCH_RST_PIN: u32 = 22;
const DEFAULT_TOUCH_INT_PIN: u32 = 27;
const DEFAULT_ROTATION: Rotation = Rotation::Deg90;

const EPD_BUSY_CONSUMER: &str = "epd-busy";
const EPD_DC_CONSUMER: &str = "epd-dc";
const EPD_RST_CONSUMER: &str = "epd-rst";
const TOUCH_RST_CONSUMER: &str = "touch-rst";

#[derive(Default)]
pub struct DeviceConfig {
    pub spi_bus_path: Option<String>,
    pub spi_options: Option<SpidevOptions>,
    pub gpio_chip_path: Option<String>,
    pub busy_pin: Option<u32>,
    pub dc_pin: Option<u32>,
    pub rst_pin: Option<u32>,
    pub i2c_bus_path: Option<String>,
    pub touch_rst_pin: Option<u32>,
    pub touch_int_pin: Option<u32>,
    pub rotation: Option<Rotation>,
}

pub struct Device {
    pub display: Display,
    pub touch: touch::Touch,
}

impl Device {
    pub fn new(config: DeviceConfig) -> EpdResult<(Self, Receiver<Point>)> {
        let rotation = config.rotation.unwrap_or(DEFAULT_ROTATION);
        let spi_bus_path = config
            .spi_bus_path
            .unwrap_or_else(|| DEFAULT_SPI_BUS_PATH.to_string());
        let spi_options = config.spi_options.unwrap_or_else(|| {
            SpidevOptions::new()
                .bits_per_word(DEFAULT_SPI_BITS_PER_WORD)
                .max_speed_hz(DEFAULT_SPI_MAX_SPEED_HZ)
                .mode(SpiModeFlags::SPI_MODE_0)
                .build()
        });
        let gpio_chip_path = config
            .gpio_chip_path
            .unwrap_or_else(|| DEFAULT_GPIO_CHIP_PATH.to_string());
        let busy_pin = config.busy_pin.unwrap_or(DEFAULT_BUSY_PIN);
        let dc_pin = config.dc_pin.unwrap_or(DEFAULT_DC_PIN);
        let rst_pin = config.rst_pin.unwrap_or(DEFAULT_RST_PIN);
        let i2c_bus_path = config
            .i2c_bus_path
            .unwrap_or_else(|| DEFAULT_I2C_BUS_PATH.to_string());
        let touch_rst_pin = config.touch_rst_pin.unwrap_or(DEFAULT_TOUCH_RST_PIN);
        let touch_int_pin = config.touch_int_pin.unwrap_or(DEFAULT_TOUCH_INT_PIN);

        info!("Initializing EPD device...");

        // EPD SPI setup
        let mut spi_bus = SpidevBus::open(spi_bus_path)?;
        spi_bus.configure(&spi_options)?;

        // GPIO setup
        let mut chip = Chip::new(gpio_chip_path)?;
        let busy = CdevPin::new(chip.get_line(busy_pin)?.request(
            LineRequestFlags::INPUT,
            0,
            EPD_BUSY_CONSUMER,
        )?)?;
        let dc = CdevPin::new(chip.get_line(dc_pin)?.request(
            LineRequestFlags::OUTPUT,
            0,
            EPD_DC_CONSUMER,
        )?)?;
        let rst = CdevPin::new(chip.get_line(rst_pin)?.request(
            LineRequestFlags::OUTPUT,
            0,
            EPD_RST_CONSUMER,
        )?)?;
        let delay = Delay {};

        // EPD driver
        let epd_driver = Epd2in13v4::new(spi_bus, busy, dc, rst, delay)?;
        let display = Display::new(epd_driver, rotation);

        // Touch I2C setup
        let i2c_bus = I2cdev::new(i2c_bus_path)?;
        let touch_rst_pin = CdevPin::new(chip.get_line(touch_rst_pin)?.request(
            LineRequestFlags::OUTPUT,
            0,
            TOUCH_RST_CONSUMER,
        )?)?;
        let touch_int_line = chip.get_line(touch_int_pin)?;

        // Touch driver and touchscreen
        let touch_driver = TouchDriver::new(i2c_bus, touch_rst_pin)?;
        let (touch, event_rx) = touch::Touch::new(touch_driver, touch_int_line, rotation)?;

        let device = Self { display, touch };

        Ok((device, event_rx))
    }

    pub fn sleep(&mut self) -> EpdResult<()> {
        self.touch.sleep()?;
        self.display.sleep()
    }

    pub fn display_sleep(&mut self) -> EpdResult<()> {
        self.display.sleep()
    }

    pub fn display_wake(&mut self) -> EpdResult<()> {
        self.display.wake()
    }
}
