use core::convert::Infallible;
use linux_embedded_hal::CdevPinError;
use linux_embedded_hal::SPIError;
use linux_embedded_hal::gpio_cdev::Error as GpioError;
use std::io::Error as IoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Timeout waiting for busy pin")]
    Timeout,
    #[error("SPI error: {0}")]
    Spi(#[from] SPIError),
    #[error("IO error: {0}")]
    Io(#[from] IoError),
    #[error("GPIO error: {0}")]
    Gpio(#[from] GpioError),
    #[error("Cdev pin error: {0}")]
    CdevPin(#[from] CdevPinError),
    #[error("I2C error: {0}")]
    I2c(#[from] linux_embedded_hal::i2cdev::linux::LinuxI2CError),
    #[error("I2C HAL error: {0}")]
    I2cHal(String),
    #[error("Touchscreen error: {0}")]
    Touchscreen(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("Infallible")]
    Infallible(#[from] Infallible),
}

pub type EpdResult<T> = Result<T, Error>;
