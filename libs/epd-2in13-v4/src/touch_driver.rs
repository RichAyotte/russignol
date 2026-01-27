use crate::error::{EpdResult, Error};
use embedded_hal::digital::OutputPin;
use embedded_hal::i2c::I2c;
use linux_embedded_hal::{CdevPin, I2cdev};
use log::info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub x: i32,
    pub y: i32,
}

pub const GT1151_I2C_ADDR: u8 = 0x14;
pub const GT1151_PRODUCT_ID_REG: u16 = 0x8140;
pub const GT1151_COORD_REG: u16 = 0x814E;
pub const GT1151_CMD_REG: u16 = 0x8040;
pub const GT1151_SLEEP_CMD: u8 = 0x05;
pub const TOUCH_DATA_LEN: usize = 9;
pub const TOUCH_RESET_LOW_DURATION_MS: u64 = 10;
pub const TOUCH_RESET_HIGH_DURATION_MS: u64 = 50;
static IS_FINGER_DOWN: AtomicBool = AtomicBool::new(false);

// --- Touch Driver ---

pub struct TouchDriver {
    i2c: Arc<Mutex<I2cdev>>,
}

impl TouchDriver {
    pub fn new(i2c: I2cdev, mut rst_pin: CdevPin) -> EpdResult<Self> {
        info!("Initializing touchscreen...");
        rst_pin
            .set_low()
            .map_err(|e| Error::Touchscreen(e.into()))?;
        thread::sleep(Duration::from_millis(TOUCH_RESET_LOW_DURATION_MS));
        rst_pin
            .set_high()
            .map_err(|e| Error::Touchscreen(e.into()))?;
        thread::sleep(Duration::from_millis(TOUCH_RESET_HIGH_DURATION_MS));

        let i2c = Arc::new(Mutex::new(i2c));
        read_product_id(&i2c)?;

        info!("Touchscreen initialized.");

        Ok(Self { i2c })
    }

    pub fn i2c_arc(&self) -> Arc<Mutex<I2cdev>> {
        self.i2c.clone()
    }

    pub fn sleep(&mut self) -> EpdResult<()> {
        let mut i2c_guard = self.i2c.lock().unwrap();
        let cmd_bytes = GT1151_CMD_REG.to_be_bytes();
        let sleep_cmd = [cmd_bytes[0], cmd_bytes[1], GT1151_SLEEP_CMD];
        i2c_guard
            .write(GT1151_I2C_ADDR, &sleep_cmd)
            .map_err(|e| Error::I2cHal(format!("Failed to send sleep command: {e}")))
    }
}

fn read_product_id(i2c: &Arc<Mutex<I2cdev>>) -> EpdResult<()> {
    let addr_bytes = GT1151_PRODUCT_ID_REG.to_be_bytes();
    let mut id_buf = [0u8; 4];
    match i2c
        .lock()
        .unwrap()
        .write_read(GT1151_I2C_ADDR, &addr_bytes, &mut id_buf)
    {
        Ok(()) => {}
        Err(e) => {
            return Err(Error::I2cHal(format!("Failed to read product ID: {e}")));
        }
    }
    let id_str = std::str::from_utf8(&id_buf).map_err(|e| Error::Touchscreen(e.into()))?;
    info!("Touchscreen Product ID: {id_str}");
    Ok(())
}

pub fn read_and_clear_touch_data(
    i2c: &Arc<Mutex<I2cdev>>,
) -> Result<Option<Event>, Box<dyn std::error::Error + Send + Sync>> {
    let mut i2c_guard = i2c.lock().unwrap();
    let addr_bytes = GT1151_COORD_REG.to_be_bytes();
    let mut data_buf = [0u8; TOUCH_DATA_LEN];

    i2c_guard.write_read(GT1151_I2C_ADDR, &addr_bytes, &mut data_buf)?;
    i2c_guard.write(GT1151_I2C_ADDR, &[addr_bytes[0], addr_bytes[1], 0])?;

    let status = data_buf[0];
    let touch_count = (status & 0x0F) as usize;

    if touch_count > 0 {
        if !IS_FINGER_DOWN.swap(true, Ordering::SeqCst) {
            let x = i32::from(u16::from_le_bytes([data_buf[2], data_buf[3]]));
            let y = i32::from(u16::from_le_bytes([data_buf[4], data_buf[5]]));
            return Ok(Some(Event { x, y }));
        }
    } else {
        IS_FINGER_DOWN.store(false, Ordering::SeqCst);
    }

    Ok(None)
}
