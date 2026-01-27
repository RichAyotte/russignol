use crate::common::BUFFER_SIZE;
use crate::error::{EpdResult, Error};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{InputPin, OutputPin};
use embedded_hal::spi::SpiBus;
use linux_embedded_hal::{CdevPin, Delay, SpidevBus};
use log::{debug, trace};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayMode {
    Full,
    Partial,
}

// EPD (Display) constants
pub(crate) const RESET_DELAY_MS: u32 = 20;
pub(crate) const RESET_PULSE_MS: u32 = 2;
pub(crate) const WAIT_IDLE_DELAY_MS: u32 = 10;
pub(crate) const WAIT_IDLE_TIMEOUT_MS: u32 = 10000;
pub(crate) const SLEEP_DELAY_MS: u32 = 100;
pub(crate) const PARTIAL_UPDATE_RESET_DELAY_MS: u32 = 1;
// --- EPD Driver ---

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum EpdCommand {
    DriverOutputControl = 0x01,
    DataEntryMode = 0x11,
    SoftwareReset = 0x12,
    TemperatureSensor = 0x18,
    DisplayUpdateControl = 0x22,
    DisplayUpdateControl2 = 0x21,
    WriteRam = 0x24,
    WriteRamRed = 0x26,
    BorderWaveform = 0x3C,
    SetRamXAddress = 0x44,
    SetRamYAddress = 0x45,
    DeepSleep = 0x10,
    ActivateDisplayUpdateSequence = 0x20,
    SetRamXAddressCounter = 0x4E,
    SetRamYAddressCounter = 0x4F,
}

pub enum EpdData {
    DriverOutputControl,
    DataEntryMode,
    BorderWaveform,
    DisplayUpdateControl2,
    TemperatureSensor,
    DisplayFrame,
    DeepSleep,
    DisplayPartial,
    PartialUpdateBorderWaveform,
    PartialUpdateDriverOutputControl,
    PartialUpdateDataEntryMode,
    RamX,
    RamY,
}

impl EpdData {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            EpdData::DriverOutputControl | EpdData::PartialUpdateDriverOutputControl => {
                &[0xF9, 0x00, 0x00]
            }
            EpdData::DataEntryMode | EpdData::PartialUpdateDataEntryMode => &[0x03],
            EpdData::BorderWaveform => &[0x05],
            EpdData::DisplayUpdateControl2 => &[0x00, 0x80],
            EpdData::TemperatureSensor | EpdData::PartialUpdateBorderWaveform => &[0x80],
            EpdData::DisplayFrame => &[0xf7],
            EpdData::DeepSleep => &[0x01],
            EpdData::DisplayPartial => &[0xff],
            EpdData::RamX => &[0x00, 0x0F],
            EpdData::RamY => &[0x00, 0x00, 0xF9, 0x00],
        }
    }
}

pub struct Epd2in13v4 {
    spi: SpidevBus,
    busy: CdevPin,
    dc: CdevPin,
    rst: CdevPin,
    delay: Delay,
    last_update_mode: Option<DisplayMode>,
    /// Tracks pixels modified since last `wait_until_idle()`.
    /// 1 = pixel was touched, 0 = untouched.
    dirty_mask: Box<[u8]>,
    /// The previous frame sent, used to detect what's changing.
    last_frame: Box<[u8]>,
}

impl Epd2in13v4 {
    pub fn new(
        spi: SpidevBus,
        busy: CdevPin,
        dc: CdevPin,
        rst: CdevPin,
        delay: Delay,
    ) -> EpdResult<Self> {
        let dirty_mask: Box<[u8]> = vec![0x00; BUFFER_SIZE].into_boxed_slice();
        let last_frame: Box<[u8]> = vec![0xFF; BUFFER_SIZE].into_boxed_slice(); // Start as white
        let mut driver = Self {
            spi,
            busy,
            dc,
            rst,
            delay,
            last_update_mode: None,
            dirty_mask,
            last_frame,
        };
        driver.hardware_reset()?;
        driver.software_reset()?;
        Ok(driver)
    }

    fn hardware_reset(&mut self) -> EpdResult<()> {
        debug!("EPD: Hardware reset starting");
        self.rst.set_high()?;
        self.delay.delay_ms(RESET_DELAY_MS);
        self.rst.set_low()?;
        self.delay.delay_ms(RESET_PULSE_MS);
        self.rst.set_high()?;
        self.delay.delay_ms(RESET_DELAY_MS);
        debug!("EPD: Hardware reset complete");
        Ok(())
    }

    fn software_reset(&mut self) -> EpdResult<()> {
        self.send_command(EpdCommand::SoftwareReset, None)
    }

    fn send_command(&mut self, command: EpdCommand, data: Option<&[u8]>) -> EpdResult<()> {
        trace!("EPD: send_command {:?} (0x{:02X})", command, command as u8);
        match command {
            EpdCommand::ActivateDisplayUpdateSequence
            | EpdCommand::SoftwareReset
            | EpdCommand::DisplayUpdateControl
            | EpdCommand::DisplayUpdateControl2
            | EpdCommand::WriteRam
            | EpdCommand::WriteRamRed
            | EpdCommand::DeepSleep
            | EpdCommand::TemperatureSensor => {
                self.wait_until_idle()?;
            }
            _ => {}
        }
        self.dc.set_low()?;
        self.spi.write(&[command as u8])?;
        trace!("EPD: command byte sent");

        if let Some(data) = data {
            self.send_data(data)?;
        }

        Ok(())
    }

    fn send_data(&mut self, data: &[u8]) -> EpdResult<()> {
        self.dc.set_high()?;
        self.spi.write(data)?;
        trace!("EPD: sent {} bytes of data", data.len());
        Ok(())
    }

    fn wait_until_idle(&mut self) -> EpdResult<()> {
        let start = Instant::now();
        let initial_busy = self.busy.is_high()?;
        trace!(
            "EPD: wait_until_idle starting (BUSY={})",
            if initial_busy { "HIGH" } else { "LOW" }
        );

        while self.busy.is_high()?
            && start.elapsed().as_millis() <= u128::from(WAIT_IDLE_TIMEOUT_MS)
        {
            self.delay.delay_ms(WAIT_IDLE_DELAY_MS);
        }

        let elapsed = start.elapsed().as_millis();
        if self.busy.is_high()? {
            debug!("EPD: wait_until_idle TIMEOUT after {elapsed}ms");
            Err(Error::Timeout)
        } else {
            trace!("EPD: wait_until_idle done in {elapsed}ms");
            Ok(())
        }
    }

    pub fn sleep(&mut self) -> EpdResult<()> {
        self.send_command(EpdCommand::DeepSleep, Some(EpdData::DeepSleep.as_slice()))?;
        self.delay.delay_ms(SLEEP_DELAY_MS);
        Ok(())
    }

    pub fn wake(&mut self) -> EpdResult<()> {
        // HW reset is required to exit deep sleep (per datasheet section 6)
        self.hardware_reset()?;
        // Re-send init commands since HW reset restores POR defaults.
        // These control scan direction - without them, display appears mirrored.
        self.send_command(
            EpdCommand::DriverOutputControl,
            Some(EpdData::DriverOutputControl.as_slice()),
        )?;
        self.send_command(
            EpdCommand::DataEntryMode,
            Some(EpdData::DataEntryMode.as_slice()),
        )?;
        self.set_full_ram_window()?;
        // Reset so next display() takes the full update path
        self.last_update_mode = None;
        Ok(())
    }

    pub fn display(&mut self, buffer: &[u8], mode: DisplayMode) -> EpdResult<()> {
        debug!(
            "EPD: display() called with mode={:?}, buffer_len={}",
            mode,
            buffer.len()
        );

        // Check if display is currently refreshing
        let is_busy = self.busy.is_high()?;

        // If display is idle, previous refresh completed - clear dirty tracking
        if !is_busy {
            self.dirty_mask.fill(0x00);
        }

        // For partial updates, only wait if there's pixel overlap with dirty pixels
        if mode == DisplayMode::Partial
            && is_busy
            && has_overlap(&self.dirty_mask, &self.last_frame, buffer)
        {
            debug!("EPD: Overlap detected with dirty pixels, waiting for idle");
            self.wait_until_idle()?;
        }

        let result = match mode {
            DisplayMode::Full => {
                self.set_full_ram_window()?;
                self.send_command(
                    EpdCommand::DriverOutputControl,
                    Some(EpdData::DriverOutputControl.as_slice()),
                )?;
                self.send_command(
                    EpdCommand::DataEntryMode,
                    Some(EpdData::DataEntryMode.as_slice()),
                )?;
                self.send_command(
                    EpdCommand::BorderWaveform,
                    Some(EpdData::BorderWaveform.as_slice()),
                )?;
                self.send_command(
                    EpdCommand::DisplayUpdateControl2,
                    Some(EpdData::DisplayUpdateControl2.as_slice()),
                )?;
                self.send_command(
                    EpdCommand::TemperatureSensor,
                    Some(EpdData::TemperatureSensor.as_slice()),
                )?;
                self.send_command(EpdCommand::WriteRam, Some(buffer))?;
                self.send_command(EpdCommand::WriteRamRed, Some(buffer))?;
                self.send_command(
                    EpdCommand::DisplayUpdateControl,
                    Some(EpdData::DisplayFrame.as_slice()),
                )?;
                self.send_command(EpdCommand::ActivateDisplayUpdateSequence, None)
            }
            DisplayMode::Partial => {
                if self.last_update_mode.is_none()
                    || self.last_update_mode == Some(DisplayMode::Full)
                {
                    self.wait_until_idle()?;
                }
                self.rst.set_low()?;
                self.delay.delay_ms(PARTIAL_UPDATE_RESET_DELAY_MS);
                self.rst.set_high()?;
                self.set_full_ram_window()?;
                self.send_command(
                    EpdCommand::BorderWaveform,
                    Some(EpdData::PartialUpdateBorderWaveform.as_slice()),
                )?;
                self.send_command(
                    EpdCommand::DriverOutputControl,
                    Some(EpdData::PartialUpdateDriverOutputControl.as_slice()),
                )?;
                self.send_command(
                    EpdCommand::DataEntryMode,
                    Some(EpdData::PartialUpdateDataEntryMode.as_slice()),
                )?;
                self.send_command(EpdCommand::WriteRam, Some(buffer))?;
                self.send_command(
                    EpdCommand::DisplayUpdateControl,
                    Some(EpdData::DisplayPartial.as_slice()),
                )?;
                self.send_command(EpdCommand::ActivateDisplayUpdateSequence, None)
            }
        };

        // Track dirty pixels (accumulate changes into dirty mask)
        if result.is_ok() {
            for ((dirty, last), &buf) in self
                .dirty_mask
                .iter_mut()
                .zip(self.last_frame.iter())
                .zip(buffer.iter())
            {
                *dirty |= *last ^ buf;
            }
            self.last_frame.copy_from_slice(buffer);
        }

        self.last_update_mode = Some(mode);
        result
    }

    fn set_full_ram_window(&mut self) -> EpdResult<()> {
        self.send_command(EpdCommand::SetRamXAddress, Some(EpdData::RamX.as_slice()))?;
        self.send_command(EpdCommand::SetRamYAddress, Some(EpdData::RamY.as_slice()))?;
        self.send_command(EpdCommand::SetRamXAddressCounter, Some(&[0]))?;
        self.send_command(EpdCommand::SetRamYAddressCounter, Some(&[0, 0]))
    }
}

/// Check if new frame changes any pixel that was already touched since last wait.
/// Returns true if there's overlap (changing a dirty pixel).
fn has_overlap(dirty_mask: &[u8], last_frame: &[u8], new_frame: &[u8]) -> bool {
    dirty_mask
        .iter()
        .zip(last_frame.iter())
        .zip(new_frame.iter())
        .any(|((dirty, last), new)| {
            let changing = last ^ new; // pixels this frame wants to change
            (dirty & changing) != 0 // any of those already dirty?
        })
}
