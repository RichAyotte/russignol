// Hardware detection and management for Russignol devices
//
// This module provides unified hardware detection logic used by both
// setup and status commands to ensure consistent behavior.

use crate::constants::{
    INTERFACE_NAME, MANUFACTURER_NAME, USB_PRODUCT_ID, USB_VENDOR_ID, USB_VID_PID,
};
use crate::utils::{command_exists, run_command};
use anyhow::{Context, Result};
use std::path::Path;

/// Detect if a Russignol hardware device is connected via USB
///
/// This function checks for the device using multiple methods:
/// 1. lsusb command (if available) - checks for VID:PID or manufacturer string
/// 2. /sys/bus/usb/devices - checks manufacturer and VID:PID
///
/// Returns Ok(()) if device is found, error otherwise
pub fn detect_hardware_device() -> Result<()> {
    // Primary: Check for russignol via lsusb (VID:PID or manufacturer)
    if command_exists("lsusb") {
        let output = run_command("lsusb", &[])?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Look for specific VID:PID or manufacturer string
        if stdout.contains(USB_VID_PID) || stdout.contains(MANUFACTURER_NAME) {
            log::debug!("Found russignol device via lsusb");
            return Ok(());
        }
    }

    // Secondary: Check /sys/bus/usb/devices for manufacturer string
    let devices_path = Path::new("/sys/bus/usb/devices");
    if devices_path.exists() {
        let entries =
            std::fs::read_dir(devices_path).context("Failed to read /sys/bus/usb/devices")?;

        for entry in entries {
            let entry = entry?;
            let device_path = entry.path();

            // Check manufacturer
            let manufacturer_path = device_path.join("manufacturer");
            if manufacturer_path.exists()
                && let Ok(content) = std::fs::read_to_string(&manufacturer_path)
                && content.trim() == MANUFACTURER_NAME
            {
                log::debug!(
                    "Found russignol device in sysfs: {} (manufacturer: {})",
                    device_path.display(),
                    MANUFACTURER_NAME
                );
                return Ok(());
            }

            // Check VID:PID
            let vid_path = device_path.join("idVendor");
            let pid_path = device_path.join("idProduct");
            if vid_path.exists()
                && pid_path.exists()
                && let (Ok(vid), Ok(pid)) = (
                    std::fs::read_to_string(&vid_path),
                    std::fs::read_to_string(&pid_path),
                )
                && vid.trim() == USB_VENDOR_ID
                && pid.trim() == USB_PRODUCT_ID
            {
                log::debug!(
                    "Found russignol device in sysfs: {} (VID:PID {})",
                    device_path.display(),
                    USB_VID_PID
                );
                return Ok(());
            }
        }
    }

    anyhow::bail!(
        "russignol hardware device not detected.\n\n\
         Please check:\n\
         1. Is the SD card flashed with Russignol firmware?\n\
            If not, run: russignol image download-and-flash\n\n\
         2. Is the device connected via USB and powered on?\n\n\
         3. Is the device fully booted? (allow ~30 seconds after power-on)"
    )
}

/// Get the USB serial number for the Russignol device
///
/// Returns Ok(Some(serial)) if found, Ok(None) if device exists but has no serial,
/// or an error if sysfs cannot be read
pub fn get_usb_serial_number() -> Result<Option<String>> {
    // Try to get serial from sysfs
    let devices_path = Path::new("/sys/bus/usb/devices");
    if !devices_path.exists() {
        return Ok(None);
    }

    let entries = std::fs::read_dir(devices_path)?;

    for entry in entries {
        let entry = entry?;
        let device_path = entry.path();

        // Check if this is our device (VID:PID)
        let vid_path = device_path.join("idVendor");
        let pid_path = device_path.join("idProduct");
        let serial_path = device_path.join("serial");

        if vid_path.exists()
            && pid_path.exists()
            && let (Ok(vid), Ok(pid)) = (
                std::fs::read_to_string(&vid_path),
                std::fs::read_to_string(&pid_path),
            )
            && vid.trim() == USB_VENDOR_ID
            && pid.trim() == USB_PRODUCT_ID
            && serial_path.exists()
            && let Ok(serial) = std::fs::read_to_string(&serial_path)
        {
            return Ok(Some(serial.trim().to_string()));
        }
    }

    Ok(None)
}

/// Get the MAC address of the Russignol network interface
///
/// Returns `Ok(Some(mac_address))` if interface exists and has a MAC address,
/// Ok(None) if interface doesn't exist or has no MAC
pub fn get_mac_address() -> Result<Option<String>> {
    // Get MAC address of russignol network interface
    let output = run_command("ip", &["link", "show", INTERFACE_NAME])?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse MAC address from line like "link/ether 02:d7:3d:5e:85:f9 brd ..."
    for line in stdout.lines() {
        if let Some(mac_line) = line.trim().strip_prefix("link/ether ")
            && let Some(mac) = mac_line.split_whitespace().next()
        {
            return Ok(Some(mac.to_string()));
        }
    }

    Ok(None)
}

/// Find the Russignol network interface
///
/// Checks if the /sys/class/net/russignol interface exists and optionally verifies
/// it's actually the Russignol device by checking VID:PID
///
/// Returns true if interface found, false otherwise
pub fn find_russignol_network_interface() -> bool {
    let interface_path = Path::new("/sys/class/net").join(INTERFACE_NAME);

    if !interface_path.exists() {
        log::debug!(
            "Network interface '{}' does not exist at {}",
            INTERFACE_NAME,
            interface_path.display()
        );
        return false;
    }

    log::debug!(
        "Found network interface '{}' at {}",
        INTERFACE_NAME,
        interface_path.display()
    );

    // Verify it's our USB device by checking VID:PID
    let device_path = interface_path.join("device");
    if device_path.exists() {
        let vendor_path = device_path.join("idVendor");
        let product_path = device_path.join("idProduct");

        if vendor_path.exists()
            && product_path.exists()
            && let (Ok(vid), Ok(pid)) = (
                std::fs::read_to_string(&vendor_path),
                std::fs::read_to_string(&product_path),
            )
        {
            let vid = vid.trim();
            let pid = pid.trim();
            log::debug!("Network interface has VID:PID {vid}:{pid}");

            if vid == USB_VENDOR_ID && pid == USB_PRODUCT_ID {
                log::debug!("Confirmed {INTERFACE_NAME} network interface with correct VID:PID");
                return true;
            }
            log::debug!("Network interface has wrong VID:PID (expected {USB_VID_PID})");
            return false;
        }
    }

    // If we can't verify VID:PID but the interface exists, accept it
    log::debug!("Found network interface '{INTERFACE_NAME}' (VID:PID verification skipped)");
    true
}
