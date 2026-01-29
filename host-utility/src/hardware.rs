// Hardware detection and management for Russignol devices
//
// This module provides unified hardware detection logic used by both
// setup and status commands to ensure consistent behavior.

use crate::constants::{
    INTERFACE_NAME, MANUFACTURER_NAME, USB_BUS_POWERED_BUDGET_MA, USB_PRODUCT_ID, USB_VENDOR_ID,
    USB_VID_PID,
};
use crate::utils::{command_exists, run_command};
use anyhow::{Context, Result};
use std::path::Path;

// ============================================================================
// USB Power Detection Types
// ============================================================================

/// Information about the USB power situation for the Russignol device
#[derive(Debug, Clone)]
pub struct UsbPowerInfo {
    /// The sysfs device path (e.g., "3-7.2")
    pub device_path: String,
    /// Power requested by this device in mA
    pub device_power_ma: u32,
    /// Whether the device is connected through a hub
    pub behind_hub: bool,
    /// Hub power information, if behind a hub
    pub hub_info: Option<HubPowerInfo>,
}

/// Information about a USB hub's power situation
#[derive(Debug, Clone)]
pub struct HubPowerInfo {
    /// The sysfs hub path (e.g., "3-7")
    pub hub_path: String,
    /// Power requested by the hub itself in mA (0 = self-powered)
    pub hub_power_ma: u32,
    /// Whether this is a bus-powered hub (vs self-powered)
    pub is_bus_powered: bool,
    /// Total power draw of all devices on this hub in mA
    pub total_power_draw_ma: u32,
    /// Power budget available (500mA for bus-powered)
    pub power_budget_ma: u32,
    /// List of devices connected to this hub
    pub devices: Vec<HubDevice>,
}

/// A device connected to a USB hub
#[derive(Debug, Clone)]
pub struct HubDevice {
    /// The sysfs device path
    pub path: String,
    /// Product name (from sysfs "product" file)
    pub product: String,
    /// Power requested in mA
    pub power_ma: u32,
}

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

// ============================================================================
// USB Power Detection Functions
// ============================================================================

/// Parse a power value string like "500mA" to an integer in milliamps
fn parse_power_ma(value: &str) -> Option<u32> {
    value.trim().strip_suffix("mA")?.parse().ok()
}

/// Check if a device path indicates it's behind a hub
///
/// Device paths like "3-7" are direct connections, while "3-7.2" indicates
/// the device is connected through a hub (the `.` after bus-port).
fn is_behind_hub(device_path: &str) -> bool {
    // Find the first '-' (separates bus from port)
    if let Some(dash_pos) = device_path.find('-') {
        // Check if there's a '.' after the dash (indicates hub port)
        device_path[dash_pos..].contains('.')
    } else {
        false
    }
}

/// Get the parent hub path from a device path
///
/// For "3-7.2" returns Some("3-7"), for "3-7" returns None
fn get_parent_hub_path(device_path: &str) -> Option<String> {
    if !is_behind_hub(device_path) {
        return None;
    }
    // Find the last '.' and return everything before it
    device_path
        .rfind('.')
        .map(|pos| device_path[..pos].to_string())
}

/// Get the sysfs device path for the Russignol device
///
/// Scans `/sys/bus/usb/devices/` for a device matching our VID:PID
/// Returns the device name (e.g., "3-7.2"), not the full path
pub fn get_device_sysfs_path() -> Result<Option<String>> {
    let devices_path = Path::new("/sys/bus/usb/devices");
    if !devices_path.exists() {
        return Ok(None);
    }

    let entries = std::fs::read_dir(devices_path)?;

    for entry in entries {
        let entry = entry?;
        let device_path = entry.path();

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
            && let Some(name) = device_path.file_name()
        {
            return Ok(Some(name.to_string_lossy().to_string()));
        }
    }

    Ok(None)
}

/// Collect all devices connected to a hub
///
/// Scans `/sys/bus/usb/devices/{hub_path}.*` for child devices
fn collect_hub_devices(hub_path: &str) -> Result<Vec<HubDevice>> {
    let devices_path = Path::new("/sys/bus/usb/devices");
    let mut devices = Vec::new();

    if !devices_path.exists() {
        return Ok(devices);
    }

    let entries = std::fs::read_dir(devices_path)?;
    let prefix = format!("{hub_path}.");

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Check if this is a child device of the hub (e.g., "3-7.1", "3-7.2" for hub "3-7")
        // Also exclude deeper nested devices (e.g., "3-7.1.1")
        if name_str.starts_with(&prefix) {
            let suffix = &name_str[prefix.len()..];
            // Only include direct children (no additional dots in suffix)
            if !suffix.contains('.') {
                let device_path = entry.path();

                // Read product name
                let product = device_path
                    .join("product")
                    .exists()
                    .then(|| std::fs::read_to_string(device_path.join("product")).ok())
                    .flatten()
                    .map_or_else(|| "Unknown Device".to_string(), |s| s.trim().to_string());

                // Read power draw
                let power_ma = device_path
                    .join("bMaxPower")
                    .exists()
                    .then(|| std::fs::read_to_string(device_path.join("bMaxPower")).ok())
                    .flatten()
                    .and_then(|s| parse_power_ma(&s))
                    .unwrap_or(0);

                devices.push(HubDevice {
                    path: name_str.to_string(),
                    product,
                    power_ma,
                });
            }
        }
    }

    // Sort by path for consistent output
    devices.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(devices)
}

/// Get USB power information for the Russignol device
///
/// Returns `Ok(Some(info))` with power details if device found,
/// `Ok(None)` if device not found or sysfs unavailable
pub fn get_usb_power_info() -> Result<Option<UsbPowerInfo>> {
    let Some(device_path) = get_device_sysfs_path()? else {
        return Ok(None);
    };

    let devices_base = Path::new("/sys/bus/usb/devices");
    let device_sysfs = devices_base.join(&device_path);

    // Read device power draw
    let device_power_ma = device_sysfs
        .join("bMaxPower")
        .exists()
        .then(|| std::fs::read_to_string(device_sysfs.join("bMaxPower")).ok())
        .flatten()
        .and_then(|s| parse_power_ma(&s))
        .unwrap_or(0);

    let behind_hub = is_behind_hub(&device_path);

    let hub_info = if behind_hub {
        if let Some(hub_path) = get_parent_hub_path(&device_path) {
            let hub_sysfs = devices_base.join(&hub_path);

            // Read hub's own power draw (0 = self-powered, >0 = bus-powered)
            let hub_power_ma = hub_sysfs
                .join("bMaxPower")
                .exists()
                .then(|| std::fs::read_to_string(hub_sysfs.join("bMaxPower")).ok())
                .flatten()
                .and_then(|s| parse_power_ma(&s))
                .unwrap_or(0);

            let is_bus_powered = hub_power_ma > 0;

            // Collect all devices on the hub
            let devices = collect_hub_devices(&hub_path)?;

            // Calculate total power draw
            let total_power_draw_ma: u32 = devices.iter().map(|d| d.power_ma).sum();

            let power_budget_ma = if is_bus_powered {
                USB_BUS_POWERED_BUDGET_MA
            } else {
                // Self-powered hubs can provide much more, but we don't warn about them
                0
            };

            Some(HubPowerInfo {
                hub_path,
                hub_power_ma,
                is_bus_powered,
                total_power_draw_ma,
                power_budget_ma,
                devices,
            })
        } else {
            None
        }
    } else {
        None
    };

    Ok(Some(UsbPowerInfo {
        device_path,
        device_power_ma,
        behind_hub,
        hub_info,
    }))
}

/// Check if a power warning should be displayed
///
/// Returns `Some(warning_message)` if power budget is exceeded on a bus-powered hub,
/// None otherwise
pub fn check_power_warning(power_info: &UsbPowerInfo) -> Option<String> {
    let hub_info = power_info.hub_info.as_ref()?;

    // Only warn for bus-powered hubs
    if !hub_info.is_bus_powered {
        return None;
    }

    // Only warn if over budget
    if hub_info.total_power_draw_ma <= hub_info.power_budget_ma {
        return None;
    }

    let device_list = format_hub_devices(&hub_info.devices, &power_info.device_path);

    Some(format!(
        "Device connected through bus-powered USB hub\n\
         Power budget: {}mA requested / {}mA available\n\
         \n\
         Devices on hub {}:\n\
         {}\n\
         \n\
         To resolve: Remove other devices from the hub, use a self-powered hub,\n\
         or connect Russignol directly to a host USB port.",
        hub_info.total_power_draw_ma, hub_info.power_budget_ma, hub_info.hub_path, device_list
    ))
}

/// Format the list of hub devices for display
pub fn format_hub_devices(devices: &[HubDevice], russignol_path: &str) -> String {
    let mut lines = Vec::new();
    let mut total = 0u32;

    for device in devices {
        let suffix = if device.path == russignol_path {
            " (this device)"
        } else {
            ""
        };
        lines.push(format!(
            "  {:<24} {:>3}mA{}",
            device.product, device.power_ma, suffix
        ));
        total += device.power_ma;
    }

    lines.push(format!("  {:<24} -----", ""));
    lines.push(format!("  {:<24} {:>3}mA", "Total", total));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_power_ma_valid() {
        assert_eq!(parse_power_ma("500mA"), Some(500));
        assert_eq!(parse_power_ma("100mA"), Some(100));
        assert_eq!(parse_power_ma("0mA"), Some(0));
        assert_eq!(parse_power_ma("  500mA  "), Some(500));
    }

    #[test]
    fn test_parse_power_ma_invalid() {
        assert_eq!(parse_power_ma("500"), None);
        assert_eq!(parse_power_ma("mA"), None);
        assert_eq!(parse_power_ma(""), None);
        assert_eq!(parse_power_ma("abc"), None);
        assert_eq!(parse_power_ma("500ma"), None); // Case sensitive
    }

    #[test]
    fn test_is_behind_hub_direct() {
        assert!(!is_behind_hub("3-7"));
        assert!(!is_behind_hub("1-1"));
        assert!(!is_behind_hub("usb1"));
    }

    #[test]
    fn test_is_behind_hub_through_hub() {
        assert!(is_behind_hub("3-7.2"));
        assert!(is_behind_hub("3-7.2.1"));
        assert!(is_behind_hub("1-1.4"));
    }

    #[test]
    fn test_get_parent_hub_path_direct() {
        assert_eq!(get_parent_hub_path("3-7"), None);
        assert_eq!(get_parent_hub_path("1-1"), None);
    }

    #[test]
    fn test_get_parent_hub_path_through_hub() {
        assert_eq!(get_parent_hub_path("3-7.2"), Some("3-7".to_string()));
        assert_eq!(get_parent_hub_path("1-1.4"), Some("1-1".to_string()));
        assert_eq!(get_parent_hub_path("3-7.2.1"), Some("3-7.2".to_string()));
    }

    #[test]
    fn test_check_power_warning_direct_connection() {
        let info = UsbPowerInfo {
            device_path: "3-7".to_string(),
            device_power_ma: 500,
            behind_hub: false,
            hub_info: None,
        };
        assert!(check_power_warning(&info).is_none());
    }

    #[test]
    fn test_check_power_warning_self_powered_hub() {
        let info = UsbPowerInfo {
            device_path: "3-7.2".to_string(),
            device_power_ma: 500,
            behind_hub: true,
            hub_info: Some(HubPowerInfo {
                hub_path: "3-7".to_string(),
                hub_power_ma: 0, // Self-powered
                is_bus_powered: false,
                total_power_draw_ma: 600,
                power_budget_ma: 0,
                devices: vec![],
            }),
        };
        assert!(check_power_warning(&info).is_none());
    }

    #[test]
    fn test_check_power_warning_bus_powered_under_budget() {
        let info = UsbPowerInfo {
            device_path: "3-7.2".to_string(),
            device_power_ma: 400,
            behind_hub: true,
            hub_info: Some(HubPowerInfo {
                hub_path: "3-7".to_string(),
                hub_power_ma: 100,
                is_bus_powered: true,
                total_power_draw_ma: 400,
                power_budget_ma: 500,
                devices: vec![HubDevice {
                    path: "3-7.2".to_string(),
                    product: "Russignol Signer".to_string(),
                    power_ma: 400,
                }],
            }),
        };
        assert!(check_power_warning(&info).is_none());
    }

    #[test]
    fn test_check_power_warning_bus_powered_over_budget() {
        let info = UsbPowerInfo {
            device_path: "3-7.2".to_string(),
            device_power_ma: 500,
            behind_hub: true,
            hub_info: Some(HubPowerInfo {
                hub_path: "3-7".to_string(),
                hub_power_ma: 100,
                is_bus_powered: true,
                total_power_draw_ma: 600,
                power_budget_ma: 500,
                devices: vec![
                    HubDevice {
                        path: "3-7.1".to_string(),
                        product: "USB Keyboard".to_string(),
                        power_ma: 100,
                    },
                    HubDevice {
                        path: "3-7.2".to_string(),
                        product: "Russignol Signer".to_string(),
                        power_ma: 500,
                    },
                ],
            }),
        };
        let warning = check_power_warning(&info);
        assert!(warning.is_some());
        let msg = warning.unwrap();
        assert!(msg.contains("600mA requested"));
        assert!(msg.contains("500mA available"));
        assert!(msg.contains("bus-powered USB hub"));
        assert!(msg.contains("Russignol Signer"));
        assert!(msg.contains("USB Keyboard"));
    }

    #[test]
    fn test_format_hub_devices() {
        let devices = vec![
            HubDevice {
                path: "3-7.1".to_string(),
                product: "USB Keyboard".to_string(),
                power_ma: 100,
            },
            HubDevice {
                path: "3-7.2".to_string(),
                product: "Russignol Signer".to_string(),
                power_ma: 500,
            },
        ];
        let output = format_hub_devices(&devices, "3-7.2");
        assert!(output.contains("USB Keyboard"));
        assert!(output.contains("100mA"));
        assert!(output.contains("Russignol Signer"));
        assert!(output.contains("500mA"));
        assert!(output.contains("(this device)"));
        assert!(output.contains("Total"));
        assert!(output.contains("600mA"));
    }
}
