//! USB gadget host link status without forking `ip`/`ping`.
//!
//! Interface up + IPv4 uses sysfs + `getifaddrs`. Host presence uses the
//! kernel neighbour table (`/proc/net/arp`) gated by sysfs `carrier`: ICMP
//! echo would need `CAP_NET_RAW` or a process fork. Carrier drops on USB
//! host unplug so a stale complete ARP entry cannot keep Host=OK after the
//! link is gone. Under normal baking the host is the complete ARP neighbour
//! on `usb0`.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

const INTERFACE_NAME: &str = "usb0";
const HOST_IP: &str = "169.254.1.2";
const BAKER_ACTIVITY_TIMEOUT: Duration = Duration::from_mins(1);
const SYSFS_NET: &str = "/sys/class/net";
const PROC_ARP: &str = "/proc/net/arp";

/// `ATF_COM` — neighbour entry is complete (has a MAC).
const ARP_FLAG_COMPLETE: u32 = 0x2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkStatus {
    pub interface_configured: bool,
    pub host_reachable: bool,
    pub baker_active: bool,
}

impl NetworkStatus {
    /// Check the current network status including baker activity.
    pub fn check(last_baker_request: Option<SystemTime>) -> Self {
        Self::check_with(
            last_baker_request,
            SystemTime::now(),
            Path::new(SYSFS_NET),
            Path::new(PROC_ARP),
            INTERFACE_NAME,
            HOST_IP,
        )
    }

    /// Testable entry: inject clock, sysfs net root, ARP path, and names.
    pub fn check_with(
        last_baker_request: Option<SystemTime>,
        now: SystemTime,
        sysfs_net: &Path,
        arp_path: &Path,
        interface: &str,
        host_ip: &str,
    ) -> Self {
        let iface_dir = sysfs_net.join(interface);
        let carrier = read_carrier(&iface_dir);
        let interface_configured = interface_configured(sysfs_net, interface, carrier);
        let host_reachable = if interface_configured {
            host_reachable(arp_path, host_ip, interface, carrier)
        } else {
            false
        };
        let baker_active = baker_active_at(last_baker_request, now);

        Self {
            interface_configured,
            host_reachable,
            baker_active,
        }
    }
}

#[must_use]
pub fn baker_active_at(last_baker_request: Option<SystemTime>, now: SystemTime) -> bool {
    let Some(last_time) = last_baker_request else {
        return false;
    };
    match now.duration_since(last_time) {
        Ok(elapsed) => elapsed < BAKER_ACTIVITY_TIMEOUT,
        Err(_) => false,
    }
}

/// Link is usable: `operstate=up`, or `operstate=unknown` with carrier present.
///
/// USB gadgets sometimes report `unknown` while carrier is asserted; requiring
/// only exact `up` would show Offline with a live host. Explicit `down` and
/// `unknown` without carrier stay offline.
#[must_use]
pub fn link_is_up(operstate: &str, carrier: Option<bool>) -> bool {
    let op = operstate.trim();
    if op.eq_ignore_ascii_case("up") {
        return true;
    }
    if op.eq_ignore_ascii_case("unknown") && carrier == Some(true) {
        return true;
    }
    false
}

/// Host present: L2 carrier (when known) and a complete ARP neighbour.
///
/// `carrier == Some(false)` means the USB host link is down — refuse even if
/// `/proc/net/arp` still lists a complete entry (stale after unplug).
#[must_use]
pub fn host_reachable_from(
    arp_table: &str,
    host_ip: &str,
    interface: &str,
    carrier: Option<bool>,
) -> bool {
    if carrier == Some(false) {
        return false;
    }
    arp_has_complete_neighbour(arp_table, host_ip, interface)
}

/// Interface exists, link is up, and has a non-loopback IPv4.
fn interface_configured(sysfs_net: &Path, interface: &str, carrier: Option<bool>) -> bool {
    let iface_dir = sysfs_net.join(interface);
    if !iface_dir.is_dir() {
        log::debug!(
            "Interface {interface} not present under {}",
            sysfs_net.display()
        );
        return false;
    }

    let operstate = fs::read_to_string(iface_dir.join("operstate")).unwrap_or_default();
    if !link_is_up(&operstate, carrier) {
        log::debug!(
            "Interface {interface} link not up: operstate={} carrier={carrier:?}",
            operstate.trim()
        );
        return false;
    }

    if !interface_has_ipv4(interface) {
        log::debug!("Interface {interface} has no IPv4 address");
        return false;
    }

    log::debug!("Interface {interface} up with IPv4");
    true
}

/// Read sysfs `carrier` (`1` / `0`). `None` if the file is missing or unreadable
/// (some virtual nics omit it).
fn read_carrier(iface_dir: &Path) -> Option<bool> {
    let raw = fs::read_to_string(iface_dir.join("carrier")).ok()?;
    match raw.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// True when `getifaddrs` reports a non-loopback IPv4 on `interface`.
fn interface_has_ipv4(interface: &str) -> bool {
    // SAFETY: getifaddrs allocates a linked list we free with freeifaddrs.
    // We only read ifa_name / ifa_addr while the list is live.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&raw mut ifap) != 0 {
            log::debug!("getifaddrs failed for interface check");
            return false;
        }
        let mut found = false;
        let mut cur = ifap;
        while !cur.is_null() {
            let entry = &*cur;
            if !entry.ifa_name.is_null() {
                let name = std::ffi::CStr::from_ptr(entry.ifa_name);
                if name.to_bytes() == interface.as_bytes()
                    && let Some(addr) = entry.ifa_addr.as_ref()
                    && i32::from(addr.sa_family) == libc::AF_INET
                {
                    // Kernel may return under-aligned sockaddr pointers; copy.
                    let sin: libc::sockaddr_in = std::ptr::read_unaligned(entry.ifa_addr.cast());
                    let ip = u32::from_be(sin.sin_addr.s_addr);
                    // Skip 127.0.0.0/8
                    if (ip >> 24) != 127 {
                        found = true;
                        break;
                    }
                }
            }
            cur = entry.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found
    }
}

/// Host is a complete ARP neighbour on `interface` for `host_ip`, unless
/// carrier is known-down.
fn host_reachable(arp_path: &Path, host_ip: &str, interface: &str, carrier: Option<bool>) -> bool {
    if carrier == Some(false) {
        log::debug!("Host not reachable: carrier down on {interface}");
        return false;
    }
    let Ok(contents) = fs::read_to_string(arp_path) else {
        log::debug!("Failed to read {}", arp_path.display());
        return false;
    };
    let reachable = host_reachable_from(&contents, host_ip, interface, carrier);
    log::debug!(
        "ARP neighbour {host_ip} on {interface}: {}",
        if reachable { "complete" } else { "absent" }
    );
    reachable
}

/// Parse `/proc/net/arp` text for a complete entry matching IP and device.
///
/// Format: `IP address HW type Flags HW address Mask Device`
/// Flags bit `0x2` (`ATF_COM`) means the MAC is resolved.
#[must_use]
pub fn arp_has_complete_neighbour(arp_table: &str, host_ip: &str, interface: &str) -> bool {
    for line in arp_table.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let Some(ip) = cols.next() else {
            continue;
        };
        if ip != host_ip {
            continue;
        }
        // HW type
        let _ = cols.next();
        let Some(flags_s) = cols.next() else {
            continue;
        };
        // HW address, Mask
        let _ = cols.next();
        let _ = cols.next();
        let Some(dev) = cols.next() else {
            continue;
        };
        if dev != interface {
            continue;
        }
        let flags = parse_arp_flags(flags_s);
        if flags & ARP_FLAG_COMPLETE != 0 {
            return true;
        }
    }
    false
}

fn parse_arp_flags(s: &str) -> u32 {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        trimmed.parse().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    const COMPLETE_ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
169.254.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        usb0
";

    #[test]
    fn link_is_up_accepts_up_and_unknown_with_carrier() {
        assert!(link_is_up("up\n", None));
        assert!(link_is_up("UP", Some(false)));
        assert!(link_is_up("unknown", Some(true)));
        assert!(link_is_up("UNKNOWN\n", Some(true)));
        assert!(!link_is_up("unknown", Some(false)));
        assert!(!link_is_up("unknown", None));
        assert!(!link_is_up("down\n", Some(true)));
        assert!(!link_is_up("", None));
    }

    #[test]
    fn host_reachable_from_rejects_no_carrier_despite_complete_arp() {
        assert!(host_reachable_from(
            COMPLETE_ARP,
            "169.254.1.2",
            "usb0",
            Some(true)
        ));
        assert!(host_reachable_from(
            COMPLETE_ARP,
            "169.254.1.2",
            "usb0",
            None
        ));
        assert!(!host_reachable_from(
            COMPLETE_ARP,
            "169.254.1.2",
            "usb0",
            Some(false)
        ));
    }

    #[test]
    fn arp_complete_neighbour_detected() {
        assert!(arp_has_complete_neighbour(
            COMPLETE_ARP,
            "169.254.1.2",
            "usb0"
        ));
    }

    #[test]
    fn arp_incomplete_or_wrong_device_not_reachable() {
        let incomplete = "\
IP address       HW type     Flags       HW address            Mask     Device
169.254.1.2      0x1         0x0         00:00:00:00:00:00     *        usb0
";
        assert!(!arp_has_complete_neighbour(
            incomplete,
            "169.254.1.2",
            "usb0"
        ));

        let wrong_dev = "\
IP address       HW type     Flags       HW address            Mask     Device
169.254.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
";
        assert!(!arp_has_complete_neighbour(
            wrong_dev,
            "169.254.1.2",
            "usb0"
        ));

        assert!(!arp_has_complete_neighbour(
            "IP address HW type Flags HW address Mask Device\n",
            "169.254.1.2",
            "usb0"
        ));
    }

    #[test]
    fn baker_active_boundary_at_one_minute() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let just_inside = now - Duration::from_secs(59);
        let just_outside = now - Duration::from_mins(1);
        assert!(baker_active_at(Some(just_inside), now));
        assert!(!baker_active_at(Some(just_outside), now));
        assert!(!baker_active_at(None, now));
    }

    #[test]
    fn network_status_eq_tracks_axis_flips() {
        // Status page invalidates when the paint snapshot differs; NetworkStatus
        // is one axis of that snapshot via PartialEq.
        let a = NetworkStatus {
            interface_configured: true,
            host_reachable: true,
            baker_active: false,
        };
        assert_eq!(a, a);
        assert_ne!(
            a,
            NetworkStatus {
                baker_active: true,
                ..a
            }
        );
        assert_ne!(
            a,
            NetworkStatus {
                host_reachable: false,
                ..a
            }
        );
        assert_ne!(
            a,
            NetworkStatus {
                interface_configured: false,
                ..a
            }
        );
    }

    #[test]
    fn check_with_missing_interface_is_offline() {
        let dir = tempfile::tempdir().unwrap();
        let arp = dir.path().join("arp");
        fs::write(&arp, "IP address HW type Flags HW address Mask Device\n").unwrap();
        let status = NetworkStatus::check_with(
            None,
            SystemTime::UNIX_EPOCH,
            dir.path(),
            &arp,
            "usb0",
            "169.254.1.2",
        );
        assert!(!status.interface_configured);
        assert!(!status.host_reachable);
        assert!(!status.baker_active);
    }

    #[test]
    fn check_with_down_operstate_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let iface = dir.path().join("usb0");
        fs::create_dir(&iface).unwrap();
        fs::write(iface.join("operstate"), "down\n").unwrap();
        fs::write(iface.join("carrier"), "0\n").unwrap();
        let arp = dir.path().join("arp");
        fs::write(&arp, COMPLETE_ARP).unwrap();
        let status = NetworkStatus::check_with(
            None,
            SystemTime::UNIX_EPOCH,
            dir.path(),
            &arp,
            "usb0",
            "169.254.1.2",
        );
        assert!(!status.interface_configured);
        assert!(!status.host_reachable);
    }

    #[test]
    fn check_with_unknown_operstate_without_carrier_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let iface = dir.path().join("usb0");
        fs::create_dir(&iface).unwrap();
        fs::write(iface.join("operstate"), "unknown\n").unwrap();
        fs::write(iface.join("carrier"), "0\n").unwrap();
        let arp = dir.path().join("arp");
        fs::write(&arp, COMPLETE_ARP).unwrap();
        let status = NetworkStatus::check_with(
            None,
            SystemTime::UNIX_EPOCH,
            dir.path(),
            &arp,
            "usb0",
            "169.254.1.2",
        );
        assert!(!status.interface_configured);
        assert!(!status.host_reachable);
    }

    #[test]
    fn read_carrier_parses_sysfs() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("carrier"), "1\n").unwrap();
        assert_eq!(read_carrier(dir.path()), Some(true));
        fs::write(dir.path().join("carrier"), "0").unwrap();
        assert_eq!(read_carrier(dir.path()), Some(false));
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(read_carrier(empty.path()), None);
    }
}
