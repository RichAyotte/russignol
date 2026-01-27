use std::process::Command;
use std::time::{Duration, SystemTime};

const INTERFACE_NAME: &str = "usb0";
const HOST_IP: &str = "169.254.1.2";
const BAKER_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(60); // Consider baker idle after 60s

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkStatus {
    pub interface_configured: bool,
    pub host_reachable: bool,
    pub baker_active: bool,
}

impl NetworkStatus {
    /// Check the current network status including baker activity
    pub fn check(last_baker_request: Option<SystemTime>) -> Self {
        let interface_configured = check_interface_configured();
        let host_reachable = if interface_configured {
            check_host_reachable()
        } else {
            false
        };

        // Check if baker has sent a request recently
        let baker_active = if let Some(last_time) = last_baker_request {
            if let Ok(elapsed) = SystemTime::now().duration_since(last_time) {
                elapsed < BAKER_ACTIVITY_TIMEOUT
            } else {
                false
            }
        } else {
            false
        };

        Self {
            interface_configured,
            host_reachable,
            baker_active,
        }
    }
}

/// Check if the network interface has an IP address configured
fn check_interface_configured() -> bool {
    // Try to get IP address using `ip addr show usb0`
    let output = match Command::new("ip")
        .args(["addr", "show", INTERFACE_NAME])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            log::warn!("Failed to run 'ip addr show {INTERFACE_NAME}': {e}");
            return false;
        }
    };

    if !output.status.success() {
        log::warn!("Interface {INTERFACE_NAME} does not exist (command failed)");
        log::debug!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        return false;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    log::debug!("ip addr show {INTERFACE_NAME} output:\n{stdout}");

    // Check if interface is UP (look for both "state UP" and just "UP" in flags)
    let is_up = stdout.contains("state UP") || stdout.contains('<') && stdout.contains("UP");
    if !is_up {
        log::warn!("Interface {INTERFACE_NAME} is not UP");
        return false;
    }

    // Check if there's an inet (IPv4) address
    let has_ip = stdout.lines().any(|line| {
        let trimmed = line.trim();
        let is_inet = trimmed.starts_with("inet ") && !trimmed.contains("127.0.0.1");
        if is_inet {
            log::debug!("Found IP line: {trimmed}");
        }
        is_inet
    });

    if !has_ip {
        log::warn!("Interface {INTERFACE_NAME} has no IP address assigned");
        return false;
    }

    log::info!("✓ Interface {INTERFACE_NAME} is configured and UP with IP address");
    true
}

/// Check if the host is reachable via ping
fn check_host_reachable() -> bool {
    // Use ping with:
    // -c 1: Send only 1 packet
    // -W 1: Wait max 1 second for response
    // -q: Quiet output
    log::debug!("Pinging host at {HOST_IP}...");
    let output = match Command::new("ping")
        .args(["-c", "1", "-W", "1", "-q", HOST_IP])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            log::warn!("Failed to run ping command for {HOST_IP}: {e}");
            return false;
        }
    };

    let success = output.status.success();
    if success {
        log::info!("✓ Host {HOST_IP} is reachable");
    } else {
        log::warn!("Host {HOST_IP} is unreachable");
        log::debug!("ping stdout: {}", String::from_utf8_lossy(&output.stdout));
        log::debug!("ping stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    success
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_status_check() {
        // Just verify it doesn't panic
        let status = NetworkStatus::check(None);
        println!("Network status: {status:?}");
    }
}
