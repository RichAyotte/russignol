//! Shared utility functions

use crate::constants::{BOOT_MOUNT, BOOT_PARTITION};
use std::process::Command;

/// Run a command and return Ok(()) on success, or error with stderr on failure
pub fn run_command(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {cmd}: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub fn mount_boot_partition() -> Result<(), String> {
    std::fs::create_dir_all(BOOT_MOUNT)
        .map_err(|e| format!("Failed to create mount point: {e}"))?;

    // Check if already mounted (e.g. from a previous attempt or manual SSH inspection)
    if is_mounted(BOOT_MOUNT) {
        log::info!("Boot partition already mounted at {BOOT_MOUNT}");
        return Ok(());
    }

    run_command(
        "/bin/mount",
        &["-t", "vfat", "-o", "rw", BOOT_PARTITION, BOOT_MOUNT],
    )?;
    log::debug!("Mounted {BOOT_PARTITION} to {BOOT_MOUNT}");
    Ok(())
}

/// Check if a path is a mount point by reading /proc/mounts
pub fn is_mounted(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts").is_ok_and(|contents| {
        contents
            .lines()
            .any(|line| line.split(' ').nth(1) == Some(path))
    })
}

pub fn unmount_boot_partition() -> Result<(), String> {
    let _ = Command::new("/bin/sync").output(); // Sync first, ignore result
    run_command("/bin/umount", &[BOOT_MOUNT])?;
    let _ = std::fs::remove_dir(BOOT_MOUNT); // Clean up mount point
    log::debug!("Unmounted {BOOT_MOUNT}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_command_failure() {
        let result = run_command("/bin/false", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed"));
    }

    #[test]
    fn test_run_command_not_found() {
        let result = run_command("/nonexistent/command", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to run"));
    }
}
