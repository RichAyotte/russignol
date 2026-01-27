//! Runtime storage partitioning for first-boot setup
//!
//! This module handles hardware-adaptive partition creation at first boot:
//! 1. Detects SD card discard granularity from sysfs
//! 2. Creates 16MB-aligned Keys (p3) and Data (p4) partitions using sfdisk
//! 3. Notifies kernel via BLKPG ioctl (no reboot needed)
//! 4. Runs conditional TRIM on partition areas and over-provisioning space
//! 5. Formats with F2FS using `inline_data/inline_dentry` for small file optimization
//! 6. Drops root privileges to russignol user after setup completes
//!
//! The remaining SD card space is left unpartitioned for controller wear leveling.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

// Constants
const MIN_ALIGNMENT: u64 = 16 * 1024 * 1024; // 16MB minimum alignment
const F2FS_PARTITION_SIZE: u64 = 64 * 1024 * 1024; // 64MB for each partition
const SECTOR_SIZE: u64 = 512;

// Device paths
const DISK: &str = "/dev/mmcblk0";
const KEYS_PART: &str = "/dev/mmcblk0p3";
const DATA_PART: &str = "/dev/mmcblk0p4";
const KEYS_MOUNT: &str = "/keys";
const DATA_MOUNT: &str = "/data";

// Command paths
const SFDISK: &str = "/sbin/sfdisk";
const BLKDISCARD: &str = "/sbin/blkdiscard";
const MKFS_F2FS: &str = "/usr/sbin/mkfs.f2fs";
const MOUNT: &str = "/bin/mount";
const MDEV: &str = "/sbin/mdev";
const SYNC: &str = "/bin/sync";
const CHOWN: &str = "/bin/chown";

// F2FS mount options for data partition
// F2FS mount options: inline_data/inline_dentry store small files in inode (no data block needed)
const F2FS_MOUNT_OPTS: &str = "rw,inline_data,inline_dentry,fsync_mode=strict,compress_algorithm=zstd,compress_chksum,atgc,gc_merge,alloc_mode=reuse,background_gc=off,errors=remount-ro";

// BLKPG ioctl constants for kernel notification
const BLKPG: libc::c_ulong = 0x1269; // _IO(0x12, 105)
const BLKPG_ADD_PARTITION: libc::c_int = 1;

use crate::util::run_command;

/// Partition layout calculated from hardware parameters
#[derive(Debug)]
#[allow(dead_code)] // Fields used for Debug output and diagnostic logging
pub struct PartitionLayout {
    pub alignment: u64,
    pub keys_start_sector: u64,
    pub keys_size_sectors: u64,
    pub data_start_sector: u64,
    pub data_size_sectors: u64,
    pub disk_size_sectors: u64,
    pub trim_supported: bool,
}

// BLKPG structures - must match kernel's blkpg.h
#[repr(C)]
struct BlkpgPartition {
    start: i64,
    length: i64,
    pno: libc::c_int,
    devname: [u8; 64],
    volname: [u8; 64],
}

#[repr(C)]
struct BlkpgIoctlArg {
    op: libc::c_int,
    flags: libc::c_int,
    datalen: libc::c_int,
    data: *mut BlkpgPartition,
}

/// Run complete storage setup with progress updates
pub fn setup_storage<F>(progress: F) -> Result<(), String>
where
    F: Fn(&str, u8) -> Result<(), String>,
{
    progress("Detecting storage...", 5)?;
    let alignment = calculate_alignment();
    let trim_supported = is_trim_supported();
    log::info!(
        "Storage detected: alignment={}MB, trim={}",
        alignment / (1024 * 1024),
        trim_supported
    );

    progress("Planning partitions...", 10)?;
    let layout = calculate_partition_layout(alignment, trim_supported)?;
    log::info!("Partition layout: {layout:?}");

    progress("Creating partitions...", 20)?;
    create_partitions(&layout)?;

    progress("Waiting for devices...", 30)?;
    wait_for_partition_devices()?;

    if trim_supported {
        progress("Optimizing keys area...", 40)?;
        trim_partition_range(
            layout.keys_start_sector * SECTOR_SIZE,
            layout.keys_size_sectors * SECTOR_SIZE,
        )?;

        progress("Optimizing data area...", 50)?;
        trim_partition_range(
            layout.data_start_sector * SECTOR_SIZE,
            layout.data_size_sectors * SECTOR_SIZE,
        )?;
    }

    progress("Formatting keys...", 60)?;
    format_partition(KEYS_PART, "russignol-keys")?;

    progress("Formatting data...", 75)?;
    format_partition(DATA_PART, "russignol-data")?;

    if trim_supported {
        progress("Optimizing free space...", 85)?;
        trim_over_provisioning(&layout)?;
    }

    progress("Mounting storage...", 95)?;
    mount_partitions()?;

    progress("Storage ready!", 100)?;

    // Sync to ensure everything is written
    let _ = Command::new(SYNC).output();

    Ok(())
}

/// Detect discard granularity from sysfs
fn detect_discard_granularity() -> Option<u64> {
    let path = "/sys/block/mmcblk0/queue/discard_granularity";
    match fs::read_to_string(path) {
        Ok(s) => s.trim().parse().ok(),
        Err(_) => None,
    }
}

/// Check if TRIM/discard is supported
fn is_trim_supported() -> bool {
    detect_discard_granularity().is_some_and(|g| g > 0)
}

/// Calculate optimal alignment for this hardware
fn calculate_alignment() -> u64 {
    match detect_discard_granularity() {
        Some(granularity) if granularity > 0 => {
            // Use MAX(16MB, discard_granularity)
            std::cmp::max(MIN_ALIGNMENT, granularity)
        }
        _ => {
            log::warn!("Could not detect discard granularity, using 16MB default");
            MIN_ALIGNMENT
        }
    }
}

/// Round up to alignment boundary
fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

/// Read a sysfs value as u64
fn read_sysfs_u64(path: &str) -> Result<u64, String> {
    fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {path}: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("Failed to parse {path}: {e}"))
}

/// Calculate partition layout based on hardware parameters
fn calculate_partition_layout(
    alignment: u64,
    trim_supported: bool,
) -> Result<PartitionLayout, String> {
    // Get disk size from sysfs
    let disk_size_sectors = read_sysfs_u64("/sys/block/mmcblk0/size")?;
    let disk_size_bytes = disk_size_sectors * SECTOR_SIZE;

    // Get partition 2 (rootfs) end position
    let p2_start_sectors = read_sysfs_u64("/sys/block/mmcblk0/mmcblk0p2/start")?;
    let p2_size_sectors = read_sysfs_u64("/sys/block/mmcblk0/mmcblk0p2/size")?;
    let p2_end_bytes = (p2_start_sectors + p2_size_sectors) * SECTOR_SIZE;

    // Keys partition (p3): starts at first aligned boundary after rootfs
    let keys_start_bytes = align_up(p2_end_bytes, alignment);
    let keys_size_bytes = align_up(F2FS_PARTITION_SIZE, alignment);
    let keys_end_bytes = keys_start_bytes + keys_size_bytes;

    // Data partition (p4): starts at first aligned boundary after keys
    let data_start_bytes = keys_end_bytes; // Already aligned
    let data_size_bytes = align_up(F2FS_PARTITION_SIZE, alignment);
    let data_end_bytes = data_start_bytes + data_size_bytes;

    // Validation
    if data_end_bytes > disk_size_bytes {
        return Err(format!(
            "Insufficient disk space: need {}MB for partitions, have {}MB",
            data_end_bytes / (1024 * 1024),
            disk_size_bytes / (1024 * 1024)
        ));
    }

    let layout = PartitionLayout {
        alignment,
        keys_start_sector: keys_start_bytes / SECTOR_SIZE,
        keys_size_sectors: keys_size_bytes / SECTOR_SIZE,
        data_start_sector: data_start_bytes / SECTOR_SIZE,
        data_size_sectors: data_size_bytes / SECTOR_SIZE,
        disk_size_sectors,
        trim_supported,
    };

    log::info!(
        "Partition layout: keys={}MB@sector{}, data={}MB@sector{}, over-prov={}MB",
        keys_size_bytes / (1024 * 1024),
        layout.keys_start_sector,
        data_size_bytes / (1024 * 1024),
        layout.data_start_sector,
        (disk_size_bytes - data_end_bytes) / (1024 * 1024)
    );

    Ok(layout)
}

/// Create partitions using sfdisk (util-linux)
fn create_partitions(layout: &PartitionLayout) -> Result<(), String> {
    log::info!("Creating partitions using sfdisk...");

    // sfdisk script format: start=<sector>, size=<sectors>, type=<hex>
    let script = format!(
        "start={}, size={}, type=83\nstart={}, size={}, type=83\n",
        layout.keys_start_sector,
        layout.keys_size_sectors,
        layout.data_start_sector,
        layout.data_size_sectors
    );

    log::info!("sfdisk script:\n{script}");

    let mut child = Command::new(SFDISK)
        .args(["--append", "--no-reread", DISK])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn sfdisk: {e}"))?;

    child
        .stdin
        .as_mut()
        .ok_or("Failed to open sfdisk stdin")?
        .write_all(script.as_bytes())
        .map_err(|e| format!("Failed to write to sfdisk: {e}"))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("sfdisk failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "sfdisk error: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    log::info!("sfdisk completed successfully");

    // Sync to ensure partition table is written
    let _ = Command::new(SYNC).output();
    thread::sleep(Duration::from_millis(200));

    // Notify kernel immediately via BLKPG (no partprobe needed)
    notify_kernel_blkpg(
        3,
        layout.keys_start_sector * SECTOR_SIZE,
        layout.keys_size_sectors * SECTOR_SIZE,
    )?;
    notify_kernel_blkpg(
        4,
        layout.data_start_sector * SECTOR_SIZE,
        layout.data_size_sectors * SECTOR_SIZE,
    )?;

    // Trigger mdev to create device nodes
    let _ = Command::new(SYNC).output();
    thread::sleep(Duration::from_millis(300));

    log::info!("Running mdev -s to create device nodes");
    let mdev_output = Command::new(MDEV)
        .arg("-s")
        .output()
        .map_err(|e| format!("Failed to run mdev: {e}"))?;

    if !mdev_output.status.success() {
        log::warn!(
            "mdev -s returned non-zero: {}",
            String::from_utf8_lossy(&mdev_output.stderr)
        );
    }

    Ok(())
}

/// Notify kernel about new partition using BLKPG ioctl
fn notify_kernel_blkpg(
    partition_num: i32,
    start_bytes: u64,
    size_bytes: u64,
) -> Result<(), String> {
    log::info!(
        "Notifying kernel via BLKPG: partition {partition_num}, start={start_bytes}, size={size_bytes}"
    );

    let disk_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DISK)
        .map_err(|e| format!("Failed to open {DISK}: {e}"))?;

    let mut partition = BlkpgPartition {
        start: start_bytes.cast_signed(),
        length: size_bytes.cast_signed(),
        pno: partition_num,
        devname: [0; 64],
        volname: [0; 64],
    };

    let mut arg = BlkpgIoctlArg {
        op: BLKPG_ADD_PARTITION,
        flags: 0,
        datalen: libc::c_int::try_from(std::mem::size_of::<BlkpgPartition>())
            .expect("BlkpgPartition size fits in c_int"),
        data: &raw mut partition,
    };

    let ret = unsafe { libc::ioctl(disk_fd.as_raw_fd(), BLKPG, &mut arg) };

    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!(
            "BLKPG ioctl failed for partition {partition_num}: {errno}"
        ));
    }

    log::info!("BLKPG_ADD_PARTITION succeeded for partition {partition_num}");
    Ok(())
}

/// Wait for partition device nodes to appear
fn wait_for_partition_devices() -> Result<(), String> {
    const MAX_ATTEMPTS: u32 = 30;

    for attempt in 1..=MAX_ATTEMPTS {
        let p3_exists =
            Path::new(KEYS_PART).exists() && Path::new("/sys/block/mmcblk0/mmcblk0p3").exists();
        let p4_exists =
            Path::new(DATA_PART).exists() && Path::new("/sys/block/mmcblk0/mmcblk0p4").exists();

        if p3_exists && p4_exists {
            log::info!("Partition devices found: {KEYS_PART} and {DATA_PART}");
            return Ok(());
        }

        if attempt == MAX_ATTEMPTS {
            // Last attempt - try mdev again
            let _ = Command::new(MDEV).arg("-s").output();
            thread::sleep(Duration::from_millis(500));

            if Path::new(KEYS_PART).exists() && Path::new(DATA_PART).exists() {
                return Ok(());
            }

            return Err("Partition devices not found after 15 seconds".into());
        }

        log::info!("Waiting for partition devices (attempt {attempt}/{MAX_ATTEMPTS})");
        thread::sleep(Duration::from_millis(500));
    }

    Err("Partition devices not found".into())
}

/// Run blkdiscard on a range (TRIM)
fn trim_partition_range(offset_bytes: u64, length_bytes: u64) -> Result<(), String> {
    log::info!("Running blkdiscard: offset={offset_bytes}, length={length_bytes} bytes");

    let output = Command::new(BLKDISCARD)
        .args([
            "--offset",
            &offset_bytes.to_string(),
            "--length",
            &length_bytes.to_string(),
            DISK,
        ])
        .output()
        .map_err(|e| format!("Failed to run blkdiscard: {e}"))?;

    if output.status.success() {
        log::info!("blkdiscard completed for range");
    } else {
        // blkdiscard failure is non-fatal
        log::warn!(
            "blkdiscard failed (continuing): {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// TRIM the over-provisioning area (unallocated tail of disk)
fn trim_over_provisioning(layout: &PartitionLayout) -> Result<(), String> {
    let data_end_bytes = (layout.data_start_sector + layout.data_size_sectors) * SECTOR_SIZE;
    let disk_size_bytes = layout.disk_size_sectors * SECTOR_SIZE;
    let overprov_size = disk_size_bytes - data_end_bytes;

    if overprov_size > 0 {
        log::info!(
            "TRIMming over-provisioning area: {}MB",
            overprov_size / (1024 * 1024)
        );
        trim_partition_range(data_end_bytes, overprov_size)?;
    }

    Ok(())
}

/// Format a partition with F2FS using inline optimizations
fn format_partition(device: &str, label: &str) -> Result<(), String> {
    log::info!("Formatting {device} with F2FS label '{label}' and small-file optimizations");

    // Note: inline_data and inline_dentry are enabled by default in F2FS
    // (files < 3.4KB stored in inode). Only extra_attr and compression need -O flag.
    let output = Command::new(MKFS_F2FS)
        .args([
            "-l",
            label,
            "-O",
            "extra_attr,compression",
            "-f", // Force overwrite
            device,
        ])
        .output()
        .map_err(|e| format!("Failed to run mkfs.f2fs: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "mkfs.f2fs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    log::info!("mkfs.f2fs completed for {device}");
    Ok(())
}

/// Mount the partitions after formatting
fn mount_partitions() -> Result<(), String> {
    // Create mount points
    fs::create_dir_all(KEYS_MOUNT).map_err(|e| format!("Failed to create {KEYS_MOUNT}: {e}"))?;
    fs::create_dir_all(DATA_MOUNT).map_err(|e| format!("Failed to create {DATA_MOUNT}: {e}"))?;

    // Mount keys partition (read-write for now, will be remounted RO after setup)
    let output = Command::new(MOUNT)
        .args(["-t", "f2fs", "-o", "rw", KEYS_PART, KEYS_MOUNT])
        .output()
        .map_err(|e| format!("Failed to mount keys partition: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to mount keys partition: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    log::info!("Keys partition mounted at {KEYS_MOUNT}");

    // Mount data partition with F2FS options
    let output = Command::new(MOUNT)
        .args(["-t", "f2fs", "-o", F2FS_MOUNT_OPTS, DATA_PART, DATA_MOUNT])
        .output()
        .map_err(|e| format!("Failed to mount data partition: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to mount data partition: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    log::info!("Data partition mounted at {DATA_MOUNT}");

    // Set ownership of mount points to russignol user
    let _ = Command::new(CHOWN)
        .args(["-R", "russignol:russignol", KEYS_MOUNT])
        .output();
    let _ = Command::new(CHOWN)
        .args(["-R", "russignol:russignol", DATA_MOUNT])
        .output();

    Ok(())
}

/// Remount keys partition as read-only for security
///
/// Must be called after key generation is complete and setup marker is written.
/// Requires root privileges.
pub fn remount_keys_readonly() -> Result<(), String> {
    log::info!("Remounting {KEYS_MOUNT} as read-only");
    run_command(MOUNT, &["-o", "remount,ro", KEYS_MOUNT])?;
    log::info!("Keys partition remounted read-only");
    Ok(())
}

// Russignol user UID/GID (from /etc/passwd: russignol:x:1000:1000)
const RUSSIGNOL_UID: libc::uid_t = 1000;
const RUSSIGNOL_GID: libc::gid_t = 1000;

/// Drop root privileges to russignol user
///
/// Must be called after storage setup completes. Uses `setgid()` then `setuid()`
/// to permanently drop privileges. This is a one-way operation.
///
/// Returns Ok(true) if privileges were dropped, Ok(false) if already unprivileged.
pub fn drop_privileges() -> Result<bool, String> {
    // Check current UID
    let current_uid = unsafe { libc::getuid() };

    if current_uid != 0 {
        log::info!("Already running as unprivileged user (uid={current_uid})");
        return Ok(false);
    }

    log::info!(
        "Dropping privileges from root to russignol (uid={RUSSIGNOL_UID}, gid={RUSSIGNOL_GID})"
    );

    // Drop group privileges first (must be done before dropping user)
    if unsafe { libc::setgid(RUSSIGNOL_GID) } != 0 {
        return Err(format!(
            "Failed to setgid({}): {}",
            RUSSIGNOL_GID,
            std::io::Error::last_os_error()
        ));
    }

    // Drop supplementary groups
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        log::warn!(
            "Failed to clear supplementary groups: {}",
            std::io::Error::last_os_error()
        );
        // Non-fatal, continue
    }

    // Drop user privileges (point of no return)
    if unsafe { libc::setuid(RUSSIGNOL_UID) } != 0 {
        return Err(format!(
            "Failed to setuid({}): {}",
            RUSSIGNOL_UID,
            std::io::Error::last_os_error()
        ));
    }

    // Verify we actually dropped privileges
    let verified_user_id = unsafe { libc::getuid() };
    let verified_group_id = unsafe { libc::getgid() };

    if verified_user_id != RUSSIGNOL_UID || verified_group_id != RUSSIGNOL_GID {
        return Err(format!(
            "Privilege drop verification failed: uid={verified_user_id}, gid={verified_group_id}"
        ));
    }

    log::info!(
        "Privileges dropped successfully (now uid={verified_user_id}, gid={verified_group_id})"
    );
    Ok(true)
}
