use core::fmt;

/// 16 MB minimum alignment for partition boundaries
pub const MIN_ALIGNMENT: u64 = 16 * 1024 * 1024;

/// 64 MB for each F2FS partition (keys, data)
pub const F2FS_PARTITION_SIZE: u64 = 64 * 1024 * 1024;

/// Standard sector size
pub const SECTOR_SIZE: u64 = 512;

/// F2FS feature flags passed to `mkfs.f2fs -O`
pub const F2FS_FORMAT_FEATURES: &str = "extra_attr,compression";

/// Partition layout for keys (p3) and data (p4) partitions in sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionLayout {
    pub keys_start_sector: u64,
    pub keys_size_sectors: u64,
    pub data_start_sector: u64,
    pub data_size_sectors: u64,
}

/// Error returned when partition layout calculation fails.
#[derive(Debug)]
pub struct InsufficientSpace {
    pub need_mb: u64,
    pub have_mb: u64,
}

impl fmt::Display for InsufficientSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Insufficient disk space for key/data partitions: need {}MB, have {}MB",
            self.need_mb, self.have_mb
        )
    }
}

/// Round `value` up to the next multiple of `alignment`.
///
/// Returns 0 when `value` is 0.
pub fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

/// Calculate partition layout for keys (p3) and data (p4) partitions.
///
/// Given the byte offset where partition 2 (rootfs) ends, the alignment
/// to use, and the total disk size in bytes, computes sector-based start
/// and size values for two 64 MB F2FS partitions.
pub fn calculate_partition_layout(
    p2_end_bytes: u64,
    alignment: u64,
    disk_size_bytes: u64,
) -> Result<PartitionLayout, InsufficientSpace> {
    let keys_start_bytes = align_up(p2_end_bytes, alignment);
    let keys_size_bytes = align_up(F2FS_PARTITION_SIZE, alignment);
    let keys_end_bytes = keys_start_bytes + keys_size_bytes;

    let data_start_bytes = keys_end_bytes;
    let data_size_bytes = align_up(F2FS_PARTITION_SIZE, alignment);
    let data_end_bytes = data_start_bytes + data_size_bytes;

    if data_end_bytes > disk_size_bytes {
        return Err(InsufficientSpace {
            need_mb: data_end_bytes / (1024 * 1024),
            have_mb: disk_size_bytes / (1024 * 1024),
        });
    }

    Ok(PartitionLayout {
        keys_start_sector: keys_start_bytes / SECTOR_SIZE,
        keys_size_sectors: keys_size_bytes / SECTOR_SIZE,
        data_start_sector: data_start_bytes / SECTOR_SIZE,
        data_size_sectors: data_size_bytes / SECTOR_SIZE,
    })
}

/// Generate an sfdisk `--append` script for the given partition layout.
///
/// Produces two lines that create Linux (type 83) partitions for keys and data.
pub fn generate_sfdisk_script(layout: &PartitionLayout) -> String {
    format!(
        "start={}, size={}, type=83\nstart={}, size={}, type=83\n",
        layout.keys_start_sector,
        layout.keys_size_sectors,
        layout.data_start_sector,
        layout.data_size_sectors
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, MIN_ALIGNMENT), 0);
        assert_eq!(align_up(1, MIN_ALIGNMENT), MIN_ALIGNMENT);
        assert_eq!(align_up(MIN_ALIGNMENT, MIN_ALIGNMENT), MIN_ALIGNMENT);
        assert_eq!(
            align_up(MIN_ALIGNMENT + 1, MIN_ALIGNMENT),
            2 * MIN_ALIGNMENT
        );
    }

    #[test]
    fn test_calculate_partition_layout() {
        // p2 ends at sector 532480 + 4194304 = 4726784, byte offset = 4726784 * 512
        let p2_end_bytes = (532_480 + 4_194_304) * SECTOR_SIZE;
        let disk_size_bytes: u64 = 62_521_344 * SECTOR_SIZE; // ~32GB

        let layout =
            calculate_partition_layout(p2_end_bytes, MIN_ALIGNMENT, disk_size_bytes).unwrap();

        let expected_keys_start = align_up(p2_end_bytes, MIN_ALIGNMENT) / SECTOR_SIZE;
        assert_eq!(layout.keys_start_sector, expected_keys_start);
        assert_eq!(layout.keys_size_sectors, F2FS_PARTITION_SIZE / SECTOR_SIZE);
        assert_eq!(
            layout.data_start_sector,
            layout.keys_start_sector + layout.keys_size_sectors
        );
        assert_eq!(layout.data_size_sectors, F2FS_PARTITION_SIZE / SECTOR_SIZE);
    }

    #[test]
    fn test_calculate_partition_layout_insufficient_space() {
        let p2_end_bytes = (24_576 + 131_072) * SECTOR_SIZE;
        let disk_size_bytes = 100 * 1024 * 1024; // 100MB

        let err =
            calculate_partition_layout(p2_end_bytes, MIN_ALIGNMENT, disk_size_bytes).unwrap_err();
        assert!(err.to_string().contains("Insufficient disk space"));
    }

    #[test]
    fn test_generate_sfdisk_script() {
        let layout = PartitionLayout {
            keys_start_sector: 4751360,
            keys_size_sectors: 131072,
            data_start_sector: 4882432,
            data_size_sectors: 131072,
        };

        let script = generate_sfdisk_script(&layout);
        assert_eq!(
            script,
            "start=4751360, size=131072, type=83\nstart=4882432, size=131072, type=83\n"
        );
    }
}
