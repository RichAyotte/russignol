use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SYSFS_POLICY: &str = "/sys/devices/system/cpu/cpufreq/policy0";

struct CpuBoostInner {
    setspeed_path: PathBuf,
    /// Sysfs setspeed payload for min frequency (ASCII kHz digits).
    min_freq: Box<[u8]>,
    /// Sysfs setspeed payload for max frequency (ASCII kHz digits).
    max_freq: Box<[u8]>,
    /// Nested boost sessions so one connection's restore cannot drop frequency
    /// while another connection is still signing.
    active: Mutex<u32>,
}

/// CPU frequency controller for the userspace governor.
///
/// Brackets CPU-intensive work (BLS signing, scrypt) with `boost()` and
/// `restore()` calls. Designed for the `RPi` Zero 2W where signing takes
/// ~5ms per operation.
///
/// When idle (99.9% of the time), the CPU runs at minimum frequency (~600 MHz).
/// Callers set max frequency (~1000 MHz) before work and restore min after.
#[derive(Clone)]
pub struct CpuBoost(Arc<CpuBoostInner>);

impl CpuBoost {
    /// Initialize CPU frequency control.
    ///
    /// The init scripts chown `scaling_setspeed` to russignol before starting
    /// the signer, so the file is already writable.
    pub fn new() -> io::Result<Self> {
        Self::init(Path::new(SYSFS_POLICY))
    }

    fn init(policy_path: &Path) -> io::Result<Self> {
        let min_freq: Box<[u8]> = fs::read_to_string(policy_path.join("cpuinfo_min_freq"))?
            .trim()
            .as_bytes()
            .into();
        let max_freq: Box<[u8]> = fs::read_to_string(policy_path.join("cpuinfo_max_freq"))?
            .trim()
            .as_bytes()
            .into();
        let setspeed_path = policy_path.join("scaling_setspeed");

        log::info!(
            "CPU freq control: min={} max={} kHz",
            String::from_utf8_lossy(&min_freq),
            String::from_utf8_lossy(&max_freq)
        );

        // Start at minimum frequency
        fs::write(&setspeed_path, &min_freq)?;

        Ok(Self(Arc::new(CpuBoostInner {
            setspeed_path,
            min_freq,
            max_freq,
            active: Mutex::new(0),
        })))
    }

    /// Set CPU to maximum frequency before CPU-intensive work.
    pub fn boost(&self) {
        // Hold the lock across the sysfs write so a concurrent restore cannot
        // commit a stale min after this 0→1 raise (last writer would win).
        let mut active = self.0.active.lock().unwrap();
        *active = active.saturating_add(1);
        if *active == 1
            && let Err(e) = fs::write(&self.0.setspeed_path, &self.0.max_freq)
        {
            log::warn!("Failed to set CPU max freq: {e}");
        }
    }

    /// Return CPU to minimum frequency after the last nested boost ends.
    pub fn restore(&self) {
        // Hold the lock across the sysfs write so a concurrent boost cannot
        // raise max and then be overwritten by this 1→0 lower.
        let mut active = self.0.active.lock().unwrap();
        if *active == 0 {
            return;
        }
        *active -= 1;
        if *active == 0
            && let Err(e) = fs::write(&self.0.setspeed_path, &self.0.min_freq)
        {
            log::warn!("Failed to set CPU min freq: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mock_sysfs(dir: &Path) {
        fs::write(dir.join("cpuinfo_min_freq"), "600000\n").unwrap();
        fs::write(dir.join("cpuinfo_max_freq"), "1000000\n").unwrap();
        fs::write(dir.join("scaling_setspeed"), "").unwrap();
    }

    #[test]
    fn initial_freq_is_min() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let _boost = CpuBoost::init(dir.path()).unwrap();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }

    #[test]
    fn boost_sets_max_freq() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let cpu = CpuBoost::init(dir.path()).unwrap();
        cpu.boost();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "1000000");
    }

    #[test]
    fn restore_sets_min_freq() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let cpu = CpuBoost::init(dir.path()).unwrap();
        cpu.boost();
        cpu.restore();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }

    #[test]
    fn nested_boost_keeps_max_until_last_restore() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let cpu = CpuBoost::init(dir.path()).unwrap();
        cpu.boost();
        cpu.boost();
        cpu.restore();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "1000000");

        cpu.restore();
        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }

    #[test]
    fn restore_without_boost_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        create_mock_sysfs(dir.path());

        let cpu = CpuBoost::init(dir.path()).unwrap();
        cpu.restore();

        let freq = fs::read_to_string(dir.path().join("scaling_setspeed")).unwrap();
        assert_eq!(freq, "600000");
    }
}
