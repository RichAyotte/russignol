use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SYSFS_LED: &str = "/sys/class/leds/ACT";
const MIN_ON_DURATION: Duration = Duration::from_millis(200);

struct LedState {
    /// Nested connection count so overlapping sessions share one lit period.
    active: u32,
    /// Bumped on every 0→1 transition; deferred offs only write 0 if unchanged.
    generation: u64,
    /// Instant of the current 0→1 transition (for min-on hold).
    on_at: Option<Instant>,
}

struct LedInner {
    brightness_path: PathBuf,
    state: Mutex<LedState>,
}

/// Activity LED controller.
///
/// Turns the LED on when a signer connection opens and off when it closes.
/// The min-on hold is aesthetic only and never blocks the caller: a sleep in
/// `off()` holds connection teardown for its whole duration, and the baker's
/// next sign connection opens behind that teardown, so ~200ms of it lands in
/// the pre→att forge gap.
#[derive(Clone)]
pub struct Led(Arc<LedInner>);

impl Led {
    /// Initialize LED control, starting in the off state.
    ///
    /// The init scripts chown `brightness` to russignol before starting
    /// the signer, so the file is already writable.
    pub fn new() -> io::Result<Self> {
        Self::init(Path::new(SYSFS_LED))
    }

    fn init(path: &Path) -> io::Result<Self> {
        let brightness_path = path.join("brightness");
        fs::write(&brightness_path, "0")?;
        log::info!("LED control initialized");
        Ok(Self(Arc::new(LedInner {
            brightness_path,
            state: Mutex::new(LedState {
                active: 0,
                generation: 0,
                on_at: None,
            }),
        })))
    }

    /// Turn the LED on (or nest another active session).
    pub fn on(&self) {
        let mut state = self.0.state.lock().unwrap();
        state.active = state.active.saturating_add(1);
        if state.active != 1 {
            return;
        }
        state.generation = state.generation.wrapping_add(1);
        state.on_at = Some(Instant::now());
        // Brightness write stays under the lock so it cannot interleave with a
        // deferred off()'s generation check + write "0".
        if let Err(e) = fs::write(&self.0.brightness_path, "1") {
            log::warn!("Failed to turn LED on: {e}");
        }
    }

    /// Schedule LED off after the min-on hold. Returns immediately.
    ///
    /// Nested `on()`/`off()` pairs keep the LED lit until the last session ends.
    /// A deferred write is cancelled if a newer session lights the LED again.
    pub fn off(&self) {
        let deferred = {
            let mut state = self.0.state.lock().unwrap();
            if state.active == 0 {
                return;
            }
            state.active -= 1;
            if state.active > 0 {
                return;
            }
            let on_at = state.on_at.take().unwrap_or_else(Instant::now);
            let remaining = MIN_ON_DURATION.saturating_sub(on_at.elapsed());
            Some((state.generation, remaining))
        };

        let Some((generation, remaining)) = deferred else {
            return;
        };

        let led = Arc::clone(&self.0);
        thread::spawn(move || {
            if !remaining.is_zero() {
                thread::sleep(remaining);
            }
            // Hold the state lock across the brightness write so a concurrent
            // on() cannot interleave a "1" between the generation check and "0".
            let state = led.state.lock().unwrap();
            if state.active != 0 || state.generation != generation {
                return;
            }
            if let Err(e) = fs::write(&led.brightness_path, "0") {
                log::warn!("Failed to turn LED off: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    fn mock_led() -> (tempfile::TempDir, Led) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("brightness"), "").unwrap();
        let led = Led::init(dir.path()).unwrap();
        (dir, led)
    }

    fn brightness(dir: &tempfile::TempDir) -> String {
        fs::read_to_string(dir.path().join("brightness")).unwrap()
    }

    /// Long enough that only a write which never lands can miss it.
    const SETTLE_TIMEOUT: Duration = Duration::from_secs(5);

    /// Read `brightness` until it reads `want`, and answer with what it read
    /// and how long after `since` that was.
    ///
    /// Waited for rather than slept through: the deferred write lands a
    /// scheduled thread's wake-up after the hold expires, and how long that
    /// takes is the machine's rather than this crate's. A fixed margin over
    /// the hold is one a loaded machine loses, which turns this red with no
    /// defect behind it.
    fn settles_at(dir: &tempfile::TempDir, want: &str, since: Instant) -> (String, Duration) {
        let deadline = Instant::now() + SETTLE_TIMEOUT;
        loop {
            let read = brightness(dir);
            if read == want || Instant::now() >= deadline {
                return (read, since.elapsed());
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn test_initial_state_is_off() {
        let (dir, _led) = mock_led();
        assert_eq!(brightness(&dir), "0");
    }

    #[test]
    fn test_on_writes_one() {
        let (dir, led) = mock_led();
        led.on();
        assert_eq!(brightness(&dir), "1");
    }

    #[test]
    fn test_off_writes_zero_after_min_on() {
        let (dir, led) = mock_led();
        let lit = Instant::now();
        led.on();
        led.off();
        // Min-on hold is deferred — still lit immediately after off().
        assert_eq!(brightness(&dir), "1");

        let (settled, after) = settles_at(&dir, "0", lit);

        assert_eq!(settled, "0", "the deferred write never landed");
        assert!(
            after >= MIN_ON_DURATION,
            "the LED went dark {after:?} after it was lit, inside the {MIN_ON_DURATION:?} hold"
        );
    }

    #[test]
    fn test_off_returns_without_waiting_for_min_on() {
        let (_dir, led) = mock_led();
        led.on();
        let start = Instant::now();
        led.off();
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "off() blocked the caller for {:?}",
            start.elapsed()
        );
    }

    /// Connection path must not serialize the next `on()` behind `MIN_ON_DURATION`.
    #[test]
    fn test_on_not_blocked_by_concurrent_off_min_on_hold() {
        let (_dir, led) = mock_led();
        led.on();

        let barrier = Arc::new(Barrier::new(2));
        let led_on = led.clone();
        let barrier_on = Arc::clone(&barrier);
        let on_latency = thread::spawn(move || {
            barrier_on.wait();
            let start = Instant::now();
            led_on.on();
            start.elapsed()
        });

        // Released after off() returns, so on() provably runs against a hold
        // already scheduled. Releasing it first leaves which of the two goes
        // in front to the scheduler, and the order that proves nothing is the
        // one that passes.
        led.off();
        barrier.wait();
        let elapsed = on_latency.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(50),
            "on() waited {elapsed:?} behind off()'s min-on hold (limit 50ms)"
        );
    }

    #[test]
    fn test_re_on_cancels_deferred_off() {
        let (dir, led) = mock_led();
        led.on();
        led.off();
        led.on();
        thread::sleep(MIN_ON_DURATION + Duration::from_millis(50));
        assert_eq!(
            brightness(&dir),
            "1",
            "deferred off from an earlier session must not darken a live session"
        );
        led.off();

        // The LED has been lit past MIN_ON_DURATION by now, so this session's
        // write is due immediately and what is left to establish is that it
        // lands.
        let (settled, _) = settles_at(&dir, "0", Instant::now());

        assert_eq!(settled, "0", "the deferred write never landed");
    }

    #[test]
    fn test_nested_on_keeps_led_lit_until_last_off() {
        let (dir, led) = mock_led();
        led.on();
        led.on();
        led.off();
        // Slept through rather than waited for: what is asserted is that no
        // write landed, which only time can establish and which a longer wait
        // can only make surer.
        thread::sleep(MIN_ON_DURATION + Duration::from_millis(50));
        assert_eq!(brightness(&dir), "1");

        led.off();

        let (settled, _) = settles_at(&dir, "0", Instant::now());

        assert_eq!(settled, "0", "the deferred write never landed");
    }
}
