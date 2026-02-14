use std::time::{Duration, Instant};

/// Detects rapid consecutive taps for triggering actions (e.g., shutdown).
///
/// Each tap must arrive within `max_gap` of the previous one. When `threshold`
/// consecutive rapid taps accumulate, the counter triggers once and ignores
/// further taps until `reset()` is called.
pub struct TapCounter {
    last_tap: Option<Instant>,
    count: usize,
    threshold: usize,
    max_gap: Duration,
    triggered: bool,
}

impl TapCounter {
    pub fn max_gap(&self) -> Duration {
        self.max_gap
    }

    pub fn new(threshold: usize, max_gap: Duration) -> Self {
        Self {
            last_tap: None,
            count: 0,
            threshold,
            max_gap,
            triggered: false,
        }
    }

    /// Record a tap at the given instant. Returns `true` if the threshold was
    /// just reached (fires only once until `reset()` is called).
    pub fn record_tap(&mut self, now: Instant) -> bool {
        if self.triggered {
            return false;
        }

        if self
            .last_tap
            .is_some_and(|last| now.duration_since(last) <= self.max_gap)
        {
            self.count += 1;
        } else {
            self.count = 1;
        }
        self.last_tap = Some(now);

        if self.count >= self.threshold {
            self.triggered = true;
            return true;
        }

        false
    }

    /// Returns `true` if the last tap was within `max_gap` of `now`.
    pub fn has_recent_taps(&self, now: Instant) -> bool {
        self.last_tap
            .is_some_and(|last| now.duration_since(last) <= self.max_gap)
    }

    /// Clear all state so the counter can trigger again.
    pub fn reset(&mut self) {
        self.last_tap = None;
        self.count = 0;
        self.triggered = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Instant {
        Instant::now()
    }

    #[test]
    fn below_threshold_does_not_trigger() {
        let mut counter = TapCounter::new(5, Duration::from_millis(200));
        let t = base();

        for i in 0..4 {
            assert!(
                !counter.record_tap(t + Duration::from_millis(i * 100)),
                "should not trigger on tap {i}"
            );
        }
    }

    #[test]
    fn exactly_threshold_consecutive_rapid_taps_triggers() {
        let mut counter = TapCounter::new(5, Duration::from_millis(200));
        let t = base();

        for i in 0..4 {
            assert!(!counter.record_tap(t + Duration::from_millis(i * 100)));
        }
        assert!(counter.record_tap(t + Duration::from_millis(400)));
    }

    #[test]
    fn gap_exceeding_max_resets_count() {
        let mut counter = TapCounter::new(5, Duration::from_millis(200));
        let t = base();

        // 3 rapid taps
        for i in 0..3 {
            counter.record_tap(t + Duration::from_millis(i * 100));
        }

        // Gap too large — resets count to 1
        let late = t + Duration::from_millis(500);
        assert!(!counter.record_tap(late));

        // Only 1 tap in current streak, need 4 more
        assert!(!counter.record_tap(late + Duration::from_millis(100)));
    }

    #[test]
    fn reset_clears_all_state() {
        let mut counter = TapCounter::new(3, Duration::from_millis(200));
        let t = base();

        // Trigger
        counter.record_tap(t);
        counter.record_tap(t + Duration::from_millis(100));
        assert!(counter.record_tap(t + Duration::from_millis(200)));

        // Reset and verify we can trigger again
        counter.reset();

        let t2 = t + Duration::from_secs(1);
        counter.record_tap(t2);
        counter.record_tap(t2 + Duration::from_millis(100));
        assert!(counter.record_tap(t2 + Duration::from_millis(200)));
    }

    #[test]
    fn has_recent_taps_within_max_gap() {
        let mut counter = TapCounter::new(5, Duration::from_millis(200));
        let t = base();
        counter.record_tap(t);
        assert!(counter.has_recent_taps(t + Duration::from_millis(150)));
    }

    #[test]
    fn has_recent_taps_outside_max_gap() {
        let mut counter = TapCounter::new(5, Duration::from_millis(200));
        let t = base();
        counter.record_tap(t);
        assert!(!counter.has_recent_taps(t + Duration::from_millis(300)));
    }

    #[test]
    fn has_recent_taps_empty() {
        let counter = TapCounter::new(5, Duration::from_millis(200));
        assert!(!counter.has_recent_taps(base()));
    }

    #[test]
    fn no_retrigger_until_reset() {
        let mut counter = TapCounter::new(3, Duration::from_millis(200));
        let t = base();

        counter.record_tap(t);
        counter.record_tap(t + Duration::from_millis(100));
        assert!(counter.record_tap(t + Duration::from_millis(200)));

        // Additional taps should not re-trigger
        for i in 3..10 {
            assert!(
                !counter.record_tap(t + Duration::from_millis(i * 100)),
                "should not re-trigger on tap {i}"
            );
        }
    }
}
