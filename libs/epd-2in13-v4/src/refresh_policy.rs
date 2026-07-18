use crate::display_driver::DisplayMode;

// SSD1680 guidance is a full refresh every ~10 partial updates or every
// 30 minutes to prevent ghosting, but the panel shows no visible ghosting
// after hundreds of consecutive partials. Live pages repaint 1-2×/s while a
// baker signs, the fastest the counter advances (unchanged frames are
// skipped), so 1000 keeps the deferred full within the 30-minute guidance
// at that worst-case rate while making transition flashes rare.
pub const PARTIALS_BETWEEN_FULLS: u16 = 1000;

/// The moment at which a refresh is being considered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshOpportunity {
    /// Repaint of the page already on screen.
    InPlace,
    /// The screen is switching to a different page.
    Transition,
    /// The caller demands a full refresh.
    ForcedFull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshAction {
    Skip,
    Push(DisplayMode),
}

/// The action to apply plus the counter value to store afterwards.
///
/// The caller applies both verbatim; it never re-derives the counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshDecision {
    pub action: RefreshAction,
    pub partials_since_full: u16,
}

pub fn decide(
    frame_changed: bool,
    has_ever_pushed: bool,
    partials_since_full: u16,
    opportunity: RefreshOpportunity,
) -> RefreshDecision {
    let full_due = partials_since_full >= PARTIALS_BETWEEN_FULLS;
    let action = match opportunity {
        RefreshOpportunity::ForcedFull => RefreshAction::Push(DisplayMode::Full),
        _ if !has_ever_pushed => RefreshAction::Push(DisplayMode::Full),
        RefreshOpportunity::Transition if full_due => RefreshAction::Push(DisplayMode::Full),
        _ if !frame_changed => RefreshAction::Skip,
        _ => RefreshAction::Push(DisplayMode::Partial),
    };
    let next_partials_since_full = match action {
        RefreshAction::Push(DisplayMode::Full) => 0,
        RefreshAction::Push(DisplayMode::Partial) => partials_since_full.saturating_add(1),
        RefreshAction::Skip => partials_since_full,
    };
    RefreshDecision {
        action,
        partials_since_full: next_partials_since_full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DisplayMode::{Full, Partial};
    use RefreshAction::{Push, Skip};
    use RefreshOpportunity::{ForcedFull, InPlace, Transition};

    const DUE: u16 = PARTIALS_BETWEEN_FULLS;
    const NOT_DUE: u16 = PARTIALS_BETWEEN_FULLS - 1;

    fn check(
        name: &str,
        frame_changed: bool,
        has_ever_pushed: bool,
        counter: u16,
        opportunity: RefreshOpportunity,
        action: RefreshAction,
        next_counter: u16,
    ) {
        let decision = decide(frame_changed, has_ever_pushed, counter, opportunity);
        assert_eq!(decision.action, action, "{name}: action");
        assert_eq!(
            decision.partials_since_full, next_counter,
            "{name}: counter"
        );
    }

    #[test]
    fn bootstrap_forces_full() {
        check(
            "in-place unchanged",
            false,
            false,
            0,
            InPlace,
            Push(Full),
            0,
        );
        check("in-place changed", true, false, 0, InPlace, Push(Full), 0);
        check(
            "transition unchanged",
            false,
            false,
            0,
            Transition,
            Push(Full),
            0,
        );
        check("forced", false, false, 0, ForcedFull, Push(Full), 0);
    }

    #[test]
    fn unchanged_frames_skip() {
        check(
            "in-place not due",
            false,
            true,
            NOT_DUE,
            InPlace,
            Skip,
            NOT_DUE,
        );
        check("in-place due", false, true, DUE, InPlace, Skip, DUE);
        check(
            "transition not due",
            false,
            true,
            NOT_DUE,
            Transition,
            Skip,
            NOT_DUE,
        );
    }

    #[test]
    fn transition_due_forces_full() {
        check("unchanged", false, true, DUE, Transition, Push(Full), 0);
        check("changed", true, true, DUE, Transition, Push(Full), 0);
    }

    #[test]
    fn changed_frames_push_partial() {
        check(
            "in-place not due",
            true,
            true,
            NOT_DUE,
            InPlace,
            Push(Partial),
            NOT_DUE + 1,
        );
        check(
            "in-place due",
            true,
            true,
            DUE,
            InPlace,
            Push(Partial),
            DUE + 1,
        );
        check(
            "transition not due",
            true,
            true,
            NOT_DUE,
            Transition,
            Push(Partial),
            NOT_DUE + 1,
        );
    }

    #[test]
    fn forced_is_always_full() {
        check(
            "changed not due",
            true,
            true,
            NOT_DUE,
            ForcedFull,
            Push(Full),
            0,
        );
        check("unchanged due", false, true, DUE, ForcedFull, Push(Full), 0);
    }

    #[test]
    fn partial_counter_saturates() {
        check(
            "at max",
            true,
            true,
            u16::MAX,
            InPlace,
            Push(Partial),
            u16::MAX,
        );
    }
}
