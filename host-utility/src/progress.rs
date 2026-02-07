// Progress tracking module for sequential operations
//
// This module provides progress tracking functionality with visual indicators.

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::constants::ORANGE_256;
use crate::utils;

/// Create an orange-themed spinner with a message
///
/// Returns a `ProgressBar` configured as a spinner with consistent styling.
/// The spinner auto-ticks every 80ms. Call `.finish_and_clear()` when done.
pub fn create_spinner(message: &str) -> ProgressBar {
    use std::time::Duration;

    let spinner = ProgressBar::new_spinner();
    let template = format!("  {{spinner:.{ORANGE_256}}} {{msg}}");
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template(&template)
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

/// Run a single setup step with spinner and success indicator
///
/// Shows `  ⠋ description (command)` while executing `f`,
/// then replaces with `  ✓ description (command)` on success.
pub fn run_step<F, R>(description: &str, command: &str, f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let label = format!("{description} ({command})");
    let spinner = create_spinner(&label);
    match f() {
        Ok(value) => {
            spinner.finish_and_clear();
            utils::success(&label);
            Ok(value)
        }
        Err(e) => {
            spinner.finish_and_clear();
            Err(e)
        }
    }
}

/// Like [`run_step`] but the closure returns `(R, detail)` where `detail` is
/// appended after the checkmark line: `  ✓ description (command) — detail`
pub fn run_step_detail<F, R>(description: &str, command: &str, f: F) -> Result<R>
where
    F: FnOnce() -> Result<(R, String)>,
{
    let label = format!("{description} ({command})");
    let spinner = create_spinner(&label);
    match f() {
        Ok((value, detail)) => {
            spinner.finish_and_clear();
            utils::success(&format!("{label} — {detail}"));
            Ok(value)
        }
        Err(e) => {
            spinner.finish_and_clear();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_step_propagates_success() {
        let result = run_step("test desc", "test cmd", || Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_run_step_propagates_error() {
        let result: Result<()> = run_step("test desc", "test cmd", || anyhow::bail!("test error"));
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "test error");
    }

    #[test]
    fn test_run_step_detail_propagates_value() {
        let result = run_step_detail("desc", "cmd", || Ok((42, "detail".to_string())));
        assert_eq!(result.unwrap(), 42);
    }
}
