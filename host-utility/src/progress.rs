// Progress tracking module for sequential operations
//
// This module provides progress tracking functionality with visual indicators.

use indicatif::{ProgressBar, ProgressStyle};

use crate::constants::ORANGE_256;

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
