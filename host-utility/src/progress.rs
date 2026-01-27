// Progress tracking module for concurrent operations
//
// This module provides progress tracking functionality with visual indicators
// for both concurrent and sequential operations.

use indicatif::{ProgressBar, ProgressStyle};
use std::sync::mpsc;
use std::thread::JoinHandle;

use crate::constants::ORANGE_256;

/// Events sent by status checks to update progress display
pub enum CheckEvent {
    /// Check has started running - display its name
    Started(&'static str),
    /// Check has completed - remove from active set and increment progress
    Completed(&'static str),
}

/// Create an orange-themed spinner with a message
///
/// Returns a `ProgressBar` configured as a spinner with consistent styling.
/// The spinner auto-ticks every 80ms. Call `.finish_and_clear()` when done.
pub fn create_spinner(message: &str) -> ProgressBar {
    use std::time::Duration;

    let spinner = ProgressBar::new_spinner();
    let template = format!("  {{spinner:.{ORANGE_256}}} {message}");
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template(&template)
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

/// Create a progress tracker for concurrent operations
///
/// Returns a sender for progress updates and a join handle for the progress task.
/// Tracks active checks and displays the most recently started one that's still running.
pub fn create_concurrent_progress(total: usize) -> (mpsc::Sender<CheckEvent>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<CheckEvent>();

    // Create progress bar with indicatif
    let pb = ProgressBar::new(total as u64);

    // Build template with orange color (xterm-256 color 214)
    // Compact format: more room for task names, title shown at end
    let template = format!(
        "🔐 [{{pos}}/{{len}}] {{msg:<20}} {{spinner:.{ORANGE_256}}} [{{bar:10.{ORANGE_256}}}] {{percent}}%"
    );

    pb.set_style(
        ProgressStyle::default_spinner()
            .template(&template)
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "])
            .progress_chars("█░ "),
    );

    let handle = std::thread::spawn(move || {
        let mut completed = 0;
        let mut active_checks: Vec<&'static str> = Vec::new();
        let sleep_duration = std::time::Duration::from_millis(80);

        loop {
            // Sleep for a short duration to provide smooth animation
            std::thread::sleep(sleep_duration);

            // Process all pending events (non-blocking)
            loop {
                match rx.try_recv() {
                    Ok(CheckEvent::Started(name)) => {
                        active_checks.push(name);
                        pb.set_message(name);
                    }
                    Ok(CheckEvent::Completed(name)) => {
                        completed += 1;
                        pb.set_position(completed);
                        // Remove completed check from active set
                        if let Some(pos) = active_checks.iter().position(|&n| n == name) {
                            active_checks.remove(pos);
                        }
                        // Show next most recent active check (or empty if none)
                        if let Some(&current) = active_checks.last() {
                            pb.set_message(current);
                        } else {
                            pb.set_message("");
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // Channel closed - finish and clear
                        pb.finish_and_clear();
                        return;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        // No more updates, break inner loop
                        break;
                    }
                }
            }

            // Always tick to update spinner animation
            pb.tick();
        }
    });

    (tx, handle)
}
