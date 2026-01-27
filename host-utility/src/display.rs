use indicatif::{ProgressBar, ProgressStyle};

use crate::constants::ORANGE_256;
use crate::utils::print_title_bar;

pub struct SetupDisplay {
    pb: ProgressBar,
}

impl SetupDisplay {
    pub fn new(total_steps: usize) -> Self {
        // Print title and separator
        print_title_bar("🔐 Russignol Hardware Signer Setup");
        println!();

        // Create visible progress bar (stays at bottom of terminal)
        let pb = ProgressBar::new(total_steps as u64);
        let template = format!(
            "{{spinner:.{ORANGE_256}}} [{{pos}}/{{len}}] {{msg}} [{{bar:20.{ORANGE_256}}}] {{percent}}%"
        );
        pb.set_style(
            ProgressStyle::default_bar()
                .template(&template)
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "])
                .progress_chars("█░ "),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        Self { pb }
    }

    pub fn update(&self, step: usize, description: &str) {
        self.pb.set_position(step as u64);
        self.pb.set_message(description.to_string());
    }

    pub fn suspend_for_prompt<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Temporarily hide progress bar during prompts, then restore it
        self.pb.suspend(f)
    }

    pub fn finish(&self) {
        self.pb.finish_and_clear();
    }
}
