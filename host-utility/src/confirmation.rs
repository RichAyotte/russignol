use anyhow::Result;
use colored::Colorize;
use inquire::{Confirm, ui::RenderConfig, ui::Styled};

use crate::constants::ORANGE_RGB;
use crate::utils::print_subtitle_bar;

/// Represents a single mutation that will be performed
pub struct MutationAction {
    pub description: String,
    pub detailed_info: Option<String>, // Only shown in verbose mode
}

/// Represents all mutations for a phase
pub struct PhaseMutations {
    pub phase_name: String,
    pub actions: Vec<MutationAction>,
}

/// Configuration for confirmation behavior
#[derive(Clone)]
pub struct ConfirmationConfig {
    pub auto_confirm: bool, // --yes flag
    pub dry_run: bool,
    pub verbose: bool,
}

/// Result of a confirmation prompt
pub enum ConfirmationResult {
    Confirmed,
    Skipped,
    Cancelled,
}

/// Main entry point for phase confirmations
pub fn confirm_phase_mutations(
    mutations: &PhaseMutations,
    config: &ConfirmationConfig,
) -> ConfirmationResult {
    // In dry-run mode, always proceed without confirmation
    if config.dry_run {
        return ConfirmationResult::Confirmed;
    }

    // Auto-confirm mode (--yes flag)
    if config.auto_confirm {
        if config.verbose {
            println!();
            display_mutations(mutations, config);
            println!("{} {}", "✓".green(), "Auto-confirmed".dimmed());
        }
        return ConfirmationResult::Confirmed;
    }

    // Interactive confirmation
    println!();
    let subtitle = format!(
        "The following changes will be made to {}:",
        mutations.phase_name
    );
    print_subtitle_bar(&subtitle);

    display_mutations(mutations, config);

    println!();

    // Use inquire for consistent UX with existing code
    let render_config = RenderConfig {
        prompt_prefix: Styled::new("?").with_fg(ORANGE_RGB),
        answer: inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB),
        help_message: inquire::ui::StyleSheet::new().with_fg(ORANGE_RGB),
        ..Default::default()
    };

    let confirm = Confirm::new("Proceed with these changes?")
        .with_default(true)
        .with_help_message("y = yes, n = skip this phase")
        .with_render_config(render_config)
        .prompt();

    match confirm {
        Ok(true) => ConfirmationResult::Confirmed,
        Ok(false) => {
            println!("{} {} skipped", "⚠".yellow(), mutations.phase_name);
            ConfirmationResult::Skipped
        }
        Err(_) => {
            // User pressed Ctrl+C
            ConfirmationResult::Cancelled
        }
    }
}

/// Display the list of mutations (summary or detailed based on verbose flag)
fn display_mutations(mutations: &PhaseMutations, config: &ConfirmationConfig) {
    for action in &mutations.actions {
        println!("  • {}", action.description);

        if config.verbose
            && let Some(detail) = &action.detailed_info
        {
            println!("    {}", detail.dimmed());
        }
    }
}

/// Check if we're in a non-interactive environment
pub fn is_non_interactive() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Validate that the environment is suitable for running the setup
pub fn validate_environment(config: &ConfirmationConfig) -> Result<()> {
    if !config.auto_confirm && !config.dry_run && is_non_interactive() {
        anyhow::bail!(
            "Running in non-interactive environment (no TTY detected). \
             Use --yes to auto-confirm or --dry-run to simulate."
        );
    }
    Ok(())
}
