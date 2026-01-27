use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::utils::run_cmd_in_dir;

/// Clean build artifacts
pub fn clean(clean_buildroot: bool, deep: bool) -> Result<()> {
    println!("{}", "Cleaning build artifacts...".cyan());

    // Clean Cargo artifacts
    println!("  Cleaning Cargo artifacts...");
    run_cmd_in_dir(".", "cargo", &["clean"], "Cargo clean failed")?;
    println!("    {} Cargo artifacts cleaned", "✓".green());

    // Clean parallel build directories
    for dir_name in ["target-x86_64", "target-aarch64"] {
        let dir = Path::new(dir_name);
        if dir.exists() {
            std::fs::remove_dir_all(dir).with_context(|| format!("Failed to remove {dir_name}"))?;
            println!("    {} {} removed", "✓".green(), dir_name);
        }
    }

    // Clean overlay binary
    let overlay_binary =
        Path::new("rpi-signer/buildroot-external/rootfs-overlay-common/bin/russignol-signer");
    if overlay_binary.exists() {
        std::fs::remove_file(overlay_binary).context("Failed to remove overlay binary")?;
        println!("    {} overlay binary removed", "✓".green());
    }

    // Clean buildroot if requested
    if clean_buildroot {
        let buildroot_dir = Path::new("buildroot");
        if buildroot_dir.exists() {
            if deep {
                println!(
                    "  {} Cleaning buildroot (deep clean - removes downloads and ccache)...",
                    "⚠".yellow()
                );
                run_cmd_in_dir(
                    "buildroot",
                    "make",
                    &["distclean"],
                    "Buildroot distclean failed",
                )?;
                println!("    {} Buildroot deep cleaned", "✓".green());
            } else {
                println!("  Cleaning buildroot output...");
                run_cmd_in_dir("buildroot", "make", &["clean"], "Buildroot clean failed")?;
                println!("    {} Buildroot output cleaned", "✓".green());
            }

            // Remove state file
            let state_file = Path::new("rpi-signer/buildroot-external/.last_build_config");
            if state_file.exists() {
                std::fs::remove_file(state_file)
                    .context("Failed to remove buildroot state file")?;
                println!("    {} Buildroot state file removed", "✓".green());
            }
        } else {
            println!("  {} Buildroot directory not found, skipping", "⚠".yellow());
        }
    }

    println!();
    println!("{}", "✓ Clean complete".green());

    if !clean_buildroot {
        println!();
        println!(
            "Tip: Use {} to also clean buildroot output",
            "--buildroot".cyan()
        );
        println!(
            "     Use {} for deep clean (removes buildroot downloads and ccache)",
            "--buildroot --deep".cyan()
        );
    }

    Ok(())
}
