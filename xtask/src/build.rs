use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::process::{Command, Stdio};

use crate::utils::{check_command, clear_host_compiler_flags, set_arm_rustflags};

const TARGET: &str = "aarch64-unknown-linux-gnu";
const SIGNER_PACKAGE: &str = "russignol-signer";

/// Build the `RPi` signer binary for ARM64
pub fn build_rpi_signer(dev: bool) -> Result<()> {
    let mode_desc = if dev {
        "DEBUG"
    } else {
        "RELEASE (speed optimized)"
    };
    println!(
        "{}",
        format!("Building RPi signer for ARM64 ({mode_desc})...").cyan()
    );

    // Check prerequisites
    check_command(
        "aarch64-linux-gnu-gcc",
        "Install with: sudo apt-get install gcc-aarch64-linux-gnu",
    )?;

    // Ensure rust target is installed
    if !is_target_installed(TARGET)? {
        println!("Installing Rust target {}...", TARGET.yellow());
        install_target(TARGET)?;
    }

    // Clear host compiler flags and set ARM-specific flags
    println!("  Configuring build environment...");
    clear_host_compiler_flags();
    set_arm_rustflags();

    // Build signer package
    let mut cargo_args = vec!["build", "--package", SIGNER_PACKAGE, "--target", TARGET];

    if !dev {
        cargo_args.push("--release");
    }

    println!("  Running: cargo {}", cargo_args.join(" "));

    let status = Command::new("cargo")
        .args(&cargo_args)
        .status()
        .context("Failed to execute cargo build")?;

    if !status.success() {
        bail!("RPi build failed");
    }

    // Show build results
    let binary_path = get_signer_binary_path(dev)?;
    println!("\n{}", "=== Build Complete ===".green().bold());

    if let Ok(metadata) = std::fs::metadata(&binary_path) {
        let size_kb = metadata.len() / 1024;
        println!("  Signer: {} ({} KB)", binary_path.display(), size_kb);
    }

    println!("{}", "✓ RPi signer built".green());

    // Clear ARM-specific RUSTFLAGS so they don't affect subsequent builds
    unsafe {
        std::env::remove_var("RUSTFLAGS");
    }

    Ok(())
}

/// Get the path to the built signer binary
pub fn get_signer_binary_path(dev: bool) -> Result<std::path::PathBuf> {
    get_binary_path(SIGNER_PACKAGE, dev, "rpi-signer")
}

/// Get the path to a built ARM64 binary
fn get_binary_path(package: &str, dev: bool, build_cmd: &str) -> Result<std::path::PathBuf> {
    let profile = if dev { "debug" } else { "release" };
    let path = std::path::PathBuf::from(format!("target/{TARGET}/{profile}/{package}"));

    if !path.exists() {
        bail!(
            "Binary {} not found at {}. Build it first with: cargo xtask {}{}",
            package,
            path.display(),
            build_cmd,
            if dev { " --dev" } else { "" }
        );
    }

    Ok(path)
}

/// Check if a Rust target is installed
fn is_target_installed(target: &str) -> Result<bool> {
    let output = Command::new("rustup")
        .args(["target", "list"])
        .stdout(Stdio::piped())
        .output()
        .context("Failed to run rustup")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .any(|line| line.contains(target) && line.contains("installed")))
}

/// Install a Rust target
fn install_target(target: &str) -> Result<()> {
    let status = Command::new("rustup")
        .args(["target", "add", target])
        .status()
        .context("Failed to run rustup target add")?;

    if !status.success() {
        bail!("Failed to install target {target}");
    }

    println!("  {} Target {} installed", "✓".green(), target);
    Ok(())
}
