use anyhow::{Context, Result};
use colored::Colorize;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::utils;

/// Main entry point for install command
pub fn run_install(backup: bool) -> Result<()> {
    // Get current executable path
    let current_exe =
        std::env::current_exe().context("Failed to determine current executable path")?;

    // Get installation directory
    let install_dir = get_install_dir()?;
    let install_path = install_dir.join("russignol");

    // Create backup if requested and file exists
    if backup && install_path.exists() {
        let backup_path = backup_existing(&install_path)?;
        utils::success(&format!("Created backup: {}", backup_path.display()));
    }

    // Create directory if it doesn't exist
    if !install_dir.exists() {
        std::fs::create_dir_all(&install_dir).with_context(|| {
            format!(
                "Failed to create directory: {}. Check permissions.",
                install_dir.display()
            )
        })?;
    }

    // Copy binary
    copy_binary(&current_exe, &install_path)?;

    // Make executable
    make_executable(&install_path)?;

    // Verify installation
    verify_installation(&install_path)?;

    utils::success(&format!(
        "Installed russignol to {}",
        install_path.display()
    ));

    // Check if in PATH and warn if not
    if !is_in_path(&install_dir) {
        utils::warning("~/.local/bin is not in your PATH.");
        println!();
        utils::info("Add this line to your ~/.bashrc or ~/.zshrc:");
        println!();
        println!("  {}", "export PATH=\"$HOME/.local/bin:$PATH\"".cyan());
        println!();
        utils::info("Then reload your shell: source ~/.bashrc");
        println!();
    }

    Ok(())
}

/// Get installation target directory (~/.local/bin)
fn get_install_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".local/bin"))
}

/// Check if directory is in PATH
fn is_in_path(dir: &Path) -> bool {
    std::env::var("PATH")
        .map(|path| path.split(':').any(|p| Path::new(p) == dir))
        .unwrap_or(false)
}

/// Copy binary to target location
fn copy_binary(source: &Path, dest: &Path) -> Result<()> {
    std::fs::copy(source, dest).with_context(|| {
        format!(
            "Failed to copy binary from {} to {}",
            source.display(),
            dest.display()
        )
    })?;
    Ok(())
}

/// Set executable permissions
fn make_executable(path: &Path) -> Result<()> {
    let mut perms = std::fs::metadata(path)
        .context("Failed to read file permissions")?
        .permissions();

    // Set rwxr-xr-x (0o755)
    perms.set_mode(0o755);

    std::fs::set_permissions(path, perms).context("Failed to set executable permissions")?;

    Ok(())
}

/// Verify installation was successful by running --version
fn verify_installation(path: &Path) -> Result<()> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .context("Failed to run installed binary")?;

    if !output.status.success() {
        anyhow::bail!("Installed binary failed to run");
    }

    Ok(())
}

/// Create backup of existing installation
fn backup_existing(path: &Path) -> Result<PathBuf> {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = path.with_extension(format!("bak.{timestamp}"));

    std::fs::copy(path, &backup_path).context("Failed to create backup")?;

    Ok(backup_path)
}
