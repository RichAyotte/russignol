use anyhow::{Context, Result};
use std::path::PathBuf;

/// Create a timestamped backup directory using XDG standards
pub fn create_backup_dir() -> Result<PathBuf> {
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");

    // Use XDG_DATA_HOME if set, otherwise use ~/.local/share
    let data_home = std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").expect("HOME environment variable not set");
        format!("{home}/.local/share")
    });

    let backup_dir = PathBuf::from(data_home)
        .join("russignol")
        .join("backups")
        .join(timestamp.to_string());

    std::fs::create_dir_all(&backup_dir).with_context(|| {
        format!(
            "Failed to create backup directory: {}",
            backup_dir.display()
        )
    })?;

    Ok(backup_dir)
}

/// Backup a file if it exists (with sudo fallback for root-owned files)
pub fn backup_file_if_exists(
    source: &std::path::Path,
    backup_dir: &std::path::Path,
    filename: &str,
    verbose: bool,
) -> Result<bool> {
    if !source.exists() {
        return Ok(false);
    }

    let backup_path = backup_dir.join(filename);

    // Try regular copy first
    let result = std::fs::copy(source, &backup_path);

    match result {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Use sudo for root-owned files
            crate::utils::sudo_command_success(
                "cp",
                &[source.to_str().unwrap(), backup_path.to_str().unwrap()],
            )
            .with_context(|| {
                format!(
                    "Failed to backup {} to {}",
                    source.display(),
                    backup_path.display()
                )
            })?;
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "Failed to copy {} to {}",
                    source.display(),
                    backup_path.display()
                )
            });
        }
    }

    if verbose {
        crate::utils::info(&format!(
            "Backed up {} to {}",
            source.display(),
            backup_path.display()
        ));
    }

    Ok(true)
}
