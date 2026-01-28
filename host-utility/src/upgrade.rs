use anyhow::{Context, Result, bail};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::constants::{ORANGE, ORANGE_256};
use crate::utils::create_http_agent;
use crate::version;

/// Main entry point for upgrade command
pub fn run_upgrade(check_only: bool, _yes: bool) -> Result<()> {
    let start = std::time::Instant::now();

    // Check for updates
    let update_info = match check_for_updates() {
        Ok(Some(info)) => info,
        Ok(None) => {
            println!(
                "Congrats! You're already on the latest version of Russignol (which is {})",
                format!("v{}", version::current_version()).truecolor(ORANGE.0, ORANGE.1, ORANGE.2)
            );
            return Ok(());
        }
        Err(e) => {
            return Err(e).context("Failed to check for updates");
        }
    };

    // Display update available message
    println!(
        "Russignol {} is out! You're on {}",
        format!("v{}", update_info.version).truecolor(ORANGE.0, ORANGE.1, ORANGE.2),
        format!("v{}", version::current_version()).truecolor(ORANGE.0, ORANGE.1, ORANGE.2)
    );

    if check_only {
        return Ok(());
    }

    // Get architecture and download
    let arch = version::current_arch();
    let temp_file = download_binary(&update_info, arch)?;

    // Verify checksum
    let expected_checksum = &update_info
        .binaries
        .get(arch)
        .context("Architecture not found in version info")?
        .sha256;

    if expected_checksum.is_empty() {
        bail!(
            "Checksum not available for this release. Cannot safely upgrade without verification."
        );
    }
    verify_checksum(temp_file.path(), expected_checksum)?;

    // Replace binary
    replace_binary(&temp_file)?;

    // Success message with elapsed time
    let elapsed = start.elapsed();
    println!("[{:.2}ms] Upgraded.", elapsed.as_secs_f64() * 1000.0);
    println!();
    println!(
        "Welcome to Russignol {}!",
        format!("v{}", update_info.version).truecolor(ORANGE.0, ORANGE.1, ORANGE.2)
    );

    Ok(())
}

/// Check if update is available, returns Some(VersionInfo) if update available
fn check_for_updates() -> Result<Option<version::VersionInfo>> {
    let latest = version::fetch_latest_version()?;

    if version::is_newer(version::current_version(), &latest.version)? {
        Ok(Some(latest))
    } else {
        Ok(None)
    }
}

/// Download binary from website with progress bar and retry logic
fn download_binary(version_info: &version::VersionInfo, arch: &str) -> Result<NamedTempFile> {
    let url = version::get_download_url(version_info, arch)?;
    let binary_info = version_info
        .binaries
        .get(arch)
        .context("Architecture not found")?;

    let agent = create_http_agent(300);

    // Retry logic
    for attempt in 1..=3 {
        match download_with_progress(&agent, &url, binary_info.size_bytes) {
            Ok(file) => return Ok(file),
            Err(e) if attempt < 3 => {
                eprintln!(
                    "{} Download failed (attempt {}/3): {}",
                    "warning:".yellow(),
                    attempt,
                    e
                );
                std::thread::sleep(std::time::Duration::from_secs(2u64.pow(attempt)));
            }
            Err(e) => return Err(e),
        }
    }

    unreachable!()
}

/// Download with progress bar
fn download_with_progress(
    agent: &ureq::Agent,
    url: &str,
    expected_size: u64,
) -> Result<NamedTempFile> {
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("Failed to download from {url}"))?;

    if response.status() != 200 {
        anyhow::bail!("Download failed: HTTP {}", response.status());
    }

    let total_bytes = response
        .headers()
        .get("content-length")
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(expected_size);

    // Create progress bar
    let pb = ProgressBar::new(total_bytes);
    let template = format!(
        "Downloading [{{bar:40.{ORANGE_256}}}] {{percent}}% ({{bytes}}/{{total_bytes}}) {{eta}}"
    );
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&template)
            .unwrap()
            .progress_chars("█░ "),
    );

    // Create temp file
    let mut temp_file = NamedTempFile::new().context("Failed to create temporary file")?;

    // Stream download with buffer
    let mut reader = response.body_mut().as_reader();
    let mut buffer = [0; 8192];

    loop {
        let n = reader
            .read(&mut buffer)
            .context("Failed to read response chunk")?;
        if n == 0 {
            break;
        }
        temp_file
            .write_all(&buffer[..n])
            .context("Failed to write to temporary file")?;
        pb.inc(n as u64);
    }

    pb.finish_and_clear();

    Ok(temp_file)
}

/// Verify downloaded file checksum
fn verify_checksum(file: &Path, expected: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(file).context("Failed to open file for checksum")?;

    std::io::copy(&mut f, &mut hasher).context("Failed to read file for checksum")?;

    let hash = format!("{:x}", hasher.finalize());

    if hash != expected {
        anyhow::bail!("Checksum verification failed!\nExpected: {expected}\nGot:      {hash}");
    }

    Ok(())
}

/// Replace current binary atomically using Bun's strategy
fn replace_binary(temp_file: &NamedTempFile) -> Result<()> {
    let current_path = current_binary_path()?;

    // Check if binary is in a system directory
    if current_path.starts_with("/usr") || current_path.starts_with("/opt") {
        anyhow::bail!(
            "Russignol is installed in a system directory ({}).\n\
             Please reinstall to ~/.local/bin using 'russignol install'.",
            current_path.display()
        );
    }

    // Make temp file executable
    let mut perms = std::fs::metadata(temp_file.path())
        .context("Failed to read temp file permissions")?
        .permissions();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
    }

    std::fs::set_permissions(temp_file.path(), perms)
        .context("Failed to set executable permissions")?;

    // Bun-style replacement strategy:
    // 1. Rename current binary to backup path (frees up the original path)
    // 2. Rename new binary to original path (atomic replacement)
    // 3. Clean up backup on success, or restore on failure

    let backup_path = current_path.with_extension("old");

    // Step 1: Rename current binary out of the way
    // This works even if the binary is currently running (POSIX allows this)
    if current_path.exists() {
        std::fs::rename(&current_path, &backup_path).context("Failed to rename old binary")?;
    }

    // Step 2: Rename new binary to original path
    // Try rename first (atomic, works across same filesystem)
    match std::fs::rename(temp_file.path(), &current_path) {
        Ok(()) => {
            // Success! Clean up the old binary
            if backup_path.exists() {
                let _ = std::fs::remove_file(&backup_path);
            }
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(18) => {
            // EXDEV (Invalid cross-device link) - different filesystems
            // Fall back to copy (not atomic, but works across filesystems)
            match std::fs::copy(temp_file.path(), &current_path) {
                Ok(_) => {
                    // Success! Clean up the old binary
                    if backup_path.exists() {
                        let _ = std::fs::remove_file(&backup_path);
                    }
                    Ok(())
                }
                Err(copy_err) => {
                    // Restore the old binary
                    let _ = std::fs::rename(&backup_path, &current_path);
                    Err(copy_err).with_context(|| {
                        format!(
                            "Failed to copy binary to {}. Original restored.",
                            current_path.display()
                        )
                    })
                }
            }
        }
        Err(e) => {
            // Restore the old binary
            let _ = std::fs::rename(&backup_path, &current_path);
            Err(e).with_context(|| {
                format!(
                    "Failed to replace binary at {}. Original restored.",
                    current_path.display()
                )
            })
        }
    }
}

/// Get current binary path
fn current_binary_path() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to determine current executable path")
}
