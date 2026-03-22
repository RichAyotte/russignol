use anyhow::{Context, Result, bail};
use colored::Colorize;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::utils::run_buildroot_make;

const BUILDROOT_DIR: &str = "buildroot";
const RPI_LINUX_DIR: &str = "rpi-linux";
const KERNEL_DEFCONFIG: &str =
    "rpi-signer/buildroot-external/board/russignol/linux-russignol_defconfig";
const LINUX_HASH_FILE: &str = "rpi-signer/buildroot-external/patches/linux/linux.hash";
const DEFCONFIG_FILES: &[&str] = &[
    "rpi-signer/buildroot-external/configs/russignol_defconfig",
    "rpi-signer/buildroot-external/configs/russignol_hardened_defconfig",
];

pub fn cmd_upgrade() -> Result<()> {
    println!("{}", "Checking for upgrades...".cyan().bold());
    println!();

    upgrade_cargo()?;
    println!();
    upgrade_buildroot()?;
    println!();
    upgrade_rpi_linux()?;
    println!();
    update_defconfigs()?;
    println!();
    update_kernel_config()?;

    println!();
    println!("{}", "Upgrade complete.".green().bold());
    Ok(())
}

/// Capture stdout from a git command, trimmed
fn git_output(args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("Failed to run: git {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git command with inherited stdout/stderr
fn git_run(args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run: git {}", args.join(" ")))?;

    if !status.success() {
        bail!("git {} failed", args.join(" "));
    }

    Ok(())
}

// ============================================================================
// CARGO
// ============================================================================

fn upgrade_cargo() -> Result<()> {
    println!("{}", "Cargo dependencies".cyan());

    println!("  Refreshing Cargo.lock...");
    let status = Command::new("cargo")
        .args(["update"])
        .status()
        .context("Failed to run cargo update")?;
    if !status.success() {
        bail!("cargo update failed");
    }

    if which::which("cargo-upgrade").is_ok() {
        println!("  Checking for incompatible upgrades...");
        let status = Command::new("cargo")
            .args(["upgrade", "--incompatible", "allow"])
            .status()
            .context("Failed to run cargo upgrade")?;
        if !status.success() {
            bail!("cargo upgrade failed");
        }
    } else {
        println!(
            "  {} cargo-upgrade not installed, skipping incompatible upgrade check",
            "⚠".yellow()
        );
        println!("    Install with: {}", "cargo install cargo-edit".cyan());
    }

    println!("  {} Cargo dependencies updated", "✓".green());
    Ok(())
}

// ============================================================================
// BUILDROOT
// ============================================================================

fn upgrade_buildroot() -> Result<()> {
    println!("{}", "Buildroot".cyan());

    if !Path::new(BUILDROOT_DIR).exists() {
        println!("  {} buildroot directory not found, skipping", "⚠".yellow());
        return Ok(());
    }

    println!("  Fetching tags...");
    git_run(&["-C", BUILDROOT_DIR, "fetch", "--tags", "origin"])?;

    // Current tag (may be an RC or not on a tag at all)
    let current_tag = git_output(&[
        "-C",
        BUILDROOT_DIR,
        "describe",
        "--tags",
        "--exact-match",
        "HEAD",
    ])
    .unwrap_or_else(|_| "unknown".to_string());

    // Find latest stable release tag: YYYY.MM with no suffix
    let tags_output = git_output(&["-C", BUILDROOT_DIR, "tag", "-l"])?;
    let re = Regex::new(r"^(\d{4})\.(\d{2})$").expect("valid regex");

    let mut releases: Vec<(u32, u32, String)> = tags_output
        .lines()
        .filter_map(|tag| {
            re.captures(tag).map(|caps| {
                let year: u32 = caps[1].parse().expect("valid year");
                let month: u32 = caps[2].parse().expect("valid month");
                (year, month, tag.to_string())
            })
        })
        .collect();

    releases.sort_by_key(|(y, m, _)| (*y, *m));

    let latest = releases
        .last()
        .map(|(_, _, tag)| tag.clone())
        .context("No stable buildroot releases found in tags")?;

    println!("  Current: {}", current_tag.yellow());
    println!("  Latest:  {}", latest.yellow());

    if current_tag == latest {
        println!("  {} Already up to date", "✓".green());
    } else {
        git_run(&["-C", BUILDROOT_DIR, "checkout", &latest])?;
        println!("  {} Updated to {}", "✓".green(), latest);
    }

    Ok(())
}

// ============================================================================
// RPI-LINUX
// ============================================================================

fn upgrade_rpi_linux() -> Result<()> {
    println!("{}", "Linux kernel (rpi-linux)".cyan());

    if !Path::new(RPI_LINUX_DIR).exists() {
        println!("  {} rpi-linux directory not found, skipping", "⚠".yellow());
        return Ok(());
    }

    let branch = get_rpi_linux_branch()?;
    println!("  Branch:  {}", branch.yellow());

    let old_hash = git_output(&["-C", RPI_LINUX_DIR, "rev-parse", "HEAD"])?;
    let old_version = get_kernel_version(RPI_LINUX_DIR)?;
    println!("  Current: {} ({})", old_version, &old_hash[..12]);

    // Update submodule to latest on tracked branch
    git_run(&["submodule", "update", "--remote", RPI_LINUX_DIR])?;

    let new_hash = git_output(&["-C", RPI_LINUX_DIR, "rev-parse", "HEAD"])?;
    let new_version = get_kernel_version(RPI_LINUX_DIR)?;

    if old_hash == new_hash {
        println!("  {} Already up to date ({})", "✓".green(), new_version);
    } else {
        println!(
            "  {} Updated: {} → {} ({})",
            "✓".green(),
            old_version,
            new_version,
            &new_hash[..12]
        );
    }

    check_newer_kernel_branches(&branch)?;

    Ok(())
}

fn get_rpi_linux_branch() -> Result<String> {
    let content = std::fs::read_to_string(".gitmodules").context("Failed to read .gitmodules")?;

    let mut in_rpi_linux = false;
    for line in content.lines() {
        if line.contains("[submodule \"rpi-linux\"]") {
            in_rpi_linux = true;
            continue;
        }
        if line.contains("[submodule") {
            in_rpi_linux = false;
        }
        if in_rpi_linux && let Some(branch) = line.trim().strip_prefix("branch = ") {
            return Ok(branch.trim().to_string());
        }
    }

    bail!("No branch configured for rpi-linux in .gitmodules");
}

fn get_kernel_version(dir: &str) -> Result<String> {
    let makefile_path = format!("{dir}/Makefile");
    let content = std::fs::read_to_string(&makefile_path)
        .with_context(|| format!("Failed to read {makefile_path}"))?;

    let mut version = String::new();
    let mut patchlevel = String::new();
    let mut sublevel = String::new();

    for line in content.lines().take(10) {
        if let Some(v) = line.strip_prefix("VERSION = ") {
            version = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("PATCHLEVEL = ") {
            patchlevel = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("SUBLEVEL = ") {
            sublevel = v.trim().to_string();
        }
    }

    if version.is_empty() {
        bail!("Failed to parse kernel version from {makefile_path}");
    }

    Ok(format!("{version}.{patchlevel}.{sublevel}"))
}

fn check_newer_kernel_branches(current_branch: &str) -> Result<()> {
    let re = Regex::new(r"rpi-(\d+)\.(\d+)\.y").expect("valid regex");

    let Some(current_caps) = re.captures(current_branch) else {
        return Ok(()); // Can't parse current branch, skip check
    };
    let current_major: u32 = current_caps[1].parse()?;
    let current_minor: u32 = current_caps[2].parse()?;

    let output = git_output(&[
        "-C",
        RPI_LINUX_DIR,
        "ls-remote",
        "--heads",
        "origin",
        "rpi-*.y",
    ])?;

    let mut newer: Vec<(u32, u32, String)> = Vec::new();
    for line in output.lines() {
        let Some(ref_name) = line.split('\t').nth(1) else {
            continue;
        };
        let branch = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);
        if let Some(caps) = re.captures(branch) {
            let major: u32 = caps[1].parse()?;
            let minor: u32 = caps[2].parse()?;
            if (major, minor) > (current_major, current_minor) {
                newer.push((major, minor, branch.to_string()));
            }
        }
    }

    newer.sort_by_key(|(maj, min, _)| (*maj, *min));

    if !newer.is_empty() {
        let branch_names: Vec<&str> = newer.iter().map(|(_, _, b)| b.as_str()).collect();
        println!(
            "  {} Newer branches available: {}",
            "ℹ".cyan(),
            branch_names.join(", ")
        );
    }

    Ok(())
}

// ============================================================================
// DEFCONFIGS
// ============================================================================

fn update_defconfigs() -> Result<()> {
    println!("{}", "Defconfig tarball URLs".cyan());

    if !Path::new(RPI_LINUX_DIR).exists() {
        return Ok(());
    }

    let new_commit = git_output(&["-C", RPI_LINUX_DIR, "rev-parse", "HEAD"])?;

    let tarball_re =
        Regex::new(r"https://github\.com/raspberrypi/linux/archive/([a-f0-9]+)\.tar\.gz")
            .expect("valid regex");

    // Check if any defconfig needs updating (use first file to detect)
    let first_content = std::fs::read_to_string(DEFCONFIG_FILES[0])
        .with_context(|| format!("Failed to read {}", DEFCONFIG_FILES[0]))?;
    let first_old_commit = tarball_re
        .captures(&first_content)
        .map(|c| c[1].to_string());
    let already_current = first_old_commit.as_deref() == Some(&new_commit);

    for path in DEFCONFIG_FILES {
        let filename = Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        let content =
            std::fs::read_to_string(path).with_context(|| format!("Failed to read {path}"))?;

        let Some(caps) = tarball_re.captures(&content) else {
            println!("  {} No tarball URL found in {filename}", "⚠".yellow());
            continue;
        };

        let old_commit = &caps[1];
        if old_commit == new_commit {
            println!("  {} {filename} already up to date", "✓".green());
            continue;
        }

        let new_content = content.replace(old_commit, &new_commit);
        std::fs::write(path, new_content).with_context(|| format!("Failed to write {path}"))?;
        println!("  {} Updated {filename}", "✓".green());
    }

    // Update kernel tarball hash file
    if !already_current {
        update_linux_hash_file(&new_commit)?;
    } else if Path::new(LINUX_HASH_FILE).exists() {
        println!("  {} linux.hash already up to date", "✓".green());
    }

    Ok(())
}

/// Download the kernel tarball and update the hash file with the correct SHA256
fn update_linux_hash_file(commit: &str) -> Result<()> {
    let tarball_url = format!("https://github.com/raspberrypi/linux/archive/{commit}.tar.gz");
    let tarball_name = format!("{commit}.tar.gz");

    // Check if tarball is already in buildroot's download cache
    let cached_path = PathBuf::from(BUILDROOT_DIR)
        .join("dl/linux")
        .join(&tarball_name);

    let sha256_hex = if cached_path.exists() {
        println!("  Computing hash from cached tarball...");
        compute_file_sha256(&cached_path)?
    } else {
        println!("  Downloading kernel tarball for hash verification...");
        let tmp_path = download_tarball(&tarball_url, &tarball_name)?;
        let hash = compute_file_sha256(&tmp_path)?;

        // Move to buildroot download cache for later use
        let dl_dir = PathBuf::from(BUILDROOT_DIR).join("dl/linux");
        std::fs::create_dir_all(&dl_dir).ok();
        std::fs::rename(&tmp_path, &cached_path).ok();

        hash
    };

    // Parse the branch from .gitmodules for the comment
    let branch = get_rpi_linux_branch().unwrap_or_else(|_| "rpi-6.x.y".to_string());

    // Preserve the upstream kernel hash section, replace only the RPi section
    let existing = std::fs::read_to_string(LINUX_HASH_FILE).unwrap_or_default();
    let rpi_section_re =
        Regex::new(r"(?m)^# Raspberry Pi kernel.*\n# Downloaded from:.*\nsha256 .*\n")
            .expect("valid regex");

    let new_rpi_section = format!(
        "# Raspberry Pi kernel ({branch} branch, commit {commit})\n\
         # Downloaded from: {tarball_url}\n\
         sha256  {sha256_hex}  {tarball_name}\n"
    );

    let new_content = if rpi_section_re.is_match(&existing) {
        rpi_section_re
            .replace(&existing, &new_rpi_section)
            .to_string()
    } else {
        // No existing RPi section — append
        format!("{existing}\n{new_rpi_section}")
    };

    std::fs::write(LINUX_HASH_FILE, new_content)
        .with_context(|| format!("Failed to write {LINUX_HASH_FILE}"))?;
    println!("  {} Updated linux.hash", "✓".green());

    Ok(())
}

fn compute_file_sha256(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn download_tarball(url: &str, filename: &str) -> Result<PathBuf> {
    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join(filename);

    let status = Command::new("wget")
        .args(["-q", "-O"])
        .arg(&tmp_path)
        .arg(url)
        .status()
        .context("Failed to run wget")?;

    if !status.success() {
        bail!("Failed to download {url}");
    }

    Ok(tmp_path)
}

// ============================================================================
// KERNEL CONFIG
// ============================================================================

fn update_kernel_config() -> Result<()> {
    println!("{}", "Kernel defconfig".cyan());

    let buildroot_dir = PathBuf::from(BUILDROOT_DIR);
    if !buildroot_dir.exists() {
        println!("  {} buildroot directory not found, skipping", "⚠".yellow());
        return Ok(());
    }

    if !Path::new(RPI_LINUX_DIR).exists() {
        println!("  {} rpi-linux directory not found, skipping", "⚠".yellow());
        return Ok(());
    }

    // Snapshot current defconfig content to detect changes
    let old_content = std::fs::read_to_string(KERNEL_DEFCONFIG)
        .with_context(|| format!("Failed to read {KERNEL_DEFCONFIG}"))?;

    // Load buildroot config (hardened is the default/production config)
    let external_tree = std::env::current_dir()?.join("rpi-signer/buildroot-external");
    println!("  Loading buildroot config...");
    run_buildroot_make(
        &buildroot_dir,
        &external_tree,
        &["russignol_hardened_defconfig"],
    )?;

    // Extract and configure the kernel (rsyncs from local submodule when available),
    // then save back as a minimal defconfig, capturing any new options with defaults.
    println!("  Configuring kernel (this may take a moment)...");
    run_buildroot_make(&buildroot_dir, &external_tree, &["linux-configure"])?;
    println!("  Saving kernel defconfig...");
    run_buildroot_make(&buildroot_dir, &external_tree, &["linux-update-defconfig"])?;

    let new_content = std::fs::read_to_string(KERNEL_DEFCONFIG)
        .with_context(|| format!("Failed to read {KERNEL_DEFCONFIG}"))?;

    if old_content == new_content {
        println!("  {} No config changes", "✓".green());
    } else {
        println!(
            "  {} Kernel defconfig updated with new options",
            "✓".green()
        );
        println!(
            "    Review changes: {}",
            format!("git diff {KERNEL_DEFCONFIG}").cyan()
        );
    }

    Ok(())
}
