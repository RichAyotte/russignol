use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::utils::{get_busybox_config, get_config_name, run_buildroot_make};

const BUILDROOT_DIR: &str = "buildroot";

/// Get the buildroot and external tree paths (external tree as absolute path)
fn get_paths() -> Result<(PathBuf, PathBuf)> {
    let buildroot_dir = PathBuf::from(BUILDROOT_DIR);
    if !buildroot_dir.exists() {
        bail!(
            "buildroot directory not found.\nClone it with: git clone https://gitlab.com/buildroot.org/buildroot.git"
        );
    }

    let external_tree = PathBuf::from("rpi-signer/buildroot-external");
    if !external_tree.exists() {
        bail!("External tree not found: {}", external_tree.display());
    }

    // Convert external tree to absolute path since buildroot commands run in buildroot dir
    let external_tree_abs = std::env::current_dir()?.join(&external_tree);

    Ok((buildroot_dir, external_tree_abs))
}

/// Configuration context state
enum ConfigContext {
    Ok,
    NeedsReload,
    Mismatch,
}

/// Check if buildroot config matches the requested context (hardened vs dev)
fn check_config_context(
    buildroot_dir: &Path,
    config_name: &str,
    is_dev: bool,
) -> Result<ConfigContext> {
    let config_file = buildroot_dir.join(".config");

    if !config_file.exists() {
        return Ok(ConfigContext::NeedsReload);
    }

    let expected_bb = get_busybox_config(is_dev);
    let config_content =
        std::fs::read_to_string(&config_file).context("Failed to read buildroot .config")?;

    let current_bb = config_content
        .lines()
        .find(|l| l.starts_with("BR2_PACKAGE_BUSYBOX_CONFIG="))
        .and_then(|l| l.split('=').nth(1))
        .unwrap_or("");

    if !current_bb.contains(expected_bb) {
        println!("Detected configuration mismatch.");
        println!("  Current context: {}", current_bb.trim_matches('"'));
        println!("  Requested context: {config_name}");
        return Ok(ConfigContext::Mismatch);
    }

    Ok(ConfigContext::Ok)
}

/// Reload buildroot configuration
fn reload_config(buildroot_dir: &Path, external_tree: &Path, config_name: &str) -> Result<()> {
    println!("Loading {}...", config_name.yellow());
    run_buildroot_make(buildroot_dir, external_tree, &[config_name])?;
    println!();
    Ok(())
}

// ============================================================================
// BUILDROOT CONFIGURATION
// ============================================================================

pub fn config_buildroot_nconfig(is_dev: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);
    println!(
        "{}",
        format!("Opening buildroot nconfig ({config_name})...").cyan()
    );
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Check and reload if needed
    match check_config_context(&buildroot_dir, config_name, is_dev)? {
        ConfigContext::NeedsReload | ConfigContext::Mismatch => {
            reload_config(&buildroot_dir, &external_tree, config_name)?;
        }
        ConfigContext::Ok => {}
    }

    // Open nconfig
    run_buildroot_make(&buildroot_dir, &external_tree, &["nconfig"])?;

    println!();
    println!("Configuration updated in buildroot directory.");
    println!("To save changes back to your defconfig, run:");
    println!(
        "  {}",
        format!(
            "cargo xtask config buildroot{} update",
            if is_dev { " --dev" } else { "" }
        )
        .cyan()
    );

    Ok(())
}

pub fn config_buildroot_menuconfig(is_dev: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);
    println!(
        "{}",
        format!("Opening buildroot menuconfig ({config_name})...").cyan()
    );
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Check and reload if needed
    match check_config_context(&buildroot_dir, config_name, is_dev)? {
        ConfigContext::NeedsReload | ConfigContext::Mismatch => {
            reload_config(&buildroot_dir, &external_tree, config_name)?;
        }
        ConfigContext::Ok => {}
    }

    // Open menuconfig
    run_buildroot_make(&buildroot_dir, &external_tree, &["menuconfig"])?;

    println!();
    println!("Configuration updated in buildroot directory.");
    println!("To save changes back to your defconfig, run:");
    println!(
        "  {}",
        format!(
            "cargo xtask config buildroot{} update",
            if is_dev { " --dev" } else { "" }
        )
        .cyan()
    );

    Ok(())
}

pub fn config_buildroot_load(is_dev: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);
    println!("{}", format!("Loading {config_name}...").cyan());
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Remove old .config to force fresh load
    let config_file = buildroot_dir.join(".config");
    if config_file.exists() {
        std::fs::remove_file(&config_file)?;
    }

    run_buildroot_make(&buildroot_dir, &external_tree, &[config_name])?;

    println!();
    println!("{}", "✓ Configuration loaded".green());
    println!("Buildroot is now configured and ready to build.");

    Ok(())
}

pub fn config_buildroot_update(is_dev: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);
    println!(
        "{}",
        format!("Saving buildroot config to {config_name}...").cyan()
    );
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Check if buildroot is configured
    let config_file = buildroot_dir.join(".config");
    if !config_file.exists() {
        bail!(
            "Buildroot not configured. Run 'cargo xtask config buildroot{} load' first.",
            if is_dev { " --dev" } else { "" }
        );
    }

    // Safety check: ensure we're not overwriting the wrong defconfig
    let expected_bb = get_busybox_config(is_dev);
    let config_content = std::fs::read_to_string(&config_file)?;
    let current_bb = config_content
        .lines()
        .find(|l| l.starts_with("BR2_PACKAGE_BUSYBOX_CONFIG="))
        .and_then(|l| l.split('=').nth(1))
        .unwrap_or("");

    if !current_bb.contains(expected_bb) {
        bail!(
            "Configuration mismatch prevented accidental overwrite.\n\
            You requested to save to: {} ({})\n\
            But current buildroot .config seems to be: {}\n\n\
            To fix this, load the correct context first:\n  {}",
            config_name,
            if is_dev { "dev" } else { "hardened" },
            current_bb.trim_matches('"'),
            format!(
                "cargo xtask config buildroot{} load",
                if is_dev { " --dev" } else { "" }
            )
            .cyan()
        );
    }

    let defconfig_path = external_tree.join("configs").join(config_name);
    run_buildroot_make(
        &buildroot_dir,
        &external_tree,
        &[
            "savedefconfig",
            &format!("BR2_DEFCONFIG={}", defconfig_path.display()),
        ],
    )?;

    println!();
    println!("{}", "✓ Buildroot defconfig updated at:".green());
    println!("  {}", defconfig_path.display());
    println!();
    println!("The changes are now in your external tree and ready to commit.");

    Ok(())
}

// ============================================================================
// BUSYBOX CONFIGURATION
// ============================================================================

pub fn config_busybox_menuconfig(is_dev: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);
    println!(
        "{}",
        format!("Opening BusyBox menuconfig (bootstrap: {config_name})...").cyan()
    );
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Check and reload if needed
    match check_config_context(&buildroot_dir, config_name, is_dev)? {
        ConfigContext::NeedsReload | ConfigContext::Mismatch => {
            reload_config(&buildroot_dir, &external_tree, config_name)?;
        }
        ConfigContext::Ok => {}
    }

    run_buildroot_make(&buildroot_dir, &external_tree, &["busybox-menuconfig"])?;

    println!();
    println!("Configuration updated in buildroot build directory.");
    println!("To save changes back to your external tree, run:");
    println!(
        "  {}",
        format!(
            "cargo xtask config busybox{} update",
            if is_dev { " --dev" } else { "" }
        )
        .cyan()
    );

    Ok(())
}

pub fn config_busybox_update(is_dev: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);
    println!("{}", "Saving BusyBox config to external tree...".cyan());
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Check if buildroot is configured
    let config_file = buildroot_dir.join(".config");
    if !config_file.exists() {
        bail!(
            "Buildroot not configured. Run 'cargo xtask config busybox{} menuconfig' first.",
            if is_dev { " --dev" } else { "" }
        );
    }

    // Safety check
    let expected_bb = get_busybox_config(is_dev);
    let config_content = std::fs::read_to_string(&config_file)?;
    let current_bb = config_content
        .lines()
        .find(|l| l.starts_with("BR2_PACKAGE_BUSYBOX_CONFIG="))
        .and_then(|l| l.split('=').nth(1))
        .unwrap_or("");

    if !current_bb.contains(expected_bb) {
        bail!(
            "Configuration mismatch prevented accidental overwrite.\n\
            You requested to update: {} (expects {})\n\
            But current buildroot .config points to: {}\n\n\
            To fix this, run menuconfig first to load the correct context:\n  {}",
            config_name,
            expected_bb,
            current_bb.trim_matches('"'),
            format!(
                "cargo xtask config busybox{} menuconfig",
                if is_dev { " --dev" } else { "" }
            )
            .cyan()
        );
    }

    run_buildroot_make(&buildroot_dir, &external_tree, &["busybox-update-config"])?;

    let busybox_config_path = external_tree.join("package/busybox").join(expected_bb);
    println!();
    println!("{}", "✓ BusyBox config updated at:".green());
    println!("  {}", busybox_config_path.display());
    println!();
    println!("The changes are now in your external tree and ready to commit.");

    Ok(())
}

// ============================================================================
// KERNEL CONFIGURATION
// ============================================================================

pub fn config_kernel_nconfig(is_dev: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);
    println!(
        "{}",
        format!("Opening kernel nconfig (bootstrap: {config_name})...").cyan()
    );
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Check and reload if needed
    match check_config_context(&buildroot_dir, config_name, is_dev)? {
        ConfigContext::NeedsReload | ConfigContext::Mismatch => {
            reload_config(&buildroot_dir, &external_tree, config_name)?;
        }
        ConfigContext::Ok => {}
    }

    run_buildroot_make(&buildroot_dir, &external_tree, &["linux-nconfig"])?;

    println!();
    println!("Configuration updated in buildroot build directory.");
    println!("To save changes back to your defconfig, run:");
    println!(
        "  {}",
        format!(
            "cargo xtask config kernel{} update",
            if is_dev { " --dev" } else { "" }
        )
        .cyan()
    );

    Ok(())
}

pub fn config_kernel_update(is_dev: bool) -> Result<()> {
    println!("{}", "Saving kernel config to defconfig...".cyan());
    println!();

    let (buildroot_dir, external_tree) = get_paths()?;

    // Check if buildroot is configured
    let config_file = buildroot_dir.join(".config");
    if !config_file.exists() {
        bail!(
            "Buildroot not configured. Run 'cargo xtask config kernel{} nconfig' first.",
            if is_dev { " --dev" } else { "" }
        );
    }

    run_buildroot_make(&buildroot_dir, &external_tree, &["linux-update-defconfig"])?;

    let kernel_defconfig_path = external_tree.join("board/russignol/linux-russignol_defconfig");
    println!();
    println!("{}", "✓ Kernel defconfig updated at:".green());
    println!("  {}", kernel_defconfig_path.display());
    println!();
    println!("The changes are now in your external tree and ready to commit.");

    Ok(())
}
