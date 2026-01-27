use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::build::get_signer_binary_path;
use crate::utils::{
    clear_host_compiler_flags, compress_image, copy_binary_to_rootfs, get_config_name,
    run_buildroot_make, run_cmd_in_dir,
};

const BUILDROOT_DIR: &str = "buildroot";

/// Build the SD card image using buildroot
pub fn build_image(is_dev: bool, force_clean: bool) -> Result<()> {
    let config_name = get_config_name(is_dev);

    println!(
        "{}",
        "=== Russignol SD Card Image Builder ===".cyan().bold()
    );
    println!();
    println!("Buildroot: {BUILDROOT_DIR}");
    println!("Config: {config_name}");
    println!("Force clean: {force_clean}");
    println!();

    // Clear host compiler flags that interfere with buildroot
    clear_host_compiler_flags();

    let buildroot_dir = PathBuf::from(BUILDROOT_DIR);
    let external_tree = PathBuf::from("rpi-signer/buildroot-external");

    validate_and_prepare_build(&buildroot_dir, &external_tree, config_name, is_dev)?;

    // Change to buildroot directory
    std::env::set_current_dir(&buildroot_dir).context("Failed to change to buildroot directory")?;

    run_build(config_name, force_clean, &external_tree)?;

    display_build_results()?;
    print_flashing_instructions();

    // Change back to project root
    std::env::set_current_dir("..").context("Failed to change back to project root")?;

    Ok(())
}

fn validate_and_prepare_build(
    buildroot_dir: &Path,
    external_tree: &Path,
    config_name: &str,
    is_dev: bool,
) -> Result<()> {
    // Check if buildroot exists
    if !buildroot_dir.exists() {
        bail!(
            "Buildroot directory not found: {}\n\n\
            To download buildroot:\n  \
            git clone https://git.buildroot.net/buildroot",
            buildroot_dir.display()
        );
    }

    // Check if configuration exists
    let config_path = external_tree.join("configs").join(config_name);
    if !config_path.exists() {
        bail!("Configuration not found: {}", config_path.display());
    }

    // Get binary path and copy to rootfs overlay
    println!("Preparing binary for image...");
    let signer_binary = get_signer_binary_path(is_dev)?;
    println!("  Found signer: {}", signer_binary.display());

    let rootfs_overlay = external_tree.join("rootfs-overlay-common");
    copy_binary_to_rootfs(&signer_binary, "russignol-signer", &rootfs_overlay)?;
    println!("  {} Binary copied to rootfs overlay", "✓".green());
    println!();

    Ok(())
}

fn run_build(config_name: &str, force_clean: bool, external_tree: &Path) -> Result<()> {
    // Clean if requested
    if force_clean {
        println!("Cleaning buildroot...");
        run_cmd_in_dir(".", "make", &["clean"], "Clean failed")?;
        println!("  {} Clean complete", "✓".green());
        println!();
    }

    // Load configuration
    println!("Loading configuration from external tree...");
    let external_tree_abs = std::env::current_dir()?
        .parent()
        .unwrap()
        .join(external_tree);

    run_buildroot_make(Path::new("."), &external_tree_abs, &[config_name])?;

    // Smart Rebuild Logic - detect configuration changes
    let state_file = external_tree_abs.join(".last_build_config");
    if check_buildroot_state(config_name, &state_file)? {
        println!(
            "{}",
            "⚠ Configuration changed - forcing full clean...".yellow()
        );
        run_cmd_in_dir(".", "make", &["clean"], "Clean failed")?;
    }

    println!();
    println!("Configuration loaded. Building...");
    println!();
    println!(
        "{}",
        "Starting build (this will take 30+ minutes on first run)...".cyan()
    );
    println!("Tip: Subsequent builds are much faster due to ccache");
    println!();

    run_cmd_in_dir(".", "make", &[], "Buildroot build failed")?;
    save_buildroot_state(config_name, &state_file)?;

    Ok(())
}

fn display_build_results() -> Result<()> {
    println!();
    println!("{}", "=== Build Complete ===".green().bold());
    println!();
    println!("Output files:");

    let images_dir = Path::new("output/images");
    if images_dir.exists() {
        for entry in std::fs::read_dir(images_dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                let size_mb = metadata.len() / (1024 * 1024);
                println!("  {} ({} MB)", entry.path().display(), size_mb);
            }
        }
    }

    println!();
    let sdcard_img = images_dir.join("sdcard.img");
    if sdcard_img.exists() {
        println!("SD card image: {}", sdcard_img.display());
        compress_image(&sdcard_img)?;
    }

    Ok(())
}

fn print_flashing_instructions() {
    println!();
    println!("{}", "=== Flashing Instructions ===".cyan());
    println!();
    println!("Flash to SD card using the host utility:");
    println!("  russignol image flash buildroot/output/images/sdcard.img.xz");
    println!();
}

/// Check if buildroot state indicates a config change that needs cleaning
fn check_buildroot_state(config_name: &str, state_file: &Path) -> Result<bool> {
    if !state_file.exists() {
        return Ok(false);
    }

    let last_config =
        std::fs::read_to_string(state_file).context("Failed to read buildroot state file")?;

    if last_config.trim() != config_name {
        println!();
        println!(
            "{}",
            format!(
                "⚠ Configuration changed from {} to {}.",
                last_config.trim(),
                config_name
            )
            .yellow()
        );
        return Ok(true); // Need clean
    }

    Ok(false)
}

/// Save current buildroot configuration state
fn save_buildroot_state(config_name: &str, state_file: &Path) -> Result<()> {
    std::fs::write(state_file, config_name).context("Failed to save buildroot state file")?;
    Ok(())
}
