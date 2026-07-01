use anyhow::{Context, Result, bail};
use std::env;
use std::path::Path;
use std::process::Command;

/// Clear host-specific compiler flags that interfere with cross-compilation
pub fn clear_host_compiler_flags() {
    // These env operations are safe in our single-threaded build context
    unsafe {
        env::remove_var("CFLAGS");
        env::remove_var("CXXFLAGS");
        env::remove_var("LDFLAGS");
        env::remove_var("KCFLAGS");
        env::remove_var("KCPPFLAGS");
    }
}

/// Set ARM-specific RUSTFLAGS for Cortex-A53 (`RPi` Zero 2W).
///
/// The `sha2_256_backend = "soft"` cfg forces sha2 0.11 to skip its
/// cpufeatures-gated runtime dispatch, which hangs first-boot keygen on the
/// Pi Zero 2W's Cortex-A53 (BCM2710A1) under release LTO. The CPU lacks the
/// `ARMv8` SHA-2 crypto extensions, so the soft backend is what would run at
/// runtime regardless.
pub fn set_arm_rustflags() {
    // Safe in our single-threaded build context
    unsafe {
        // The Pi Zero 2W's Cortex-A53 lacks the optional ARMv8 crypto
        // extensions, yet LLVM's cortex-a53 model enables +aes/+sha2. cpufeatures
        // then trusts the compile-time feature and skips its runtime HWCAP probe,
        // so RustCrypto executes AES/SHA/PMULL instructions that fault (SIGILL) on
        // this silicon. Subtracting the features restores the runtime probe, which
        // correctly finds no crypto and selects the software backends.
        env::set_var(
            "RUSTFLAGS",
            "-C target-cpu=cortex-a53 -C target-feature=-aes,-sha2",
        );
    }
}

/// Get config name based on dev flag
pub fn get_config_name(is_dev: bool) -> &'static str {
    if is_dev {
        "russignol_defconfig"
    } else {
        "russignol_hardened_defconfig"
    }
}

/// Get busybox config file name based on dev flag
pub fn get_busybox_config(is_dev: bool) -> &'static str {
    if is_dev {
        "busybox.config"
    } else {
        "busybox_hardened.config"
    }
}

/// Run make in buildroot directory with `BR2_EXTERNAL` set.
///
/// When the `rpi-linux` git submodule exists alongside the buildroot directory,
/// passes `LINUX_OVERRIDE_SRCDIR` so Buildroot rsyncs the kernel source locally
/// instead of downloading the tarball. This is significantly faster for clean builds.
pub fn run_buildroot_make(buildroot_dir: &Path, external_tree: &Path, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("make");
    cmd.current_dir(buildroot_dir)
        .env("BR2_EXTERNAL", external_tree);

    // Use local kernel source when the rpi-linux submodule is populated
    let rpi_linux_dir = buildroot_dir.join("../rpi-linux");
    if rpi_linux_dir.join("Makefile").exists() {
        let abs_path = rpi_linux_dir
            .canonicalize()
            .context("Failed to resolve rpi-linux path")?;
        cmd.arg(format!("LINUX_OVERRIDE_SRCDIR={}", abs_path.display()));
    }

    cmd.args(args);

    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute: make {}", args.join(" ")))?;

    if !status.success() {
        bail!("Buildroot make failed: {}", args.join(" "));
    }

    Ok(())
}

/// Copy a binary to rootfs overlay and make it executable
pub fn copy_binary_to_rootfs(
    binary_path: &Path,
    dest_name: &str,
    rootfs_overlay: &Path,
) -> Result<()> {
    let dest_dir = rootfs_overlay.join("bin");
    std::fs::create_dir_all(&dest_dir).context("Failed to create rootfs overlay bin directory")?;

    let dest_file = dest_dir.join(dest_name);
    std::fs::copy(binary_path, &dest_file)
        .with_context(|| format!("Failed to copy {} to rootfs overlay", binary_path.display()))?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dest_file)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dest_file, perms)?;
    }

    Ok(())
}

/// Compress SD card image with xz
pub fn compress_image(image_path: &Path) -> Result<()> {
    use colored::Colorize;

    if which::which("xz").is_err() {
        println!("  {} xz not found, skipping compression", "⚠".yellow());
        return Ok(());
    }

    println!("Compressing image for distribution...");
    let status = Command::new("xz")
        .args(["-9", "-k", "-f", "-T0"])
        .arg(image_path)
        .status()
        .context("Failed to run xz")?;

    if !status.success() {
        bail!("Failed to compress image");
    }

    let compressed = image_path.with_extension("img.xz");
    println!(
        "  {} Compressed image: {}",
        "✓".green(),
        compressed.display()
    );

    // Show compressed size
    if let Ok(metadata) = std::fs::metadata(&compressed) {
        let size_mb = metadata.len() / (1024 * 1024);
        println!("  Size: {size_mb} MB");
    }

    Ok(())
}

/// Run a command in a specific directory
pub fn run_cmd_in_dir(dir: &str, cmd: &str, args: &[&str], error_msg: &str) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| format!("Failed to execute: {} {}", cmd, args.join(" ")))?;

    if !status.success() {
        bail!("{error_msg}");
    }

    Ok(())
}

/// Check if a command exists in PATH
pub fn check_command(cmd: &str, hint: &str) -> Result<()> {
    if which::which(cmd).is_err() {
        bail!(
            "Required command '{}' not found.{}{}",
            cmd,
            if hint.is_empty() { "" } else { "\n" },
            hint
        );
    }
    Ok(())
}
