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
        // Remove .config before make clean — Buildroot 2026.02+ checks for legacy
        // config options before any target, including clean, causing a spurious failure.
        let _ = std::fs::remove_file(".config");
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
    verify_kernel_hardening(Path::new("output/build/linux-custom/.config"))?;
    save_buildroot_state(config_name, &state_file)?;

    Ok(())
}

/// Kernel hardening requirements asserted against the generated kernel
/// config on every image build; `true` = must be `=y`, `false` = must not
/// be enabled. Every config cited in the `docs/SECURITY_AUDIT.md` §3.1
/// table must appear here — that doc promises this list enforces the table.
///
/// The defconfig cannot pin several of these: they hold only through
/// Kconfig side effects (`SECURITY_LOCKDOWN_LSM` selects `MODULE_SIG`;
/// `INIT_STACK_ALL_ZERO` defaults on only when the toolchain supports
/// `-ftrivial-auto-var-init=zero`; `NAMESPACES`/`AIO`/`IO_URING` default
/// off only under `EXPERT`), and `savedefconfig` — which `cargo xtask
/// config kernel update` runs — strips any symbol matching those computed
/// defaults. A kernel or toolchain bump can therefore drop them without
/// any build error; this check is the guard.
const KERNEL_HARDENING: &[(&str, bool)] = &[
    ("CONFIG_RANDOMIZE_BASE", true),
    ("CONFIG_SECURITY_LOCKDOWN_LSM_EARLY", true),
    ("CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY", true),
    ("CONFIG_MODULE_SIG", true),
    ("CONFIG_MODULE_SIG_ALL", true),
    ("CONFIG_MODULE_SIG_FORCE", true),
    ("CONFIG_INIT_ON_ALLOC_DEFAULT_ON", true),
    ("CONFIG_INIT_ON_FREE_DEFAULT_ON", true),
    ("CONFIG_INIT_STACK_ALL_ZERO", true),
    ("CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT", true),
    ("CONFIG_ARM64_SW_TTBR0_PAN", true),
    ("CONFIG_SLAB_FREELIST_RANDOM", true),
    ("CONFIG_SLAB_FREELIST_HARDENED", true),
    ("CONFIG_FORTIFY_SOURCE", true),
    ("CONFIG_HARDENED_USERCOPY", true),
    ("CONFIG_LIST_HARDENED", true),
    ("CONFIG_SECURITY_YAMA", true),
    ("CONFIG_SECURITY_DMESG_RESTRICT", true),
    ("CONFIG_F2FS_FS", true),
    ("CONFIG_SLAB_MERGE_DEFAULT", false),
    ("CONFIG_COREDUMP", false),
    ("CONFIG_SWAP", false),
    ("CONFIG_AIO", false),
    ("CONFIG_IO_URING", false),
    ("CONFIG_NAMESPACES", false),
    ("CONFIG_LEGACY_PTYS", false),
    ("CONFIG_DEVMEM", false),
];

/// Violations of [`KERNEL_HARDENING`] in a kernel `.config`; empty when compliant.
fn kernel_hardening_violations(config: &str) -> Vec<String> {
    let enabled: std::collections::HashMap<&str, &str> = config
        .lines()
        .filter(|line| line.starts_with("CONFIG_"))
        .filter_map(|line| line.split_once('='))
        .collect();

    KERNEL_HARDENING
        .iter()
        .filter_map(
            |&(symbol, required)| match (required, enabled.get(symbol).copied()) {
                (true, Some("y")) => None,
                (true, value) => Some(format!(
                    "{symbol} must be =y, found {}",
                    value.map_or_else(|| "nothing".to_string(), |v| format!("={v}"))
                )),
                (false, Some(value @ ("y" | "m"))) => {
                    Some(format!("{symbol} must stay disabled, found ={value}"))
                }
                (false, _) => None,
            },
        )
        .collect()
}

/// Fail the build when the generated kernel config has lost a hardening option.
fn verify_kernel_hardening(config_path: &Path) -> Result<()> {
    let config = std::fs::read_to_string(config_path).with_context(|| {
        format!(
            "Failed to read generated kernel config: {}",
            config_path.display()
        )
    })?;

    let violations = kernel_hardening_violations(&config);
    if !violations.is_empty() {
        bail!(
            "Kernel hardening drift in {}:\n  {}\n\n\
            The image was built from a kernel config that lost hardening\n\
            options docs/SECURITY_AUDIT.md claims. Do not release this image.",
            config_path.display(),
            violations.join("\n  ")
        );
    }

    println!("  {} Kernel hardening config verified", "✓".green());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal config satisfying every [`KERNEL_HARDENING`] requirement.
    fn compliant_config() -> String {
        KERNEL_HARDENING
            .iter()
            .map(|&(symbol, required)| {
                if required {
                    format!("{symbol}=y\n")
                } else {
                    format!("# {symbol} is not set\n")
                }
            })
            .collect()
    }

    #[test]
    fn accepts_compliant_config() {
        let violations = kernel_hardening_violations(&compliant_config());
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    /// A required symbol silently dropped by a Kconfig default/select change
    /// (e.g. `MODULE_SIG` when lockdown stops selecting it) must be reported.
    #[test]
    fn reports_missing_required_symbol() {
        let config = compliant_config().replace("CONFIG_MODULE_SIG=y\n", "");
        let violations = kernel_hardening_violations(&config);
        assert!(
            violations.iter().any(|v| v.contains("CONFIG_MODULE_SIG ")),
            "missing CONFIG_MODULE_SIG must be reported: {violations:?}"
        );
    }

    /// A must-stay-off symbol re-enabled by a default flip (e.g. NAMESPACES
    /// when `CONFIG_EXPERT` is removed) must be reported.
    #[test]
    fn reports_reenabled_disabled_symbol() {
        let config =
            compliant_config().replace("# CONFIG_NAMESPACES is not set\n", "CONFIG_NAMESPACES=y\n");
        let violations = kernel_hardening_violations(&config);
        assert!(
            violations.iter().any(|v| v.contains("CONFIG_NAMESPACES")),
            "re-enabled CONFIG_NAMESPACES must be reported: {violations:?}"
        );
    }

    /// `CONFIG_MODULE_SIG=y` must not satisfy the `CONFIG_MODULE_SIG_ALL`
    /// or `CONFIG_MODULE_SIG_FORCE` requirements (prefix collision).
    #[test]
    fn requires_exact_symbol_match() {
        let config = compliant_config()
            .replace("CONFIG_MODULE_SIG_ALL=y\n", "")
            .replace("CONFIG_MODULE_SIG_FORCE=y\n", "");
        let violations = kernel_hardening_violations(&config);
        assert_eq!(
            violations.len(),
            2,
            "both dropped symbols must be reported: {violations:?}"
        );
    }

    /// A disabled requirement is also violated by `=m`: a loadable module
    /// still ships the feature.
    #[test]
    fn reports_disabled_symbol_built_as_module() {
        let config = compliant_config().replace(
            "# CONFIG_LEGACY_PTYS is not set\n",
            "CONFIG_LEGACY_PTYS=m\n",
        );
        let violations = kernel_hardening_violations(&config);
        assert!(
            violations.iter().any(|v| v.contains("CONFIG_LEGACY_PTYS")),
            "modular CONFIG_LEGACY_PTYS must be reported: {violations:?}"
        );
    }

    /// A disabled symbol absent from the config entirely (dropped by a
    /// kernel version bump) is fine: it cannot be enabled at all.
    #[test]
    fn accepts_absent_disabled_symbol() {
        let config = compliant_config().replace("# CONFIG_DEVMEM is not set\n", "");
        let violations = kernel_hardening_violations(&config);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }
}
