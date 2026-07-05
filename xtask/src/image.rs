use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::build::{build_rpi_signer, get_signer_binary_path};
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

    // Build the signer from current sources, then package the produced binary.
    println!("Preparing binary for image...");
    let rootfs_overlay = external_tree.join("rootfs-overlay-common");
    let signer_binary = prepare_signer_binary(
        is_dev,
        &rootfs_overlay,
        build_rpi_signer,
        get_signer_binary_path,
    )?;
    println!(
        "  {} Signer built and copied to rootfs overlay: {}",
        "✓".green(),
        signer_binary.display()
    );
    println!();

    Ok(())
}

/// Build the signer from the current sources, then copy the produced binary
/// into the rootfs overlay, returning its path. Building here — rather than
/// packaging whatever binary happens to sit in `target/` — is what keeps the
/// image from ever shipping a signer that predates the current sources.
fn prepare_signer_binary(
    is_dev: bool,
    rootfs_overlay: &Path,
    build: impl Fn(bool) -> Result<()>,
    locate: impl Fn(bool) -> Result<PathBuf>,
) -> Result<PathBuf> {
    build(is_dev)?;
    let signer_binary = locate(is_dev)?;
    copy_binary_to_rootfs(&signer_binary, "russignol-signer", rootfs_overlay)?;
    Ok(signer_binary)
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
    verify_compression_backend(Path::new("output/build/linux-custom/.config"))?;
    verify_mount_opts_drift()?;
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

/// Map of `CONFIG_X` -> value built from `CONFIG_X=y`/`=m`/… lines. `# CONFIG_X
/// is not set` lines are ignored, so an absent symbol is simply missing from
/// the map.
fn enabled_configs(config: &str) -> std::collections::HashMap<&str, &str> {
    config
        .lines()
        .filter(|line| line.starts_with("CONFIG_"))
        .filter_map(|line| line.split_once('='))
        .collect()
}

/// Violations of [`KERNEL_HARDENING`] in a kernel `.config`; empty when compliant.
fn kernel_hardening_violations(config: &str) -> Vec<String> {
    let enabled = enabled_configs(config);

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

/// Kernel `CONFIG_` symbols required to mount with a given F2FS
/// `compress_algorithm=` value. Empty when the mount options request no
/// compression. Requesting an algorithm the kernel lacks makes the mount fail.
fn required_compression_symbols(mount_opts: &str) -> Vec<&'static str> {
    let Some(algo) = mount_opts
        .split(',')
        .find_map(|opt| opt.trim().strip_prefix("compress_algorithm="))
    else {
        return Vec::new();
    };
    let mut syms = vec!["CONFIG_F2FS_FS_COMPRESSION"];
    match algo {
        "zstd" => syms.extend(["CONFIG_F2FS_FS_ZSTD", "CONFIG_ZSTD_COMPRESS"]),
        "lz4" => syms.push("CONFIG_F2FS_FS_LZ4"),
        "lzo" => syms.push("CONFIG_F2FS_FS_LZO"),
        "lzo-rle" => syms.extend(["CONFIG_F2FS_FS_LZO", "CONFIG_F2FS_FS_LZORLE"]),
        _ => {}
    }
    syms
}

/// Config symbols the F2FS mount options need but the `.config` lacks.
fn compression_backend_violations(mount_opts: &str, config: &str) -> Vec<String> {
    let enabled = enabled_configs(config);
    required_compression_symbols(mount_opts)
        .into_iter()
        .filter(|sym| enabled.get(sym).copied() != Some("y"))
        .map(|sym| {
            format!("{sym} must be =y (required by compress_algorithm in the /data mount options)")
        })
        .collect()
}

/// Fail the build when the data-partition mount options request a compression
/// algorithm the kernel was not built to support — the mount would be rejected
/// at boot and `/data` would silently fail to mount.
fn verify_compression_backend(config_path: &Path) -> Result<()> {
    let config = std::fs::read_to_string(config_path).with_context(|| {
        format!(
            "Failed to read generated kernel config: {}",
            config_path.display()
        )
    })?;

    let violations = compression_backend_violations(russignol_storage::F2FS_MOUNT_OPTS, &config);
    if !violations.is_empty() {
        bail!(
            "F2FS compression backend missing in {}:\n  {}\n\n\
            The /data mount options request a compress_algorithm the kernel\n\
            cannot provide, so /data will fail to mount. Enable the backend or\n\
            drop compression from russignol_storage::F2FS_MOUNT_OPTS.",
            config_path.display(),
            violations.join("\n  ")
        );
    }

    println!("  {} F2FS mount options supported by kernel", "✓".green());
    Ok(())
}

/// Data-partition mount option strings that must stay byte-identical to
/// `russignol_storage::F2FS_MOUNT_OPTS`, relative to the buildroot dir the
/// build runs in.
const MOUNT_OPT_SHELL_FILES: &[&str] = &[
    "../rpi-signer/buildroot-external/rootfs-overlay-hardened/init",
    "../rpi-signer/buildroot-external/rootfs-overlay-dev/etc/init.d/S20russignol",
];

/// Value of a `NAME="value"` (or `NAME=value`) shell assignment, ignoring an
/// optional `export ` and surrounding quotes.
fn extract_shell_var(content: &str, name: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let rest = line.strip_prefix(name)?.strip_prefix('=')?;
        Some(rest.trim().trim_matches('"').to_string())
    })
}

/// Description of a shell `F2FS_OPTS` that has drifted from `expected`, or
/// `None` when it matches.
fn shell_opts_mismatch(expected: &str, label: &str, content: &str) -> Option<String> {
    match extract_shell_var(content, "F2FS_OPTS") {
        Some(v) if v == expected => None,
        Some(v) => Some(format!(
            "{label}: F2FS_OPTS is\n    {v}\n  but expected\n    {expected}"
        )),
        None => Some(format!("{label}: F2FS_OPTS assignment not found")),
    }
}

/// Fail the build when an init script's `F2FS_OPTS` no longer matches the
/// shared Rust constant, so the shell and Rust mount options cannot drift.
fn verify_mount_opts_drift() -> Result<()> {
    let expected = russignol_storage::F2FS_MOUNT_OPTS;
    let mut violations = Vec::new();
    for path in MOUNT_OPT_SHELL_FILES {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read init script: {path}"))?;
        if let Some(v) = shell_opts_mismatch(expected, path, &content) {
            violations.push(v);
        }
    }
    if !violations.is_empty() {
        bail!(
            "F2FS mount option drift between shell and russignol_storage::F2FS_MOUNT_OPTS:\n  {}",
            violations.join("\n  ")
        );
    }

    println!(
        "  {} F2FS mount options match across shell and Rust",
        "✓".green()
    );
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

    #[test]
    fn shared_mount_opts_request_no_compression() {
        // The shipped constant must not demand a compression backend.
        assert!(required_compression_symbols(russignol_storage::F2FS_MOUNT_OPTS).is_empty());
        let violations = compression_backend_violations(russignol_storage::F2FS_MOUNT_OPTS, "");
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn required_compression_symbols_map_by_algorithm() {
        assert_eq!(
            required_compression_symbols("rw,compress_algorithm=zstd,atgc"),
            vec![
                "CONFIG_F2FS_FS_COMPRESSION",
                "CONFIG_F2FS_FS_ZSTD",
                "CONFIG_ZSTD_COMPRESS"
            ]
        );
        assert_eq!(
            required_compression_symbols("rw,compress_algorithm=lz4"),
            vec!["CONFIG_F2FS_FS_COMPRESSION", "CONFIG_F2FS_FS_LZ4"]
        );
        assert!(required_compression_symbols("rw,inline_data").is_empty());
    }

    #[test]
    fn reports_missing_compression_backend() {
        // Compression requested, but the kernel enables no zstd backend.
        let config = "CONFIG_F2FS_FS_COMPRESSION=y\n";
        let violations = compression_backend_violations("rw,compress_algorithm=zstd", config);
        assert!(
            violations.iter().any(|v| v.contains("CONFIG_F2FS_FS_ZSTD")),
            "missing zstd backend must be reported: {violations:?}"
        );
    }

    #[test]
    fn accepts_present_compression_backend() {
        let config =
            "CONFIG_F2FS_FS_COMPRESSION=y\nCONFIG_F2FS_FS_ZSTD=y\nCONFIG_ZSTD_COMPRESS=y\n";
        let violations = compression_backend_violations("rw,compress_algorithm=zstd", config);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn extract_shell_var_reads_quoted_assignment() {
        assert_eq!(
            extract_shell_var("F2FS_OPTS=\"rw,atgc\"\n", "F2FS_OPTS").as_deref(),
            Some("rw,atgc")
        );
        assert_eq!(
            extract_shell_var("export F2FS_OPTS=rw\n", "F2FS_OPTS").as_deref(),
            Some("rw")
        );
        // A longer variable name must not match.
        assert_eq!(
            extract_shell_var("F2FS_OPTS_EXTRA=\"x\"\n", "F2FS_OPTS"),
            None
        );
    }

    #[test]
    fn shell_opts_mismatch_detects_drift() {
        let expected = "rw,atgc";
        assert!(shell_opts_mismatch(expected, "f", "F2FS_OPTS=\"rw,atgc\"").is_none());
        assert!(
            shell_opts_mismatch(expected, "f", "F2FS_OPTS=\"rw,compress_algorithm=zstd\"")
                .is_some()
        );
        assert!(shell_opts_mismatch(expected, "f", "nothing here").is_some());
    }

    /// The signer must be built before it is located and copied, so a binary
    /// predating the current sources can never be packaged into the image.
    #[test]
    fn prepare_signer_builds_before_packaging() {
        use std::cell::RefCell;

        let calls = RefCell::new(Vec::new());
        let tmp = tempfile::tempdir().unwrap();
        let built = tmp.path().join("russignol-signer");
        std::fs::write(&built, b"fresh-binary").unwrap();
        let overlay = tmp.path().join("overlay");
        let built_for_locate = built.clone();

        let signer = prepare_signer_binary(
            true,
            &overlay,
            |_dev| {
                calls.borrow_mut().push("build");
                Ok(())
            },
            |_dev| {
                calls.borrow_mut().push("locate");
                Ok(built_for_locate.clone())
            },
        )
        .unwrap();

        assert_eq!(*calls.borrow(), vec!["build", "locate"]);
        assert_eq!(signer, built);
        assert_eq!(
            std::fs::read(overlay.join("bin/russignol-signer")).unwrap(),
            b"fresh-binary"
        );
    }
}
