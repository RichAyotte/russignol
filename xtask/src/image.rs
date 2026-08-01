use anyhow::{Context, Result, bail};
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::build::{build_rpi_signer, get_signer_binary_path};
use crate::utils::{
    clear_host_compiler_flags, compress_image, copy_binary_to_rootfs, get_config_name,
    run_buildroot_make, run_cmd_in_dir,
};

const BUILDROOT_DIR: &str = "buildroot";
pub const BUILDROOT_CONFIG: &str = ".config";
const KERNEL_TREE_DIR: &str = "output/build/linux-custom";
const KERNEL_TREE_MARKER: &str = ".russignol-kernel-source";

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

    // Discard an output tree the current config and buildroot cannot extend
    let state_file = external_tree_abs.join(".last_build_config");
    let state = BuildState {
        config: config_name.to_string(),
        buildroot_commit: buildroot_commit(Path::new("."))?,
    };
    if !force_clean && check_buildroot_state(&state, &state_file) {
        run_cmd_in_dir(".", "make", &["clean"], "Clean failed")?;
    }

    // Resolved before the build rather than after it, so a configuration that
    // pins no kernel source fails without first spending the build on it.
    let loaded_config = std::fs::read_to_string(BUILDROOT_CONFIG)
        .with_context(|| format!("Failed to read the loaded {BUILDROOT_CONFIG}"))?;
    let kernel_state = KernelTreeState {
        config: config_name.to_string(),
        buildroot_commit: state.buildroot_commit.clone(),
        kernel_commit: kernel_commit_from_config(&loaded_config)
            .context("No kernel source commit pinned by the loaded configuration")?,
    };

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
    save_buildroot_state(&state, &state_file)?;
    kernel_state.save(Path::new("."))?;

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

/// What the buildroot output tree was last built from.
///
/// Buildroot carries no record of which of its own versions produced a tree and
/// does not support rebuilding one across a version change: a bumped checkout
/// reuses packages, host tools and the target skeleton left by the previous one.
/// Recording the commit beside the config is what lets a later build recognise
/// a tree it cannot safely extend.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildState {
    config: String,
    buildroot_commit: String,
}

impl BuildState {
    fn render(&self) -> String {
        format!("{}\n{}\n", self.config, self.buildroot_commit)
    }

    /// Reads back a state written by [`BuildState::render`].
    ///
    /// Anything else — a truncated write, or the config-only format that
    /// predates commit tracking — leaves the tree's provenance unknown.
    fn parse(contents: &str) -> Option<Self> {
        let mut lines = contents.lines();
        let config = lines.next()?.trim();
        let buildroot_commit = lines.next()?.trim();

        if config.is_empty() || buildroot_commit.is_empty() {
            return None;
        }

        Some(Self {
            config: config.to_string(),
            buildroot_commit: buildroot_commit.to_string(),
        })
    }
}

/// Whether the existing output tree has to be removed before building `current`.
///
/// A tree of unknown provenance is discarded rather than trusted, since it may
/// have been produced by any config or buildroot version.
fn needs_clean(previous: Option<&BuildState>, current: &BuildState) -> bool {
    previous.is_none_or(|previous| previous != current)
}

/// Commit of the buildroot checkout at `buildroot_dir`
pub fn buildroot_commit(buildroot_dir: &Path) -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(buildroot_dir)
        .output()
        .context("Failed to run git in the buildroot checkout")?;

    if !output.status.success() {
        bail!("Could not read the buildroot commit; is the submodule initialised?");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// What a configured kernel build tree was produced from.
///
/// Buildroot's stamp files record that a step ran, not what it ran against:
/// `.stamp_configured` survives a source, buildroot or config change, so
/// nothing in the tree otherwise distinguishes a kernel configured from one set
/// of inputs from a kernel configured from another. The record lives inside the
/// tree so that removing the tree removes it, and an absent record therefore
/// means the tree's provenance is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelTreeState {
    pub config: String,
    pub buildroot_commit: String,
    pub kernel_commit: String,
}

impl KernelTreeState {
    fn render(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.config, self.buildroot_commit, self.kernel_commit
        )
    }

    /// Reads back a state written by [`KernelTreeState::render`]. Anything else
    /// — a truncated write, or an earlier format — leaves provenance unknown.
    fn parse(contents: &str) -> Option<Self> {
        let mut lines = contents.lines();
        let config = lines.next()?.trim();
        let buildroot_commit = lines.next()?.trim();
        let kernel_commit = lines.next()?.trim();

        if config.is_empty() || buildroot_commit.is_empty() || kernel_commit.is_empty() {
            return None;
        }

        Some(Self {
            config: config.to_string(),
            buildroot_commit: buildroot_commit.to_string(),
            kernel_commit: kernel_commit.to_string(),
        })
    }

    fn marker(buildroot_dir: &Path) -> PathBuf {
        buildroot_dir.join(KERNEL_TREE_DIR).join(KERNEL_TREE_MARKER)
    }

    pub fn read(buildroot_dir: &Path) -> Option<Self> {
        Self::parse(&std::fs::read_to_string(Self::marker(buildroot_dir)).unwrap_or_default())
    }

    /// Records this state against the kernel tree at `buildroot_dir`.
    ///
    /// Every step that leaves a configured kernel tree behind calls this, so a
    /// tree produced by an image build is as recognisable as one produced by an
    /// upgrade and neither has to rebuild what the other already configured.
    pub fn save(&self, buildroot_dir: &Path) -> Result<()> {
        let marker = Self::marker(buildroot_dir);
        std::fs::write(&marker, self.render())
            .with_context(|| format!("Failed to write {}", marker.display()))
    }
}

/// Whether the kernel build tree has to be removed before it can be configured.
pub fn needs_dirclean(previous: Option<&KernelTreeState>, current: &KernelTreeState) -> bool {
    previous.is_none_or(|previous| previous != current)
}

/// Commit of the kernel source a buildroot configuration pins.
///
/// Read from the configuration rather than from the `rpi-linux` checkout so
/// that it names the source the build will actually take, whether buildroot
/// fetches the tarball or rsyncs the submodule held at that same commit.
/// Accepts a `.config` or a defconfig, which carry the same key.
pub fn kernel_commit_from_config(config: &str) -> Option<String> {
    let url = config
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION=")
        })?
        .trim()
        .trim_matches('"');

    let commit = url.rsplit('/').next()?.strip_suffix(".tar.gz")?;

    // A release tarball is named for its version, not a commit; only a hex name
    // identifies the source precisely enough to compare two trees by.
    (!commit.is_empty() && commit.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| commit.to_string())
}

fn check_buildroot_state(current: &BuildState, state_file: &Path) -> bool {
    let contents = std::fs::read_to_string(state_file).unwrap_or_default();
    let previous = BuildState::parse(&contents);

    if !needs_clean(previous.as_ref(), current) {
        return false;
    }

    println!();
    match previous {
        None => println!(
            "{}",
            "⚠ Build tree provenance unknown - forcing full clean...".yellow()
        ),
        Some(previous) if previous.config != current.config => println!(
            "{}",
            format!(
                "⚠ Configuration changed from {} to {} - forcing full clean...",
                previous.config, current.config
            )
            .yellow()
        ),
        Some(previous) => println!(
            "{}",
            format!(
                "⚠ Buildroot changed from {} to {} - forcing full clean...",
                &previous.buildroot_commit[..12.min(previous.buildroot_commit.len())],
                &current.buildroot_commit[..12.min(current.buildroot_commit.len())]
            )
            .yellow()
        ),
    }

    true
}

/// Written only after a successful build, so a build that dies partway leaves
/// the tree marked as unbuildable-from rather than as matching the new state.
fn save_buildroot_state(state: &BuildState, state_file: &Path) -> Result<()> {
    std::fs::write(state_file, state.render()).context("Failed to save buildroot state file")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(config: &str, commit: &str) -> BuildState {
        BuildState {
            config: config.to_string(),
            buildroot_commit: commit.to_string(),
        }
    }

    #[test]
    fn an_unchanged_config_and_buildroot_extends_the_tree() {
        let current = state("russignol_hardened_defconfig", "313414b92c25");

        assert!(!needs_clean(Some(&current.clone()), &current));
    }

    #[test]
    fn switching_config_discards_the_tree() {
        let previous = state("russignol_defconfig", "313414b92c25");
        let current = state("russignol_hardened_defconfig", "313414b92c25");

        assert!(needs_clean(Some(&previous), &current));
    }

    #[test]
    fn bumping_buildroot_discards_the_tree() {
        // Same config, moved buildroot: the tree holds packages and host tools
        // the new buildroot did not produce.
        let previous = state("russignol_hardened_defconfig", "313414b92c25");
        let current = state("russignol_hardened_defconfig", "a1b2c3d4e5f6");

        assert!(needs_clean(Some(&previous), &current));
    }

    #[test]
    fn an_unrecorded_tree_is_discarded() {
        assert!(needs_clean(None, &state("russignol_defconfig", "313414b")));
    }

    #[test]
    fn state_survives_a_write_and_read_back() {
        let current = state("russignol_hardened_defconfig", "313414b92c25");

        assert_eq!(BuildState::parse(&current.render()), Some(current));
    }

    const HARDENED: &str = "russignol_hardened_defconfig";

    fn kernel_state(config: &str, buildroot: &str, kernel: &str) -> KernelTreeState {
        KernelTreeState {
            config: config.to_string(),
            buildroot_commit: buildroot.to_string(),
            kernel_commit: kernel.to_string(),
        }
    }

    #[test]
    fn the_pinned_tarball_names_the_kernel_source_commit() {
        let config = "BR2_LINUX_KERNEL=y\nBR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION=\"https://github.com/raspberrypi/linux/archive/825dba6c63eeb40a62699d1f8a4aa3f02b0eaf49.tar.gz\"\nBR2_LINUX_KERNEL_GZIP=y\n";

        assert_eq!(
            kernel_commit_from_config(config).as_deref(),
            Some("825dba6c63eeb40a62699d1f8a4aa3f02b0eaf49")
        );
    }

    #[test]
    fn a_version_named_tarball_pins_no_commit() {
        // A release tarball names its version, which cannot tell two trees apart
        // the way a commit does.
        let config = "BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION=\"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.tar.gz\"\n";

        assert_eq!(kernel_commit_from_config(config), None);
    }

    #[test]
    fn a_config_without_a_custom_tarball_pins_no_commit() {
        assert_eq!(kernel_commit_from_config("BR2_LINUX_KERNEL=y\n"), None);
    }

    #[test]
    fn a_kernel_tree_built_from_the_same_inputs_is_kept() {
        let current = kernel_state(HARDENED, "cb857ba4c87a", "825dba6c63ee");

        assert!(!needs_dirclean(Some(&current.clone()), &current));
    }

    #[test]
    fn moving_the_kernel_source_discards_the_kernel_tree() {
        let previous = kernel_state(HARDENED, "cb857ba4c87a", "f2f1e849f4fe");
        let current = kernel_state(HARDENED, "cb857ba4c87a", "825dba6c63ee");

        assert!(needs_dirclean(Some(&previous), &current));
    }

    #[test]
    fn bumping_buildroot_discards_the_kernel_tree() {
        // Buildroot's kconfig fixups are applied at configure time, so the same
        // source under a different buildroot is a different configured tree.
        let previous = kernel_state(HARDENED, "313414b92c25", "825dba6c63ee");
        let current = kernel_state(HARDENED, "cb857ba4c87a", "825dba6c63ee");

        assert!(needs_dirclean(Some(&previous), &current));
    }

    #[test]
    fn switching_config_discards_the_kernel_tree() {
        let previous = kernel_state("russignol_defconfig", "cb857ba4c87a", "825dba6c63ee");
        let current = kernel_state(HARDENED, "cb857ba4c87a", "825dba6c63ee");

        assert!(needs_dirclean(Some(&previous), &current));
    }

    #[test]
    fn an_unrecorded_kernel_tree_is_discarded() {
        let current = kernel_state(HARDENED, "cb857ba4c87a", "825dba6c63ee");

        assert!(needs_dirclean(None, &current));
    }

    #[test]
    fn kernel_state_survives_a_write_and_read_back() {
        let current = kernel_state(HARDENED, "cb857ba4c87a", "825dba6c63ee");

        assert_eq!(KernelTreeState::parse(&current.render()), Some(current));
    }

    #[test]
    fn a_partial_kernel_state_reads_as_unknown() {
        assert_eq!(KernelTreeState::parse(""), None);
        assert_eq!(
            KernelTreeState::parse("russignol_hardened_defconfig\ncb857ba4c87a\n"),
            None
        );
        assert_eq!(
            KernelTreeState::parse("russignol_hardened_defconfig\ncb857ba4c87a\n\n"),
            None
        );
    }

    #[test]
    fn the_config_only_format_reads_as_unknown() {
        // Written before buildroot commits were tracked; the tree behind it may
        // have been produced by any buildroot version.
        assert_eq!(BuildState::parse("russignol_defconfig\n"), None);
        assert_eq!(BuildState::parse(""), None);
        assert_eq!(BuildState::parse("russignol_defconfig\n\n"), None);
    }

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
