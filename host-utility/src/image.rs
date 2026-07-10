//! SD card image download and flash functionality
//!
//! This module provides commands to download russignol SD card images
//! and flash them to removable storage devices.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Select, Text};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config;
use crate::constants::ORANGE_256;
use crate::device_access::{self, FlashPrivilege};
use crate::restore_keys;
use crate::utils::{
    self, JsonValueExt, create_http_agent, create_orange_theme, format_with_separators,
    print_title_bar,
};
use crate::version;
use crate::watermark;
use russignol_flash_manifest::{FlashManifest, MANIFEST_FILENAME};

/// Download metadata resolved from URL or release info
struct DownloadInfo {
    url: String,
    checksum: Option<String>,
    compressed_size: Option<u64>,
    uncompressed_size: Option<u64>,
    version: Option<String>,
    channel: Option<String>,
    /// Detached maintainer signature (hex) over the image SHA-256
    signature: Option<String>,
}

impl DownloadInfo {
    /// Metadata for a custom `--url` download: no release info is available,
    /// so everything beyond the URL is unknown.
    fn from_custom_url(url: String) -> Self {
        Self {
            url,
            checksum: None,
            compressed_size: None,
            uncompressed_size: None,
            version: None,
            channel: None,
            signature: None,
        }
    }

    /// Metadata for a release download, mapped from the fetched image info
    fn from_release(url: String, version: &str, image: &version::ImageInfo) -> Self {
        let channel = if version.contains('-') {
            "beta"
        } else {
            "stable"
        };
        Self {
            url,
            checksum: Some(image.sha256.clone()),
            compressed_size: Some(image.compressed_size_bytes),
            uncompressed_size: Some(image.size_bytes),
            version: Some(version.to_string()),
            channel: Some(channel.to_string()),
            signature: image.signature.clone(),
        }
    }
}

/// Image provenance metadata threaded through flash pipelines
pub struct FlashMetadata {
    pub image_sha256: String,
    pub image_version: Option<String>,
    pub channel: Option<String>,
}

/// Generate a 128-bit random card ID as a 32-character hex string
pub fn generate_card_id() -> Result<String> {
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read as _;
            f.read_exact(&mut buf)
        })
        .context("Failed to read /dev/urandom")?;
    Ok(buf.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    }))
}

/// Compute SHA-256 hash of a file, returning the hex digest
pub fn compute_file_sha256(path: &Path) -> Result<String> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .context("Failed to read file for hashing")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Write a flash manifest to the boot partition (p1, FAT32)
///
/// Generates a unique `card_id`, builds the manifest with current timestamp
/// and host version, writes it as JSON, and returns the `card_id`.
/// `rootfs_sha256` is the hash teed off the flash's write stream, so the
/// manifest records the bytes that actually went to the card.
pub fn write_flash_manifest(
    device: &Path,
    metadata: &FlashMetadata,
    rootfs_sha256: Option<String>,
) -> Result<String> {
    let boot_partition = utils::get_partition_path(device, 1);
    let mount_point = utils::mount_partition(&boot_partition, "vfat", false)?;

    let card_id = generate_card_id()?;
    let manifest = FlashManifest {
        card_id: card_id.clone(),
        flashed_at: chrono::Utc::now().to_rfc3339(),
        host_version: version::VERSION.to_string(),
        image_sha256: metadata.image_sha256.clone(),
        image_version: metadata.image_version.clone(),
        channel: metadata.channel.clone(),
        rootfs_sha256,
    };

    let json =
        serde_json::to_string_pretty(&manifest).context("Failed to serialize flash manifest")?;
    let manifest_path = mount_point.join(MANIFEST_FILENAME);

    if let Err(e) = std::fs::write(&manifest_path, &json) {
        utils::warn_if_err(
            utils::unmount_partition(&mount_point, &boot_partition),
            "Failed to unmount after a failed manifest write",
        );
        return Err(anyhow::anyhow!(
            "Failed to write {}: {e}",
            manifest_path.display()
        ));
    }

    utils::unmount_partition(&mount_point, &boot_partition)?;
    Ok(card_id)
}

/// Read the `card_id` from a flash manifest on the boot partition
///
/// Returns `None` on any failure (missing partition, mount error, parse error,
/// missing field) — failure means "different card" for same-card detection.
pub fn read_card_id(device: &Path) -> Option<String> {
    let boot_partition = utils::get_partition_path(device, 1);
    if !boot_partition.exists() {
        return None;
    }

    let Ok(mount_point) = utils::mount_partition(&boot_partition, "vfat", true) else {
        return None;
    };

    let manifest_path = mount_point.join(MANIFEST_FILENAME);
    let result = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|content| serde_json::from_str::<FlashManifest>(&content).ok())
        .map(|m| m.card_id);

    utils::warn_if_err(
        utils::unmount_partition(&mount_point, &boot_partition),
        "Failed to unmount after reading the flash manifest",
    );
    result
}

/// Image subcommands
#[derive(Subcommand, Debug)]
pub enum ImageCommands {
    /// Download the latest russignol SD card image
    Download {
        /// Custom URL to download image from (default: russignol.com)
        #[arg(long)]
        url: Option<String>,

        /// Output file path (default: russignol-<version>.img.xz in current directory)
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Skip checksum verification (not recommended)
        #[arg(long)]
        skip_verify: bool,

        /// Download the latest beta (pre-release) version
        #[arg(long)]
        beta: bool,
    },

    /// Flash an image to an SD card
    Flash {
        /// Path to the image file (.img.xz or .img)
        image: PathBuf,

        /// Target device (e.g., /dev/sdc or /dev/mmcblk0). Auto-detects if not specified.
        #[arg(long, short)]
        device: Option<PathBuf>,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Skip all confirmation prompts (dangerous!)
        #[arg(long, short = 'y')]
        yes: bool,

        /// Restore keys and watermarks from an existing SD card (Linux only).
        /// Optionally specify the source device, or omit to auto-detect.
        #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
        restore_keys: Option<PathBuf>,

        /// Migrate keys from a Nomadic Labs tezos-rpi-bls-signer card (Linux only).
        /// Optionally specify the source device, or omit to auto-detect.
        #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
        migrate_keys: Option<PathBuf>,

        /// Source key alias to import as the consensus key (migration only;
        /// default: first key)
        #[arg(long)]
        consensus_key: Option<String>,

        /// Source key alias to import as the companion key (migration only;
        /// default: second key)
        #[arg(long)]
        companion_key: Option<String>,

        /// Skip the post-flash read-back verification (faster, not recommended)
        #[arg(long)]
        skip_verify: bool,

        /// Path to the image's detached maintainer signature (.sig). Defaults
        /// to a `<image>.sig` sidecar next to the image when present.
        #[arg(long)]
        signature: Option<PathBuf>,

        /// Flash an image with no verifiable maintainer signature (e.g. a
        /// self-built or dev image). Ignored while no maintainer key is embedded.
        #[arg(long)]
        allow_unsigned: bool,
    },

    /// Download and flash in one step
    DownloadAndFlash {
        /// Custom URL to download image from (default: russignol.com)
        #[arg(long)]
        url: Option<String>,

        /// Target device (e.g., /dev/sdc or /dev/mmcblk0). Auto-detects if not specified.
        #[arg(long, short)]
        device: Option<PathBuf>,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Skip all confirmation prompts (dangerous!)
        #[arg(long, short = 'y')]
        yes: bool,

        /// Restore keys and watermarks from an existing SD card (Linux only).
        /// Optionally specify the source device, or omit to auto-detect.
        #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
        restore_keys: Option<PathBuf>,

        /// Migrate keys from a Nomadic Labs tezos-rpi-bls-signer card (Linux only).
        /// Optionally specify the source device, or omit to auto-detect.
        #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
        migrate_keys: Option<PathBuf>,

        /// Source key alias to import as the consensus key (migration only;
        /// default: first key)
        #[arg(long)]
        consensus_key: Option<String>,

        /// Source key alias to import as the companion key (migration only;
        /// default: second key)
        #[arg(long)]
        companion_key: Option<String>,

        /// Download the latest beta (pre-release) version
        #[arg(long)]
        beta: bool,

        /// Skip the post-flash read-back verification (faster, not recommended)
        #[arg(long)]
        skip_verify: bool,

        /// Flash an image with no verifiable maintainer signature (e.g. a
        /// self-built or dev image). Ignored while no maintainer key is embedded.
        #[arg(long)]
        allow_unsigned: bool,
    },

    /// List available images
    List {
        /// Include beta (pre-release) versions
        #[arg(long)]
        beta: bool,
    },
}

impl ImageCommands {
    /// A plain interactive `download-and-flash` of the latest stable image,
    /// with no key-source, device, or channel overrides.
    pub fn download_and_flash_latest() -> Self {
        Self::DownloadAndFlash {
            url: None,
            device: None,
            endpoint: None,
            yes: false,
            restore_keys: None,
            migrate_keys: None,
            consensus_key: None,
            companion_key: None,
            beta: false,
            skip_verify: false,
            allow_unsigned: false,
        }
    }
}

/// Represents a detected block device
#[derive(Debug, Clone)]
pub struct BlockDevice {
    pub name: String,
    pub path: PathBuf,
    pub transport: String,
    pub size: String,
    pub model: String,
}

impl BlockDevice {
    /// Create a minimal `BlockDevice` from a device path when lookup fails.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            path,
            transport: "unknown".to_string(),
            size: "unknown".to_string(),
            model: "Unknown".to_string(),
        }
    }
}

impl std::fmt::Display for BlockDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} - {} ({}, {})",
            self.path.display(),
            self.model,
            self.size,
            self.transport.to_uppercase()
        )
    }
}

/// Main entry point for image commands
pub fn run_image_command(command: ImageCommands) -> Result<()> {
    match command {
        ImageCommands::Download {
            url,
            output,
            skip_verify,
            beta,
        } => cmd_download(url, output, skip_verify, beta),
        ImageCommands::Flash {
            image,
            device,
            endpoint,
            yes,
            restore_keys,
            migrate_keys,
            consensus_key,
            companion_key,
            skip_verify,
            signature,
            allow_unsigned,
        } => cmd_flash(
            &image,
            device,
            endpoint.as_deref(),
            yes,
            KeySourceArgs {
                restore_keys: restore_keys.as_deref(),
                migrate_keys: migrate_keys.as_deref(),
                consensus_key: consensus_key.as_deref(),
                companion_key: companion_key.as_deref(),
            },
            signature.as_deref(),
            FlashVerification {
                skip_readback: skip_verify,
                allow_unsigned,
            },
        ),
        ImageCommands::DownloadAndFlash {
            url,
            device,
            endpoint,
            yes,
            restore_keys,
            migrate_keys,
            consensus_key,
            companion_key,
            beta,
            skip_verify,
            allow_unsigned,
        } => cmd_download_and_flash(
            url,
            device,
            endpoint.as_deref(),
            yes,
            KeySourceArgs {
                restore_keys: restore_keys.as_deref(),
                migrate_keys: migrate_keys.as_deref(),
                consensus_key: consensus_key.as_deref(),
                companion_key: companion_key.as_deref(),
            },
            beta,
            FlashVerification {
                skip_readback: skip_verify,
                allow_unsigned,
            },
        ),
        ImageCommands::List { beta } => cmd_list(beta),
    }
}

// =============================================================================
// Command implementations
// =============================================================================

/// Check for required flash tools and bail if critical ones are missing
fn check_flash_tools() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut missing = Vec::new();

        // Critical tools - can't proceed without these
        for tool in ["dd", "lsblk"] {
            if utils::resolve_tool(tool).is_none() {
                missing.push(tool);
            }
        }

        if !missing.is_empty() {
            bail!(
                "Required tools not found: {}.\n  \
                 Install with: sudo apt install coreutils util-linux  (Debian/Ubuntu)",
                missing.join(", ")
            );
        }

        // Check for udisksctl (needed for mounting boot partition during watermark config)
        if utils::resolve_tool("udisksctl").is_none() {
            utils::warning(
                "udisksctl not found. Mounting boot partition for watermark config may fail.\n  \
                 Install with: sudo apt install udisks2  (Debian/Ubuntu)\n  \
                             sudo dnf install udisks2  (Fedora)",
            );
        }

        // Check for blkid (used for partition type verification)
        // Note: blkid is often in /sbin which may not be in PATH
        if utils::resolve_tool("blkid").is_none() {
            utils::warning(
                "blkid not found. Partition verification will be skipped.\n  \
                 Install with: sudo apt install util-linux  (Debian/Ubuntu)",
            );
        }

        // Check for findmnt (used to detect already-mounted partitions)
        if utils::resolve_tool("findmnt").is_none() {
            utils::warning(
                "findmnt not found. Auto-mount detection will be skipped.\n  \
                 Install with: sudo apt install util-linux  (Debian/Ubuntu)",
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS uses diskutil which is always available
        // dd is also always available on macOS
    }

    Ok(())
}

/// The config a flash should use for node RPCs: the loaded config with an
/// optional endpoint override, a minimal endpoint-only config when none is
/// loaded, or `None` when neither a config nor an endpoint is available.
fn effective_config(endpoint_override: Option<&str>) -> Option<config::RussignolConfig> {
    let loaded_config = config::RussignolConfig::load().ok();
    match (loaded_config, endpoint_override) {
        (Some(mut cfg), Some(endpoint)) => {
            cfg.rpc_endpoint = endpoint.to_string();
            Some(cfg)
        }
        (Some(cfg), None) => Some(cfg),
        (None, Some(endpoint)) => Some(config::RussignolConfig::minimal_with_endpoint(endpoint)),
        (None, None) => None,
    }
}

/// A validated node context: the chain info the node reported and the config
/// that produced it (carrying any interactively recovered endpoint).
///
/// Downstream node RPCs must use this config rather than re-loading one from
/// disk: a recovered endpoint the user declined to persist exists only here.
struct NodeCheck {
    chain_info: watermark::ChainInfo,
    config: config::RussignolConfig,
}

/// Check node connectivity and fetch chain info for watermark configuration
///
/// Returns `Ok(Some(NodeCheck))` if node is available,
/// Ok(None) if no config exists and no endpoint provided (with warning),
/// or Err if node check fails.
///
/// If `endpoint_override` is provided, it will be used instead of the
/// configured endpoint and no endpoint recovery is offered.
fn check_node_for_watermarks(
    endpoint_override: Option<&str>,
    yes: bool,
) -> Result<Option<NodeCheck>> {
    let effective_config = effective_config(endpoint_override);

    if let Some(mut cfg) = effective_config {
        match watermark::prefetch_chain_info(&cfg) {
            Ok(chain_info) => Ok(Some(NodeCheck {
                chain_info,
                config: cfg,
            })),
            Err(e) => {
                if endpoint_override.is_none()
                    && crate::network::resolve_endpoint_interactively(&mut cfg, yes)?
                {
                    let chain_info = watermark::prefetch_chain_info(&cfg)?;
                    return Ok(Some(NodeCheck {
                        chain_info,
                        config: cfg,
                    }));
                }
                bail!(
                    "Node check failed: {e}. Ensure your node is running before flashing.{}",
                    crate::network::NON_INTERACTIVE_HINT
                );
            }
        }
    } else {
        utils::warning(
            "No russignol configuration found. Watermarks will not be configured.\n  \
             Run 'russignol config' first, or use 'russignol watermark init' after flashing.",
        );
        Ok(None)
    }
}

fn cmd_download(
    url: Option<String>,
    output: Option<PathBuf>,
    skip_verify: bool,
    include_prerelease: bool,
) -> Result<()> {
    println!();
    print_title_bar("📥 Download SD Card Image");

    let (download_url, expected_checksum, compressed_size) = if let Some(custom_url) = url {
        utils::info(&format!("Using custom URL: {custom_url}"));
        (custom_url, None, None)
    } else {
        // Fetch version info to get image details
        utils::info("Fetching latest version info...");
        let version_info =
            version::fetch_latest_version(include_prerelease, version::RequiredAsset::Image)
                .context("Failed to fetch version info from russignol.com")?;

        let image_info = version_info.images.get("pi-zero").context(
            "No pi-zero image found in version info. Use --url to specify a direct download URL.",
        )?;

        let url = version::get_image_download_url(&version_info, "pi-zero")?;
        utils::success(&format!(
            "Found image: {} ({})",
            image_info.filename,
            format_bytes(image_info.compressed_size_bytes)
        ));

        (
            url,
            Some(image_info.sha256.clone()),
            Some(image_info.compressed_size_bytes),
        )
    };

    // Determine output path
    let output_path = output.unwrap_or_else(|| {
        let filename = get_filename_from_url(&download_url);
        PathBuf::from(filename)
    });

    // Download with caching
    let checksum = if skip_verify {
        None
    } else {
        let cs = expected_checksum.as_deref().filter(|s| !s.is_empty());
        if cs.is_none() {
            bail!(
                "Checksum not available for this release.\n\
                 Use --skip-verify to download without verification (not recommended)."
            );
        }
        cs
    };
    let cached_path = download_with_cache(&download_url, checksum, compressed_size)?;

    // Copy to output location if different from cache
    if cached_path == output_path {
        utils::success(&format!("Image available at: {}", cached_path.display()));
    } else {
        std::fs::copy(&cached_path, &output_path)
            .with_context(|| format!("Failed to save image to {}", output_path.display()))?;
        utils::success(&format!("Image saved to: {}", output_path.display()));
    }
    println!();

    Ok(())
}

/// Shared keyed-flash logic (restore or migrate) used by both `cmd_flash` and
/// `cmd_download_and_flash`. The `source` selects how the key material is read
/// and how a physical card is identified for the single-reader swap guard;
/// everything downstream is shared.
fn run_keyed_flash(
    source: &dyn restore_keys::CardSource,
    restore_source: &Path,
    device: Option<PathBuf>,
    job: restore_keys::FlashJob<'_>,
) -> Result<()> {
    restore_keys::check_restore_tools()?;
    utils::ensure_mount_capability();

    // A failed enumeration must not be flattened to "no devices" — that would
    // silently flip the single-vs-dual reader decision below.
    let detected = detect_removable_devices()
        .context("Could not enumerate removable devices to determine reader mode")?;
    let single_reader =
        restore_keys::is_single_reader_mode(restore_source, device.as_deref(), &detected);

    if single_reader {
        return restore_keys::run_single_reader_restore(source, restore_source, job);
    }

    // Dual reader: resolve the target and probe write access before the
    // source card is read — recovery may re-exec the process (sg), which
    // restarts the flow from scratch.
    let target = if let Some(dev) = device {
        utils::info(&format!("Using specified device: {}", dev.display()));
        let target = lookup_block_device(&dev).unwrap_or_else(|_| BlockDevice::from_path(dev));
        warn_if_partition(&target);
        target
    } else {
        let target = detected
            .into_iter()
            .find(|d| d.path != *restore_source)
            .context("No target device found. Use --device to specify the target SD card.")?;
        utils::info(&format!("Using target device: {}", target.path.display()));
        target
    };

    check_device_not_mounted(&target.path)?;
    check_device_has_media(&target.path)?;
    let privilege = device_access::probe_write_access(&target.path, Some(&target.path), job.yes)?;

    let backup = source.read(restore_source)?;

    if !restore_keys::warn_network_mismatch(&backup, job.chain_info, job.yes)? {
        utils::info(&format!(
            "{} cancelled",
            restore_keys::uppercase_first(source.noun())
        ));
        println!();
        return Ok(());
    }

    restore_keys::run_dual_reader_restore(&target, &backup, source.noun(), job, privilege)
}

/// Where a keyed flash gets its key material. Both `flash` and
/// `download-and-flash` accept the same options; at most one of `restore_keys`
/// / `migrate_keys` may be set.
#[derive(Clone, Copy)]
struct KeySourceArgs<'a> {
    restore_keys: Option<&'a Path>,
    migrate_keys: Option<&'a Path>,
    consensus_key: Option<&'a str>,
    companion_key: Option<&'a str>,
}

/// Write-time verification policy for a flash: whether to skip the post-flash
/// read-back, and whether to permit an image that carries no maintainer
/// signature.
#[derive(Clone, Copy)]
struct FlashVerification {
    skip_readback: bool,
    allow_unsigned: bool,
}

/// Reject `--restore-keys` and `--migrate-keys` used together: each selects a
/// different key source for the same flash, so only one may be given.
fn check_key_source_exclusive(
    restore_keys: Option<&Path>,
    migrate_keys: Option<&Path>,
) -> Result<()> {
    if restore_keys.is_some() && migrate_keys.is_some() {
        bail!("--restore-keys and --migrate-keys cannot be used together; choose one source");
    }
    Ok(())
}

/// Resolve the requested key source to a `CardSource` plus its device path, or
/// `None` when neither `--restore-keys` nor `--migrate-keys` was given.
///
/// For migration this prompts for the source/new PINs and verifies the eCryptfs
/// toolchain, so it runs before any download or destructive work. `config` is
/// the node-checked config selecting the node used to label the migrated keys
/// by their on-chain roles.
fn resolve_key_source(
    keys: KeySourceArgs<'_>,
    config: Option<&config::RussignolConfig>,
) -> Result<Option<(Box<dyn restore_keys::CardSource>, PathBuf)>> {
    if let Some(arg) = keys.migrate_keys {
        let device = restore_keys::resolve_restore_source(arg)?;
        let source = crate::migrate_keys::MigrateSource::prompt(
            keys.consensus_key.map(str::to_string),
            keys.companion_key.map(str::to_string),
            config.cloned(),
        )?;
        Ok(Some((Box::new(source), device)))
    } else if let Some(arg) = keys.restore_keys {
        let device = restore_keys::resolve_restore_source(arg)?;
        Ok(Some((Box::new(restore_keys::RestoreSource), device)))
    } else {
        Ok(None)
    }
}

/// Enforce the maintainer release-signature policy before any destructive
/// write: verify the image's signature against the embedded maintainer key and
/// refuse on mismatch; flashing an image that carries no signature requires
/// `--allow-unsigned`. A build without an embedded key proceeds silently.
fn enforce_release_signature(
    image_sha256: &str,
    signature: Option<&str>,
    allow_unsigned: bool,
) -> Result<()> {
    use crate::release_signature::{MAINTAINER_PUBKEY, SignatureVerdict, check_release_signature};

    match check_release_signature(
        MAINTAINER_PUBKEY.as_ref(),
        image_sha256,
        signature,
        allow_unsigned,
    ) {
        Ok(SignatureVerdict::Verified) => {
            utils::success("Maintainer release signature verified");
            Ok(())
        }
        // A build without an embedded key has nothing to verify against.
        Ok(SignatureVerdict::Unavailable) => Ok(()),
        Ok(SignatureVerdict::UnsignedAllowed) => {
            utils::warning("Flashing an unsigned image (--allow-unsigned)");
            Ok(())
        }
        Err(e) => bail!("Refusing to flash: {e}"),
    }
}

/// Resolve the detached maintainer signature for a locally-supplied image: an
/// explicit `--signature` path wins; otherwise a `<image>.sig` sidecar next to
/// the image is used when present; otherwise there is no signature.
///
/// The signer writes a single hex line with a trailing newline, so the content
/// is trimmed.
///
/// # Errors
///
/// Fails when a signature file that should exist cannot be read: an explicit
/// path (the operator claimed a signature exists) or a present sidecar.
fn resolve_local_signature(image: &Path, explicit: Option<&Path>) -> Result<Option<String>> {
    let path = if let Some(path) = explicit {
        path.to_path_buf()
    } else {
        let sidecar = russignol_release_signature::sidecar_path(image);
        if !sidecar.exists() {
            return Ok(None);
        }
        sidecar
    };
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read signature file {}", path.display()))?;
    Ok(Some(content.trim().to_string()))
}

fn cmd_flash(
    image: &Path,
    device: Option<PathBuf>,
    endpoint: Option<&str>,
    yes: bool,
    keys: KeySourceArgs<'_>,
    signature_path: Option<&Path>,
    verification: FlashVerification,
) -> Result<()> {
    check_key_source_exclusive(keys.restore_keys, keys.migrate_keys)?;

    // Check for required tools first
    check_flash_tools()?;

    // Early validation before any output
    if !image.exists() {
        bail!("Image file not found: {}", image.display());
    }
    if let Some(ref dev) = device
        && !dev.exists()
    {
        bail!("Device not found: {}", dev.display());
    }
    let signature = resolve_local_signature(image, signature_path)?;

    // Compute image hash for manifest
    utils::info("Computing image hash...");
    let image_sha256 = compute_file_sha256(image)?;

    // Runs before device selection so nothing is written on refusal.
    enforce_release_signature(
        &image_sha256,
        signature.as_deref(),
        verification.allow_unsigned,
    )?;

    // Check node FIRST - fail fast if node is unavailable
    let node_check = check_node_for_watermarks(endpoint, yes)?;

    // A local image carries no release metadata beyond its own hash.
    let metadata = FlashMetadata {
        image_sha256,
        image_version: None,
        channel: None,
    };

    // Keyed path: restore or migrate (mutually exclusive, checked above)
    if let Some((source, source_device)) =
        resolve_key_source(keys, node_check.as_ref().map(|nc| &nc.config))?
    {
        println!();
        let suffix = if keys.migrate_keys.is_some() {
            "migration"
        } else {
            "restore"
        };
        print_title_bar(&format!("💾 Flash SD Card (with key {suffix})"));
        let node_check = node_check.as_ref().context(
            "Node check required to write keys but no configuration found.\n  \
             Run 'russignol config' first, or use --endpoint to specify your node.",
        )?;
        return run_keyed_flash(
            source.as_ref(),
            &source_device,
            device,
            restore_keys::FlashJob {
                image,
                uncompressed_size: None,
                yes,
                metadata: &metadata,
                chain_info: &node_check.chain_info,
            },
        );
    }

    // Normal path
    println!();
    print_title_bar("💾 Flash SD Card");

    // Detect or use provided device
    let target_device = if let Some(dev) = device {
        user_specified_device(dev)
    } else {
        select_device()?
    };

    // Check if mounted, has media, and is writable by this process
    check_device_not_mounted(&target_device.path)?;
    check_device_has_media(&target_device.path)?;
    let privilege =
        device_access::probe_write_access(&target_device.path, Some(&target_device.path), yes)?;

    // Safety confirmation
    if !confirm_flash_operation(&target_device, yes)? {
        utils::info("Flash cancelled");
        println!();
        return Ok(());
    }

    // Perform the flash (no size hint for local files)
    let view = finish_normal_flash(
        image,
        &target_device.path,
        None,
        privilege,
        verification.skip_readback,
        &metadata,
        node_check.as_ref().map(|nc| &nc.chain_info),
    )?;
    conclude_flash(&target_device.path, view, yes)
}

/// Shared tail of both normal (non-keyed) flash paths: write the image, read it
/// back to confirm the write, refresh the partition table, record the manifest,
/// and finalize. Kept in one place so the two entry points cannot diverge.
fn finish_normal_flash(
    image: &Path,
    device: &Path,
    expected_size: Option<u64>,
    privilege: FlashPrivilege,
    skip_verify: bool,
    metadata: &FlashMetadata,
    chain_info: Option<&watermark::ChainInfo>,
) -> Result<HostPartitionView> {
    let rootfs_sha256 = flash_image_to_device(image, device, expected_size, privilege)?;

    // Read the card back and confirm it matches before declaring success.
    verify_flash_or_note_skip(image, device, skip_verify)?;

    // Refresh the kernel's partition table where possible; a non-root run leaves
    // it stale and reports so, so the optional verify below can drive a re-plug.
    let view = reread_partition_table(device);

    // The manifest and config only touch p1, whose offset is unchanged by the
    // flash, so they write correctly regardless of the stale view above.
    write_flash_manifest(device, metadata, rootfs_sha256)
        .context("Failed to write flash manifest")?;

    finalize_flash(device, chain_info)?;
    Ok(view)
}

/// Shared conclusion for both normal flash paths: offer the optional structural
/// verify, then point the user at the Pi. One place so the two entry points end
/// identically.
fn conclude_flash(device: &Path, view: HostPartitionView, yes: bool) -> Result<()> {
    offer_structural_verify(device, view, yes)?;
    println!("  You can now insert the SD card into your Raspberry Pi Zero 2W.");
    Ok(())
}

/// Write watermark config (if available), verify it, and print flash success message
fn finalize_flash(device: &Path, chain_info: Option<&watermark::ChainInfo>) -> Result<()> {
    println!();
    if let Some(info) = chain_info {
        watermark::write_watermark_config(device, info)
            .context("Failed to write watermark config")?;

        let written = watermark::read_back_and_verify(device)?;

        utils::success("Flash complete!");
        println!(
            "  Chain:       {} ({})",
            written.chain.name.cyan(),
            written.chain.id.cyan()
        );
        println!(
            "  Head Level:  {}",
            format_with_separators(written.chain.level).cyan()
        );
        println!();
    } else {
        utils::success(
            "Flash complete! (no watermark config - run 'russignol watermark init' later)",
        );
        println!();
    }

    Ok(())
}

/// Resolve download URL and metadata from custom URL or latest release
fn resolve_download_info(url: Option<String>, include_prerelease: bool) -> Result<DownloadInfo> {
    if let Some(custom_url) = url {
        utils::info(&format!("Using custom URL: {custom_url}"));
        Ok(DownloadInfo::from_custom_url(custom_url))
    } else {
        utils::info("Fetching latest version info...");
        let version_info =
            version::fetch_latest_version(include_prerelease, version::RequiredAsset::Image)
                .context("Failed to fetch version info from russignol.com")?;

        let image_info = version_info
            .images
            .get("pi-zero")
            .context("No pi-zero image found. Use --url to specify a direct download URL.")?;

        let url = version::get_image_download_url(&version_info, "pi-zero")?;
        utils::success(&format!(
            "Found image: {} ({})",
            image_info.filename,
            format_bytes(image_info.compressed_size_bytes)
        ));

        Ok(DownloadInfo::from_release(
            url,
            &version_info.version,
            image_info,
        ))
    }
}

/// Resolve the rootfs hash teed off the flash's write stream, or warn and
/// record nothing. The hash only feeds the device's advisory integrity check,
/// so a nonstandard image (e.g. an experimental layout) must still flash.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rootfs_hash_or_warn(hash: Result<String>) -> Option<String> {
    match hash {
        Ok(hash) => Some(hash),
        Err(e) => {
            utils::warning(&format!(
                "Could not compute the rootfs hash ({e}); \
                 the device will skip its rootfs integrity check"
            ));
            None
        }
    }
}

/// Shared trust gate of both `download-and-flash` paths: download the image
/// with its release checksum, verify the downloaded file's hash against it,
/// and enforce the maintainer signature policy. Returns the cached image path
/// and the flash metadata built from the verified download. Kept in one place
/// so the two entry points cannot diverge.
fn download_and_verify_release_image(
    dl: &DownloadInfo,
    allow_unsigned: bool,
) -> Result<(PathBuf, FlashMetadata)> {
    let checksum = dl.checksum.as_deref().filter(|s| !s.is_empty()).context(
        "Checksum not available for this release. Cannot safely flash without verification.",
    )?;
    let image_path = download_with_cache(&dl.url, Some(checksum), dl.compressed_size)?;

    // Compute hash from the downloaded file and verify against release checksum
    utils::info("Computing image hash...");
    let image_sha256 = compute_file_sha256(&image_path)?;
    if image_sha256 != checksum {
        bail!(
            "Image hash mismatch after download!\n  Expected: {checksum}\n  Got:      {image_sha256}"
        );
    }

    enforce_release_signature(&image_sha256, dl.signature.as_deref(), allow_unsigned)?;

    let metadata = FlashMetadata {
        image_sha256,
        image_version: dl.version.clone(),
        channel: dl.channel.clone(),
    };
    Ok((image_path, metadata))
}

fn cmd_download_and_flash(
    url: Option<String>,
    device: Option<PathBuf>,
    endpoint: Option<&str>,
    yes: bool,
    keys: KeySourceArgs<'_>,
    include_prerelease: bool,
    verification: FlashVerification,
) -> Result<()> {
    check_key_source_exclusive(keys.restore_keys, keys.migrate_keys)?;

    // Check for required tools first
    check_flash_tools()?;

    // Early validation before any output
    if let Some(ref dev) = device
        && !dev.exists()
    {
        bail!("Device not found: {}", dev.display());
    }
    // Check node FIRST - fail fast if node is unavailable
    let node_check = check_node_for_watermarks(endpoint, yes)?;

    // Keyed path: restore or migrate (mutually exclusive, checked above)
    if let Some((source, source_device)) =
        resolve_key_source(keys, node_check.as_ref().map(|nc| &nc.config))?
    {
        println!();
        let suffix = if keys.migrate_keys.is_some() {
            "migration"
        } else {
            "restore"
        };
        print_title_bar(&format!(
            "📥💾 Download and Flash SD Card (with key {suffix})"
        ));

        // Download first (can happen before touching cards)
        let dl = resolve_download_info(url, include_prerelease)?;
        let (image_path, metadata) =
            download_and_verify_release_image(&dl, verification.allow_unsigned)?;

        let node_check = node_check.as_ref().context(
            "Node check required to write keys but no configuration found.\n  \
             Run 'russignol config' first, or use --endpoint to specify your node.",
        )?;
        return run_keyed_flash(
            source.as_ref(),
            &source_device,
            device,
            restore_keys::FlashJob {
                image: &image_path,
                uncompressed_size: dl.uncompressed_size,
                yes,
                metadata: &metadata,
                chain_info: &node_check.chain_info,
            },
        );
    }

    // Normal path
    println!();
    print_title_bar("📥💾 Download and Flash SD Card");

    // Detect/select device
    let target_device = if let Some(dev) = device {
        user_specified_device(dev)
    } else {
        select_device()?
    };

    // Check if mounted, has media, and is writable by this process
    check_device_not_mounted(&target_device.path)?;
    check_device_has_media(&target_device.path)?;
    let privilege =
        device_access::probe_write_access(&target_device.path, Some(&target_device.path), yes)?;

    // Get download info (uncompressed_size is used for progress bar during flash)
    let dl = resolve_download_info(url, include_prerelease)?;

    // Safety confirmation BEFORE downloading
    if !confirm_flash_operation(&target_device, yes)? {
        utils::info("Flash cancelled");
        println!();
        return Ok(());
    }

    // Download with caching and resume support (checksum required for flash)
    let (image_path, metadata) =
        download_and_verify_release_image(&dl, verification.allow_unsigned)?;

    // Flash the downloaded image
    let view = finish_normal_flash(
        &image_path,
        &target_device.path,
        dl.uncompressed_size,
        privilege,
        verification.skip_readback,
        &metadata,
        node_check.as_ref().map(|nc| &nc.chain_info),
    )?;
    conclude_flash(&target_device.path, view, yes)
}

fn cmd_list(include_prerelease: bool) -> Result<()> {
    println!();
    print_title_bar("📋 Available Images");

    utils::info("Fetching version info from russignol.com...");
    let version_info =
        version::fetch_latest_version(include_prerelease, version::RequiredAsset::Image)
            .context("Failed to fetch version info")?;

    println!();
    println!("  Version: {}", version_info.version);
    println!("  Release: {}", version_info.release_date);
    println!();

    if version_info.images.is_empty() {
        utils::warning("No images available in this release");
    } else {
        println!("  Available images:");
        for (target, info) in &version_info.images {
            println!();
            println!("    Target: {target}");
            println!("    File:   {}", info.filename);
            println!(
                "    Size:   {} (compressed: {})",
                format_bytes(info.size_bytes),
                format_bytes(info.compressed_size_bytes)
            );
            if info.min_sd_size_gb > 0 {
                println!("    Min SD: {} GB", info.min_sd_size_gb);
            }
        }
    }

    println!();
    Ok(())
}

// =============================================================================
// Device detection
// =============================================================================

/// Detect removable SD card devices (USB card readers and built-in MMC readers)
pub fn detect_removable_devices() -> Result<Vec<BlockDevice>> {
    #[cfg(target_os = "linux")]
    {
        detect_removable_devices_linux()
    }
    #[cfg(target_os = "macos")]
    {
        detect_removable_devices_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("Device detection not supported on this platform. Use --device to specify manually.")
    }
}

#[cfg(target_os = "linux")]
fn detect_removable_devices_linux() -> Result<Vec<BlockDevice>> {
    let output = Command::new("lsblk")
        .args(["-d", "-o", "NAME,TYPE,TRAN,RM,SIZE,MODEL", "--json"])
        .output()
        .context("Failed to run lsblk")?;

    if !output.status.success() {
        bail!("lsblk failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse lsblk JSON output")?;

    Ok(filter_removable_devices(&json))
}

/// Normalize the lsblk transport for a device.
///
/// util-linux reports TRAN "mmc" for mmcblk devices only since v2.39; older
/// versions report null. Store "mmc" for mmcblk-named devices either way so
/// filtering and display see one transport regardless of lsblk version.
fn normalize_transport(name: &str, tran: Option<&str>) -> String {
    match tran {
        Some(t) if !t.is_empty() => t.to_string(),
        _ if name.starts_with("mmcblk") => "mmc".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Whether a device name refers to a partition rather than a whole disk
/// (e.g. sdc1, mmcblk0p1, nvme0n1p3). Flashing writes a full disk image, so
/// a partition target produces a card that cannot boot.
fn looks_like_partition(name: &str) -> bool {
    // sda1 style: sd + letters + trailing digits
    if let Some(rest) = name.strip_prefix("sd") {
        let digits = rest.trim_start_matches(|c: char| c.is_ascii_lowercase());
        return !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit());
    }
    // mmcblk0p1 / nvme0n1p3 / loop0p1 style: <disk ending in digit> + p + digits
    if let Some(p_idx) = name.rfind('p') {
        let (before, after_p) = name.split_at(p_idx);
        let digits = &after_p[1..];
        return before.ends_with(|c: char| c.is_ascii_digit())
            && !digits.is_empty()
            && digits.chars().all(|c| c.is_ascii_digit());
    }
    false
}

/// Warn when an explicitly given device names a partition: flashing writes a
/// whole-disk image, so the result would not boot.
fn warn_if_partition(device: &BlockDevice) {
    if looks_like_partition(&device.name) {
        utils::warning(&format!(
            "{} looks like a partition, not a whole disk. Flashing writes a \
             whole-disk image; a card flashed to a partition will not boot. \
             Use the parent disk device instead.",
            device.path.display()
        ));
    }
}

/// Wrap an explicitly given `--device` path in a `BlockDevice`.
fn user_specified_device(dev: PathBuf) -> BlockDevice {
    utils::info(&format!("Using specified device: {}", dev.display()));
    let mut device = BlockDevice::from_path(dev);
    device.model = "User specified".to_string();
    warn_if_partition(&device);
    device
}

/// Filter parsed `lsblk -d -o NAME,TYPE,TRAN,RM,SIZE,MODEL --json` output
/// down to flashable removable devices.
#[cfg(target_os = "linux")]
fn filter_removable_devices(json: &serde_json::Value) -> Vec<BlockDevice> {
    let mut devices = Vec::new();

    if let Some(blockdevices) = json.get_nested("blockdevices").and_then(|v| v.as_array()) {
        for dev in blockdevices {
            let name = dev.get_str("name").unwrap_or("");
            let dev_type = dev.get_str("type").unwrap_or("");
            let transport = normalize_transport(name, dev.get_str("tran"));
            let rm = dev.get_bool("rm").unwrap_or(false);
            let size = dev.get_str("size").unwrap_or("0");
            let model = dev.get_str("model").unwrap_or("Unknown");

            // Filter: must be a removable disk in a USB card reader or a
            // built-in (SDHCI/MMC) reader; non-removable eMMC is excluded
            // Also filter out empty slots (size = "0B")
            if dev_type == "disk"
                && rm
                && (transport == "usb" || transport == "mmc")
                && size != "0B"
            {
                devices.push(BlockDevice {
                    name: name.to_string(),
                    path: PathBuf::from(format!("/dev/{name}")),
                    transport,
                    size: size.to_string(),
                    model: model.trim().to_string(),
                });
            }
        }
    }

    devices
}

#[cfg(target_os = "macos")]
fn detect_removable_devices_macos() -> Result<Vec<BlockDevice>> {
    // Use diskutil to list external physical disks
    let output = Command::new("diskutil")
        .args(["list", "-plist", "external", "physical"])
        .output()
        .context("Failed to run diskutil")?;

    if !output.status.success() {
        bail!(
            "diskutil failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Parse plist output (simplified - just extract disk identifiers)
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    // Simple regex to find disk identifiers
    for line in output_str.lines() {
        if line.contains("<string>disk") && !line.contains("s") {
            if let Some(start) = line.find("disk") {
                if let Some(end) = line[start..].find('<') {
                    let disk_id = &line[start..start + end];

                    // Get more info about this disk
                    if let Ok(info) = get_macos_disk_info(disk_id) {
                        devices.push(info);
                    }
                }
            }
        }
    }

    Ok(devices)
}

#[cfg(target_os = "macos")]
fn get_macos_disk_info(disk_id: &str) -> Result<BlockDevice> {
    let output = Command::new("diskutil")
        .args(["info", disk_id])
        .output()
        .context("Failed to get disk info")?;

    let info_str = String::from_utf8_lossy(&output.stdout);

    let mut size = "Unknown".to_string();
    let mut model = "Unknown".to_string();

    for line in info_str.lines() {
        if line.contains("Disk Size:") {
            size = line
                .split(':')
                .nth(1)
                .unwrap_or("Unknown")
                .trim()
                .to_string();
        }
        if line.contains("Device / Media Name:") {
            model = line
                .split(':')
                .nth(1)
                .unwrap_or("Unknown")
                .trim()
                .to_string();
        }
    }

    Ok(BlockDevice {
        name: disk_id.to_string(),
        path: PathBuf::from(format!("/dev/{}", disk_id)),
        transport: "usb".to_string(),
        size,
        model,
    })
}

/// Look up block device info for a specific device path via lsblk
pub(crate) fn lookup_block_device(device: &Path) -> Result<BlockDevice> {
    let output = Command::new("lsblk")
        .args(["-d", "-o", "NAME,TRAN,SIZE,MODEL", "--json"])
        .arg(device)
        .output()
        .context("Failed to run lsblk")?;

    if !output.status.success() {
        bail!("lsblk failed for {}", device.display());
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse lsblk JSON")?;

    let dev = json
        .get_nested("blockdevices")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .context("No device info returned by lsblk")?;

    let name = dev.get_str("name").unwrap_or("unknown");
    let transport = normalize_transport(name, dev.get_str("tran"));
    let size = dev.get_str("size").unwrap_or("unknown");
    let model = dev.get_str("model").unwrap_or("Unknown");

    Ok(BlockDevice {
        name: name.to_string(),
        path: device.to_path_buf(),
        transport,
        size: size.to_string(),
        model: model.trim().to_string(),
    })
}

/// Interactive device selection
fn select_device() -> Result<BlockDevice> {
    let devices = detect_removable_devices()?;

    if devices.is_empty() {
        bail!(
            "No removable SD card devices found.\n\
             \n\
             Please:\n\
             1. Insert an SD card into a USB or built-in card reader\n\
             2. Wait a few seconds for it to be detected\n\
             3. Run this command again\n\
             \n\
             Or specify a device manually with --device /dev/sdX or --device /dev/mmcblk0"
        );
    }

    if devices.len() == 1 {
        let device = &devices[0];
        utils::success(&format!("Found device: {device}"));
        return Ok(device.clone());
    }

    // Multiple devices - let user select
    let options: Vec<String> = devices
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    let selection = Select::new("Select target device:", options)
        .with_render_config(create_orange_theme())
        .prompt()
        .context("Failed to get device selection")?;

    // Find the selected device
    let selected = devices
        .into_iter()
        .find(|d| d.to_string() == selection)
        .context("Selected device not found")?;

    Ok(selected)
}

// =============================================================================
// Safety checks and confirmations
// =============================================================================

/// Check that no partitions of the device are mounted
pub(crate) fn check_device_not_mounted(device: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mounts =
            std::fs::read_to_string("/proc/mounts").context("Failed to read /proc/mounts")?;

        let device_str = device.to_string_lossy();

        for line in mounts.lines() {
            let mount_device = line.split_whitespace().next().unwrap_or("");
            if mount_device.starts_with(&*device_str) {
                let mount_point = line.split_whitespace().nth(1).unwrap_or("unknown");
                bail!(
                    "Device {} has mounted partitions!\n\
                     \n\
                     Mounted: {} on {}\n\
                     \n\
                     Please unmount first:\n\
                     sudo umount {}*",
                    device.display(),
                    mount_device,
                    mount_point,
                    device.display()
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("diskutil")
            .args(["info", &device.to_string_lossy()])
            .output()
            .context("Failed to check mount status")?;

        // A failed query must not read as "not mounted" and wave the flash
        // through onto a possibly-mounted disk.
        if !output.status.success() {
            bail!(
                "Could not determine whether {} is mounted (diskutil info failed): {}",
                device.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let info = String::from_utf8_lossy(&output.stdout);
        if info.contains("Mounted:") && info.contains("Yes") {
            bail!(
                "Device {} is mounted!\n\
                 \n\
                 Please unmount first:\n\
                 diskutil unmountDisk {}",
                device.display(),
                device.display()
            );
        }
    }

    Ok(())
}

/// Unmount all mounted partitions of the device before flashing.
///
/// This avoids a TOCTOU race where the automounter mounts partitions between
/// `check_device_not_mounted` and `dd` opening the device (which would cause
/// EBUSY on Linux 6.2+).
fn unmount_device_partitions(device: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mounts =
            std::fs::read_to_string("/proc/mounts").context("Failed to read /proc/mounts")?;

        let device_str = device.to_string_lossy();

        for line in mounts.lines() {
            let mut fields = line.split_whitespace();
            let mount_device = fields.next().unwrap_or("");
            let mount_point = fields.next().unwrap_or("");

            if mount_device.starts_with(&*device_str) {
                utils::info(&format!("Unmounting {mount_device} from {mount_point}"));
                utils::unmount_partition(Path::new(mount_point), Path::new(mount_device))?;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("diskutil")
            .args(["unmountDisk", &device.to_string_lossy()])
            .output()
            .context("Failed to unmount device")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to unmount {}: {stderr}", device.display());
        }
    }

    Ok(())
}

/// Check that the device has media inserted (non-zero size)
fn check_device_has_media(device: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Get device name (e.g., "sdc" from "/dev/sdc")
        let device_name = device.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Check /sys/block/<device>/size - returns 0 if no media
        let size_path = format!("/sys/block/{device_name}/size");
        match std::fs::read_to_string(&size_path) {
            Ok(size_str) => match size_str.trim().parse::<u64>() {
                Ok(0) => bail!(
                    "No media found in device {}.\n\
                     \n\
                     Please insert an SD card and try again.",
                    device.display()
                ),
                Ok(_) => {}
                // A present-but-unparseable size means the check could not run;
                // surface it rather than silently treating the media as present.
                Err(e) => utils::warning(&format!(
                    "Could not parse device size from {size_path} ({e}); \
                     skipping the media-presence check."
                )),
            },
            Err(e) => utils::warning(&format!(
                "Could not read {size_path} ({e}) to verify media presence; \
                 skipping the media-presence check."
            )),
        }
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, check via diskutil
        match Command::new("diskutil")
            .args(["info", &device.to_string_lossy()])
            .output()
        {
            Ok(output) if output.status.success() => {
                let info = String::from_utf8_lossy(&output.stdout);
                // If diskutil can't find the disk or shows 0 bytes, no media
                if info.contains("Total Size:") && info.contains("0 B") {
                    bail!(
                        "No media found in device {}.\n\
                         \n\
                         Please insert an SD card and try again.",
                        device.display()
                    );
                }
            }
            Ok(output) => utils::warning(&format!(
                "diskutil could not report media for {} ({}); \
                 skipping the media-presence check.",
                device.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(e) => utils::warning(&format!(
                "Could not run diskutil to verify media presence ({e}); \
                 skipping the media-presence check."
            )),
        }
    }

    Ok(())
}

/// Confirm flash operation - show warning and require typing device name
fn confirm_flash_operation(device: &BlockDevice, auto_confirm: bool) -> Result<bool> {
    let target_str = format!("Target: {}", device.path.display());
    let model_str = format!("Model:  {}", device.model);
    let size_str = format!("Size:   {}", device.size);
    let warning_msg = "ALL DATA ON THIS DEVICE WILL BE PERMANENTLY ERASED!";

    println!(
        "  {}",
        "╔══════════════════════════════════════════════════════════╗".red()
    );
    println!(
        "  {}  {:^54}  {}",
        "║".red(),
        "⚠  WARNING: DESTRUCTIVE OPERATION".red().bold(),
        "║".red()
    );
    println!(
        "  {}",
        "╠══════════════════════════════════════════════════════════╣".red()
    );
    println!("  {}  {:<54}  {}", "║".red(), target_str, "║".red());
    println!("  {}  {:<54}  {}", "║".red(), model_str, "║".red());
    println!("  {}  {:<54}  {}", "║".red(), size_str, "║".red());
    println!(
        "  {}",
        "╠══════════════════════════════════════════════════════════╣".red()
    );
    println!("  {}  {:^54}  {}", "║".red(), warning_msg.red(), "║".red());
    println!(
        "  {}",
        "╚══════════════════════════════════════════════════════════╝".red()
    );

    if auto_confirm {
        utils::warning("Auto-confirming due to --yes flag");
        return Ok(true);
    }

    let prompt = format!("Type '{}' to confirm (or 'q' to cancel):", device.name);
    loop {
        let response = Text::new(&prompt)
            .with_render_config(create_orange_theme())
            .prompt()
            .context("Failed to get confirmation")?;

        let response_lower = response.trim().to_lowercase();

        if response_lower == device.name.to_lowercase() {
            return Ok(true);
        }

        if response_lower == "q" || response_lower == "quit" || response_lower == "cancel" {
            return Ok(false);
        }

        println!(
            "  {} Expected '{}', got '{}'. Try again.",
            "✗".red(),
            device.name,
            response.trim()
        );
    }
}

// =============================================================================
// Download functionality
// =============================================================================

/// Get the cache directory for downloaded images
fn get_cache_dir() -> Result<PathBuf> {
    let cache_dir = dirs::cache_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine cache directory"))?
        .join("russignol")
        .join("images");
    std::fs::create_dir_all(&cache_dir)?;
    Ok(cache_dir)
}

/// Get filename from URL
fn get_filename_from_url(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or("russignol.img.xz")
}

/// Clean up old cached images, keeping only the specified file
fn cleanup_old_cache(keep: &Path) {
    let Ok(cache_dir) = get_cache_dir() else {
        return;
    };

    let Ok(entries) = std::fs::read_dir(&cache_dir) else {
        return;
    };

    let keep_name = keep.file_name();

    for entry in entries.flatten() {
        let path = entry.path();
        // Skip the file we want to keep
        if path.file_name() == keep_name {
            continue;
        }
        // Only delete image files (.img, .img.xz)
        // Using case-insensitive extension check for both single and compound extensions
        let is_image = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| {
                let path = std::path::Path::new(name);
                // Check for .img extension
                let has_img_ext = path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("img"));
                // Check for .img.xz compound extension (xz extension with .img in stem)
                let has_img_xz_ext = path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("xz"))
                    && path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .is_some_and(|stem| {
                            std::path::Path::new(stem)
                                .extension()
                                .is_some_and(|e| e.eq_ignore_ascii_case("img"))
                        });
                has_img_ext || has_img_xz_ext
            });
        if is_image {
            if let Err(e) = std::fs::remove_file(&path) {
                log::debug!("Failed to remove old cache file {}: {}", path.display(), e);
            } else {
                log::debug!("Removed old cache file: {}", path.display());
            }
        }
    }
}

/// Download with caching support
/// Returns path to the cached file
fn download_with_cache(
    url: &str,
    expected_checksum: Option<&str>,
    expected_size: Option<u64>,
) -> Result<PathBuf> {
    let cache_dir = get_cache_dir()?;
    let filename = get_filename_from_url(url);
    let cache_path = cache_dir.join(filename);

    // Check if we have a complete cached file with valid checksum
    if cache_path.exists() {
        if let Some(expected) = expected_checksum {
            utils::info("Checking cached image...");
            if verify_checksum_silent(&cache_path, expected) {
                utils::success("Using cached image (checksum verified)");
                return Ok(cache_path);
            }
            // Checksum failed - file might be corrupt or incomplete
            utils::warning("Cached file checksum mismatch, will re-download");
        } else {
            // No checksum to verify, but file exists - use it
            return Ok(cache_path);
        }
    }

    // Download the file
    download_file(url, &cache_path, expected_size)?;

    // Verify checksum of completed download
    if let Some(expected) = expected_checksum {
        utils::info("Verifying checksum...");
        verify_checksum(&cache_path, expected)?;
        utils::success("Checksum verified");
    }

    // Clean up old cached images, keeping only this one
    cleanup_old_cache(&cache_path);

    Ok(cache_path)
}

/// Verify checksum without printing errors (for cache checking)
fn verify_checksum_silent(file: &Path, expected: &str) -> bool {
    compute_file_sha256(file).is_ok_and(|hash| hash == expected)
}

/// Download file with retry support
fn download_file(url: &str, dest: &Path, expected_size: Option<u64>) -> Result<()> {
    let agent = create_http_agent(600);

    // Retry logic
    for attempt in 1..=3 {
        match do_download(&agent, url, dest, expected_size) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 3 => {
                utils::warning(&format!("Download failed (attempt {attempt}/3): {e}"));
                std::thread::sleep(std::time::Duration::from_secs(2u64.pow(attempt)));
            }
            Err(e) => return Err(e),
        }
    }

    unreachable!()
}

fn do_download(
    agent: &ureq::Agent,
    url: &str,
    dest: &Path,
    expected_size: Option<u64>,
) -> Result<()> {
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("Failed to download from {url}"))?;

    let status = response.status();
    if status != 200 {
        bail!("Download failed: HTTP {status}");
    }

    let total_bytes = response
        .headers()
        .get("content-length")
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .or(expected_size)
        .unwrap_or(0);

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

    // Open file for writing
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dest)
        .with_context(|| format!("Failed to open {} for writing", dest.display()))?;

    // Stream download
    let mut reader = response.body_mut().as_reader();
    let mut buffer = [0; 8192];

    loop {
        let n = reader
            .read(&mut buffer)
            .context("Failed to read response chunk")?;
        if n == 0 {
            break;
        }
        file.write_all(&buffer[..n])
            .context("Failed to write to file")?;
        pb.inc(n as u64);
    }

    pb.finish_and_clear();

    Ok(())
}

/// Verify file checksum
fn verify_checksum(file: &Path, expected: &str) -> Result<()> {
    let hash = compute_file_sha256(file).context("Failed to read file for checksum")?;

    if hash != expected {
        bail!(
            "Checksum verification failed!\n\
             Expected: {expected}\n\
             Got:      {hash}"
        );
    }

    Ok(())
}

// =============================================================================
// Flash functionality
// =============================================================================

/// Flash image to device
/// `expected_size` is the uncompressed image size for progress estimation (from version.json)
/// A `Write` sink that hashes and counts the bytes streamed through it without
/// storing them — used to derive the reference SHA-256 and length of an image's
/// decompressed contents in a single pass.
struct HashCounter {
    hasher: Sha256,
    bytes: u64,
}

impl HashCounter {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.bytes)
    }
}

impl Write for HashCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Stream the decompressed contents of `image` into `sink` — the exact byte
/// stream `dd` receives when the image is flashed.
fn stream_decompressed_to<W: Write>(image: &Path, sink: &mut W) -> Result<()> {
    use lzma_rs::xz_decompress;

    match image.extension().and_then(|e| e.to_str()) {
        Some("xz") => {
            let file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;
            let mut reader = BufReader::new(file);
            xz_decompress(&mut reader, sink).context("Failed to decompress XZ image")?;
        }
        Some("img") => {
            let mut file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;
            std::io::copy(&mut file, sink).context("Failed to read image data")?;
        }
        _ => bail!(
            "Unsupported image format: {}\n Supported formats: .img.xz, .img",
            image.display()
        ),
    }
    Ok(())
}

/// Hash the decompressed contents of `image`, returning `(sha256_hex, len)`.
///
/// This is the reference the post-flash read-back compares against: the exact
/// byte stream `dd` receives, so the comparison covers decompression as well as
/// the write itself.
fn hash_decompressed_source(image: &Path) -> Result<(String, u64)> {
    let mut sink = HashCounter::new();
    stream_decompressed_to(image, &mut sink)?;
    Ok(sink.finish())
}

/// Hash the first `len` bytes of `reader`, returning `(sha256_hex, bytes_read)`.
fn hash_reader_prefix<R: Read>(reader: R, len: u64) -> Result<(String, u64)> {
    let mut hasher = HashCounter::new();
    std::io::copy(&mut reader.take(len), &mut hasher)
        .context("Failed to read back written image")?;
    Ok(hasher.finish())
}

/// Read `len` bytes back from `device` via `sudo dd` and hash them, for the
/// case where the raw device is only root-readable.
fn hash_device_prefix_sudo(device: &Path, len: u64) -> Result<(String, u64)> {
    let mut child = Command::new("sudo")
        .arg("dd")
        .arg(format!("if={}", device.display()))
        .args(["bs=1M", "status=none"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn sudo dd for read-back verification")?;
    let stdout = child
        .stdout
        .take()
        .context("Failed to capture dd output for read-back verification")?;
    let result = hash_reader_prefix(stdout, len);
    // Only the first `len` bytes are needed; stop dd rather than drain the card.
    let _ = child.kill();
    let _ = child.wait();
    result
}

/// Hash the first `len` bytes read back from `device`. Reads directly when the
/// process can open the raw device, otherwise falls back to `sudo dd` (reading
/// a raw device typically needs root, and off Linux the flash runs without an
/// explicit sudo privilege even when root is still required).
fn hash_device_prefix(device: &Path, len: u64) -> Result<(String, u64)> {
    match std::fs::File::open(device) {
        Ok(file) => hash_reader_prefix(file, len),
        Err(_) => hash_device_prefix_sudo(device, len),
    }
}

/// Read the flashed image back off the card and confirm it matches the source.
///
/// Guards against a silently truncated or corrupted write before the card is
/// walked to the signer. Reads only the source-sized prefix of the device, so
/// the cost scales with the image, not the whole card.
fn verify_flash_readback(image: &Path, device: &Path) -> Result<()> {
    let spinner = crate::progress::create_spinner("Verifying written image...");
    let result = (|| {
        let (expected_sha, len) = hash_decompressed_source(image)?;
        let (actual_sha, read) = hash_device_prefix(device, len)?;
        if read != len {
            bail!(
                "Read back only {read} of {len} bytes from the card — the write was truncated \
                 or the card is smaller than the image. Re-flash before using it."
            );
        }
        if actual_sha != expected_sha {
            bail!(
                "Read-back verification FAILED: the data on the card does not match the image.\n  \
                 Expected: {expected_sha}\n  Got:      {actual_sha}\n\n  \
                 The write did not land correctly. Re-flash the card before using it."
            );
        }
        Ok(())
    })();
    spinner.finish_and_clear();
    result?;
    utils::success("Written image verified");
    Ok(())
}

/// Verify the write unless the user opted out with `--skip-verify`.
fn verify_flash_or_note_skip(image: &Path, device: &Path, skip_verify: bool) -> Result<()> {
    if skip_verify {
        utils::warning("Skipping post-flash verification (--skip-verify).");
        Ok(())
    } else {
        verify_flash_readback(image, device)
    }
}

/// Write the image to the device, returning the rootfs-region hash teed off
/// the write stream (`None`, with a warning, when the stream carried no
/// hashable rootfs partition).
pub(crate) fn flash_image_to_device(
    image: &Path,
    device: &Path,
    expected_size: Option<u64>,
    privilege: FlashPrivilege,
) -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        flash_image_linux(image, device, expected_size, privilege)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = privilege; // probe always grants Direct off Linux
        flash_image_macos(image, device, expected_size)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (expected_size, privilege); // suppress unused warning
        bail!("Flash not supported on this platform")
    }
}

/// Default uncompressed image size fallback (used when size unknown)
/// Conservative default for when XZ metadata can't be read
const DEFAULT_IMAGE_SIZE: u64 = 10_485_760; // 10 MB

/// Read the uncompressed size from an XZ file's metadata.
/// Returns None if the xz command is unavailable or parsing fails.
fn get_xz_uncompressed_size(path: &Path) -> Option<u64> {
    let output = Command::new("xz")
        .args(["--robot", "--list", path.to_str()?])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Parse robot output: columns are separated by tabs
    // totals line format: totals\tstreams\tblocks\tcompressed\tuncompressed\tratio...
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("totals") {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 5 {
                return fields[4].parse().ok();
            }
        }
    }
    None
}

/// Writer wrapper that tracks progress and updates a progress bar
struct ProgressWriter<W: Write> {
    inner: W,
    progress_bar: ProgressBar,
    total_size: u64,
    bytes_written: u64,
    started: bool,
}

impl<W: Write> ProgressWriter<W> {
    fn new(inner: W, total_size: u64) -> Self {
        // Start with a spinner while preparing
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.208} Preparing...")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        Self {
            inner,
            progress_bar: pb,
            total_size,
            bytes_written: 0,
            started: false,
        }
    }

    fn finish(self) {
        // Set to 100% before clearing (actual size may differ slightly from estimate)
        self.progress_bar.set_position(self.total_size);
        self.progress_bar.finish_and_clear();
    }
}

impl<W: Write> Write for ProgressWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;

        // Switch from spinner to progress bar on first write
        if !self.started {
            self.started = true;
            self.progress_bar.set_length(self.total_size);
            let template = format!(
                "Flashing  [{{bar:40.{ORANGE_256}}}] {{percent}}% ({{bytes}}/{{total_bytes}}) ETA {{eta}}"
            );
            self.progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template(&template)
                    .unwrap()
                    .progress_chars("█░ "),
            );
            // Smooth out ETA calculations to reduce jumpiness
            self.progress_bar
                .enable_steady_tick(std::time::Duration::from_millis(100));
        }

        self.progress_bar.set_position(self.bytes_written);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Build the dd invocation, prefixed with sudo when the write-access probe
/// escalated. Sudo credentials must already be cached (`ensure_sudo`) so the
/// password prompt never competes with the image stream on stdin.
#[cfg(target_os = "linux")]
fn dd_command(device: &Path, privilege: FlashPrivilege) -> Command {
    let dd_args = [
        format!("of={}", device.display()),
        "bs=4M".to_string(),
        "iflag=fullblock".to_string(),
        "oflag=direct".to_string(),
    ];
    let mut cmd = match privilege {
        FlashPrivilege::Direct => Command::new("dd"),
        FlashPrivilege::Sudo => {
            let mut cmd = Command::new("sudo");
            cmd.arg("dd");
            cmd
        }
    };
    cmd.args(dd_args)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

#[cfg(target_os = "linux")]
fn flash_image_linux(
    image: &Path,
    device: &Path,
    expected_size: Option<u64>,
    privilege: FlashPrivilege,
) -> Result<Option<String>> {
    use lzma_rs::xz_decompress;

    let extension = image.extension().and_then(|e| e.to_str());

    // For uncompressed images, use actual file size
    // For XZ, try: provided expected_size -> read from XZ metadata -> default fallback
    let total_size = if extension == Some("img") {
        std::fs::metadata(image)?.len()
    } else {
        expected_size
            .or_else(|| get_xz_uncompressed_size(image))
            .unwrap_or(DEFAULT_IMAGE_SIZE)
    };

    if privilege == FlashPrivilege::Sudo {
        utils::ensure_sudo()?;
    }

    // Unmount any automounted partitions right before opening the device
    unmount_device_partitions(device)?;

    // Spawn dd process with stderr captured for error reporting
    let mut dd = dd_command(device, privilege)
        .spawn()
        .context("Failed to start dd")?;

    let stdin = dd.stdin.take().context("Failed to get dd stdin")?;
    let mut writer =
        crate::rootfs::RootfsHashingWriter::new(ProgressWriter::new(stdin, total_size));

    // Stream decompressed data to dd
    let write_result = match extension {
        Some("xz") => {
            let file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;
            let mut reader = BufReader::new(file);

            xz_decompress(&mut reader, &mut writer).context("Failed to decompress XZ image")
        }
        Some("img") => {
            let mut file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;

            std::io::copy(&mut file, &mut writer)
                .context("Failed to write image data")
                .map(|_| ())
        }
        _ => {
            bail!(
                "Unsupported image format: {}\n\
                 Supported formats: .img.xz, .img",
                image.display()
            );
        }
    };

    // Finish progress bar and close stdin
    let (progress_writer, rootfs_hash) = writer.finish();
    progress_writer.finish();

    // Wait for dd to complete
    let output = dd.wait_with_output().context("Failed to wait for dd")?;

    // If writing failed, check if dd reported the real cause
    if let Err(write_err) = write_result {
        let dd_errors = extract_dd_errors(&String::from_utf8_lossy(&output.stderr));
        if dd_errors.is_empty() {
            return Err(write_err);
        }
        // dd's error is the root cause; the write error (e.g. broken pipe) is just a consequence
        bail!("{dd_errors}");
    }

    if !output.status.success() {
        let dd_errors = extract_dd_errors(&String::from_utf8_lossy(&output.stderr));
        if dd_errors.is_empty() {
            bail!("dd failed with exit code: {:?}", output.status.code());
        }
        bail!("{dd_errors}");
    }

    // Sync to ensure all data is written
    sync_with_spinner(None)?;

    Ok(rootfs_hash_or_warn(rootfs_hash))
}

/// Whether the running process can re-read the partition table in place, or must
/// defer to a physical re-plug of the card.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartitionReread {
    /// Root: attempt the re-scan via partprobe/blockdev.
    Attempt,
    /// Non-root: the kernel re-scan (`BLKRRPART`) needs `CAP_SYS_ADMIN`, which
    /// disk-group access to the device node does not grant, so a re-plug is the
    /// only unprivileged way to make the kernel adopt the new table.
    DeferToReplug,
}

/// The re-scan needs `CAP_SYS_ADMIN`, so without root the tools can only fail;
/// spawn them only when they can succeed, and otherwise ask for a re-plug.
#[cfg(target_os = "linux")]
fn partition_reread_plan(is_root: bool) -> PartitionReread {
    if is_root {
        PartitionReread::Attempt
    } else {
        PartitionReread::DeferToReplug
    }
}

/// The host kernel's view of the card's partition table after a flash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPartitionView {
    /// The kernel holds the newly written table (re-read succeeded, or the OS
    /// refreshes it on its own).
    Current,
    /// The kernel still holds the pre-flash table; a physical re-plug is needed
    /// before the new partitions are visible on this host.
    Stale,
}

/// Re-read the partition table after flashing so the kernel sees the new
/// partitions, returning whether the host view ended up current.
///
/// After `dd` writes a new image the kernel's cached table is stale. Re-reading
/// it (`BLKRRPART`, behind partprobe/blockdev) needs `CAP_SYS_ADMIN`, so a
/// non-root run cannot refresh it in place and reports [`HostPartitionView::Stale`];
/// the caller decides whether to drive a re-plug.
pub(crate) fn reread_partition_table(device: &Path) -> HostPartitionView {
    #[cfg(target_os = "linux")]
    {
        if partition_reread_plan(nix::unistd::Uid::effective().is_root())
            == PartitionReread::DeferToReplug
        {
            return HostPartitionView::Stale;
        }

        let dev = device.to_string_lossy();

        // partprobe (parted) and blockdev --rereadpt (util-linux) both re-read
        // the table; either can return non-zero (e.g. EBUSY) while the other
        // still refreshes it, so fall back to the second only when the first
        // does not succeed. Both live in /sbin or /usr/sbin, routinely absent
        // from a user's PATH, so resolve them by location rather than spawning
        // by bare name.
        let refreshed = utils::run_resolved_best_effort(
            "partprobe",
            &[&dev],
            "Partition table re-read (partprobe)",
        ) || utils::run_resolved_best_effort(
            "blockdev",
            &["--rereadpt", &dev],
            "Partition table re-read (blockdev)",
        );

        utils::run_best_effort(
            "udevadm",
            &["settle", "--timeout=3"],
            "Waiting for udev to settle",
        );

        if refreshed {
            HostPartitionView::Current
        } else {
            // Root yet still no re-read (e.g. a busy device): surface it, since a
            // stale table silently corrupts later host-side partition reads.
            utils::warning(
                "Partition table not re-read; re-plug the card before accessing \
                 its partitions on this host.",
            );
            HostPartitionView::Stale
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS handles this automatically via diskutil
        let _ = device;
        HostPartitionView::Current
    }
}

/// One partition's structural observation: whether its node exists and whether
/// it mounts cleanly.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PartitionCheck {
    present: bool,
    mounts: bool,
}

/// Verdict of a structural check of a freshly flashed card.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum StructuralVerdict {
    Sound,
    Faulty(Vec<String>),
}

/// Judge a flashed card's structure from its boot (p1) and rootfs (p2) checks.
///
/// The image lays down exactly p1 (vfat boot) and p2 (f2fs rootfs); p3/p4 are
/// created by the device on first boot, so this deliberately does not require
/// them — their absence here is expected, not a fault.
#[cfg(target_os = "linux")]
fn evaluate_structural(boot: PartitionCheck, rootfs: PartitionCheck) -> StructuralVerdict {
    let mut faults = Vec::new();
    note_partition_fault(&mut faults, "boot partition (p1)", boot);
    note_partition_fault(&mut faults, "rootfs partition (p2)", rootfs);
    if faults.is_empty() {
        StructuralVerdict::Sound
    } else {
        StructuralVerdict::Faulty(faults)
    }
}

#[cfg(target_os = "linux")]
fn note_partition_fault(faults: &mut Vec<String>, label: &str, check: PartitionCheck) {
    if !check.present {
        faults.push(format!("{label} is missing"));
    } else if !check.mounts {
        faults.push(format!("{label} did not mount"));
    }
}

/// Observe one partition: whether its node exists and whether it mounts
/// read-only. A mount failure leaves the card untouched (mounted read-only,
/// then unmounted).
#[cfg(target_os = "linux")]
fn check_partition(device: &Path, part_num: u8, fs_type: &str) -> PartitionCheck {
    let path = utils::get_partition_path(device, part_num);
    if !path.exists() {
        return PartitionCheck {
            present: false,
            mounts: false,
        };
    }
    match utils::mount_partition(&path, fs_type, true) {
        Ok(mount) => {
            utils::warn_if_err(
                utils::unmount_partition(&mount, &path),
                "Failed to unmount after structural check",
            );
            PartitionCheck {
                present: true,
                mounts: true,
            }
        }
        Err(_) => PartitionCheck {
            present: true,
            mounts: false,
        },
    }
}

/// Structurally verify a freshly flashed card: p1 (vfat boot) and p2 (f2fs
/// rootfs) must be present and mount cleanly. When the host view is stale the
/// card is re-plugged first (the kernel re-scans on re-insertion), which is how
/// a non-root run gets the new partitions without `CAP_SYS_ADMIN`.
fn verify_flashed_card(device: &Path, view: HostPartitionView) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if view == HostPartitionView::Stale {
            utils::info("Remove and re-insert the card to reveal the new partitions.");
            restore_keys::wait_for_card_swap(device)?;
        }

        let spinner = crate::progress::create_spinner("Verifying card structure...");
        let boot = check_partition(device, 1, "vfat");
        let rootfs = check_partition(device, 2, "f2fs");
        spinner.finish_and_clear();

        match evaluate_structural(boot, rootfs) {
            StructuralVerdict::Sound => utils::success(
                "Card structure verified: boot and rootfs partitions are present and mount cleanly",
            ),
            StructuralVerdict::Faulty(faults) => {
                utils::warning("Card structure check found problems:");
                for fault in faults {
                    println!("    - {fault}");
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (device, view);
    }

    Ok(())
}

/// After a flash, offer a structural verification of the card. Declined by
/// default and skipped under `--yes`, so it never blocks the common "insert
/// into the Pi" path.
fn offer_structural_verify(
    device: &Path,
    view: HostPartitionView,
    auto_confirm: bool,
) -> Result<()> {
    if auto_confirm {
        return Ok(());
    }
    let verify = inquire::Confirm::new("Verify the flashed card?")
        .with_default(false)
        .with_render_config(create_orange_theme())
        .prompt()
        .context("Failed to read verification choice")?;
    if verify {
        // The flash itself already succeeded and was read-back verified, so a
        // verification hiccup (e.g. the re-plug wait timing out) is reported, not
        // fatal.
        utils::warn_if_err(
            verify_flashed_card(device, view),
            "Card verification did not complete",
        );
    }
    Ok(())
}

/// Run sync with a spinner, optionally eject (macOS), then show success message
fn sync_with_spinner(eject_device: Option<&Path>) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.208} Syncing...")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    Command::new("sync").status().context("Failed to sync")?;

    // Eject on macOS if device provided
    if let Some(device) = eject_device {
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.208} Ejecting...")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );

        Command::new("diskutil")
            .args(["eject", &device.to_string_lossy()])
            .status()
            .context("Failed to eject")?;
    }

    spinner.finish_and_clear();

    Ok(())
}

#[cfg(target_os = "macos")]
fn flash_image_macos(
    image: &Path,
    device: &Path,
    expected_size: Option<u64>,
) -> Result<Option<String>> {
    use lzma_rs::xz_decompress;

    // Use raw device for faster writes
    let raw_device = device.to_string_lossy().replace("/dev/disk", "/dev/rdisk");

    let extension = image.extension().and_then(|e| e.to_str());

    // For uncompressed images, use actual file size
    // For XZ, try: provided expected_size -> read from XZ metadata -> default fallback
    let total_size = if extension == Some("img") {
        std::fs::metadata(image)?.len()
    } else {
        expected_size
            .or_else(|| get_xz_uncompressed_size(image))
            .unwrap_or(DEFAULT_IMAGE_SIZE)
    };

    // Unmount any automounted partitions right before opening the device
    unmount_device_partitions(device)?;

    // Spawn dd process with macOS-specific args, stderr captured for error reporting
    let mut dd = Command::new("dd")
        .args([
            &format!("of={}", raw_device),
            "bs=4m", // lowercase for BSD dd
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to start dd. Are you running with sudo?")?;

    let stdin = dd.stdin.take().context("Failed to get dd stdin")?;
    let mut writer =
        crate::rootfs::RootfsHashingWriter::new(ProgressWriter::new(stdin, total_size));

    let write_result = match extension {
        Some("xz") => {
            let file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;
            let mut reader = BufReader::new(file);

            xz_decompress(&mut reader, &mut writer).context("Failed to decompress XZ image")
        }
        Some("img") => {
            let mut file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;

            std::io::copy(&mut file, &mut writer)
                .context("Failed to write image data")
                .map(|_| ())
        }
        _ => {
            bail!(
                "Unsupported image format: {}\n\
                 Supported formats: .img.xz, .img",
                image.display()
            );
        }
    };

    let (progress_writer, rootfs_hash) = writer.finish();
    progress_writer.finish();

    let output = dd.wait_with_output().context("Failed to wait for dd")?;

    if let Err(write_err) = write_result {
        let dd_errors = extract_dd_errors(&String::from_utf8_lossy(&output.stderr));
        if dd_errors.is_empty() {
            return Err(write_err);
        }
        bail!("{dd_errors}");
    }

    if !output.status.success() {
        let dd_errors = extract_dd_errors(&String::from_utf8_lossy(&output.stderr));
        if dd_errors.is_empty() {
            bail!("dd failed with exit code: {:?}", output.status.code());
        }
        bail!("{dd_errors}");
    }

    // Sync and eject
    sync_with_spinner(Some(device))?;

    Ok(rootfs_hash_or_warn(rootfs_hash))
}

/// Extract dd error lines from stderr, filtering out transfer statistics.
///
/// dd always prints stats to stderr (e.g. "45+0 records in", "184549376 bytes copied").
/// When dd fails, the actual error (e.g. "dd: error writing '/dev/sdc': Input/output error")
/// is mixed in with these stats. This extracts only the error lines.
fn extract_dd_errors(stderr: &str) -> String {
    stderr
        .lines()
        .filter(|line| line.starts_with("dd:"))
        .collect::<Vec<_>>()
        .join("\n")
}

// =============================================================================
// Utility functions
// =============================================================================

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        let (whole, frac) = div_with_tenths(bytes, GB);
        format!("{whole}.{frac} GB")
    } else if bytes >= MB {
        let (whole, frac) = div_with_tenths(bytes, MB);
        format!("{whole}.{frac} MB")
    } else if bytes >= KB {
        let (whole, frac) = div_with_tenths(bytes, KB);
        format!("{whole}.{frac} KB")
    } else {
        format!("{bytes} B")
    }
}

/// Divide with one decimal place of precision using integer arithmetic
fn div_with_tenths(value: u64, divisor: u64) -> (u64, u64) {
    let whole = value / divisor;
    let remainder = value % divisor;
    // Calculate tenths: (remainder * 10) / divisor, rounded
    let tenths = (remainder * 10 + divisor / 2) / divisor;
    (whole, tenths.min(9)) // Cap at 9 to avoid rounding to 10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn partition_reread_defers_to_replug_without_root() {
        // A non-root process cannot run BLKRRPART, so it must not spawn the
        // re-read tools — it asks for a re-plug instead.
        assert_eq!(partition_reread_plan(false), PartitionReread::DeferToReplug);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partition_reread_attempts_as_root() {
        assert_eq!(partition_reread_plan(true), PartitionReread::Attempt);
    }

    #[cfg(target_os = "linux")]
    fn ok_check() -> PartitionCheck {
        PartitionCheck {
            present: true,
            mounts: true,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structural_sound_when_boot_and_rootfs_mount() {
        assert_eq!(
            evaluate_structural(ok_check(), ok_check()),
            StructuralVerdict::Sound
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structural_faults_a_missing_boot_partition() {
        let missing = PartitionCheck {
            present: false,
            mounts: false,
        };
        let StructuralVerdict::Faulty(faults) = evaluate_structural(missing, ok_check()) else {
            panic!("expected a fault for a missing boot partition");
        };
        assert!(
            faults
                .iter()
                .any(|f| f.contains("boot partition (p1) is missing"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structural_faults_a_rootfs_that_does_not_mount() {
        let unmountable = PartitionCheck {
            present: true,
            mounts: false,
        };
        let StructuralVerdict::Faulty(faults) = evaluate_structural(ok_check(), unmountable) else {
            panic!("expected a fault for an unmountable rootfs");
        };
        assert!(
            faults
                .iter()
                .any(|f| f.contains("rootfs partition (p2) did not mount"))
        );
    }

    fn signed_image_info() -> version::ImageInfo {
        version::ImageInfo {
            filename: "russignol-pi-zero.img.xz".to_string(),
            sha256: "abc123".to_string(),
            size_bytes: 4096,
            compressed_size_bytes: 1024,
            min_sd_size_gb: 8,
            download_url: "https://example.com/russignol-pi-zero.img.xz".to_string(),
            signature: Some("deadbeef".to_string()),
        }
    }

    #[test]
    fn release_download_info_carries_the_image_signature() {
        let info = DownloadInfo::from_release(
            "https://example.com/russignol-pi-zero.img.xz".to_string(),
            "0.25.0",
            &signed_image_info(),
        );

        assert_eq!(info.signature, Some("deadbeef".to_string()));
    }

    #[test]
    fn custom_url_download_info_has_no_signature() {
        let info = DownloadInfo::from_custom_url("https://example.com/custom.img.xz".to_string());

        assert_eq!(info.signature, None);
    }

    #[test]
    fn local_signature_explicit_path_wins_over_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("test.img.xz");
        std::fs::write(&image, b"image").unwrap();
        std::fs::write(dir.path().join("test.img.xz.sig"), "sidecar\n").unwrap();
        let explicit = dir.path().join("elsewhere.sig");
        std::fs::write(&explicit, "explicit\n").unwrap();

        let sig = resolve_local_signature(&image, Some(&explicit)).unwrap();

        assert_eq!(sig, Some("explicit".to_string()));
    }

    #[test]
    fn local_signature_falls_back_to_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("test.img.xz");
        std::fs::write(&image, b"image").unwrap();
        std::fs::write(dir.path().join("test.img.xz.sig"), "deadbeef\n").unwrap();

        let sig = resolve_local_signature(&image, None).unwrap();

        assert_eq!(sig, Some("deadbeef".to_string()));
    }

    #[test]
    fn local_signature_none_when_no_sidecar_exists() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("test.img.xz");
        std::fs::write(&image, b"image").unwrap();

        let sig = resolve_local_signature(&image, None).unwrap();

        assert_eq!(sig, None);
    }

    /// End-to-end over the local flash path's trust decision, no device
    /// needed: a sidecar `.sig` written the way the release signer writes it
    /// (hex line, trailing newline) resolves and verifies against the image's
    /// actual SHA-256.
    #[test]
    fn resolved_sidecar_signature_verifies_against_the_image_hash() {
        use crate::release_signature::{SignatureVerdict, check_release_signature};
        use russignol_release_signature::{public_key, sign};

        // A deterministic seed — a test fixture, never a production key.
        let seed = [7u8; 32];

        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("test.img.xz");
        std::fs::write(&image, b"release image bytes").unwrap();
        let image_sha256 = compute_file_sha256(&image).unwrap();

        let sig = sign(&seed, &image_sha256).unwrap();
        std::fs::write(dir.path().join("test.img.xz.sig"), format!("{sig}\n")).unwrap();

        let resolved = resolve_local_signature(&image, None).unwrap();

        assert_eq!(
            check_release_signature(
                Some(&public_key(&seed)),
                &image_sha256,
                resolved.as_deref(),
                false,
            ),
            Ok(SignatureVerdict::Verified)
        );
    }

    #[test]
    fn local_signature_explicit_unreadable_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("test.img.xz");
        std::fs::write(&image, b"image").unwrap();
        let missing = dir.path().join("does-not-exist.sig");

        let result = resolve_local_signature(&image, Some(&missing));

        assert!(result.is_err(), "a missing explicit path must be an error");
    }

    #[test]
    fn hash_reader_prefix_hashes_only_the_requested_prefix() {
        let data = b"hello world extra bytes";
        let (hash, read) = hash_reader_prefix(&data[..], 11).unwrap();
        assert_eq!(read, 11);
        // sha256("hello world")
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn hash_decompressed_source_agrees_with_file_hash_for_uncompressed_img() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.img");
        std::fs::write(&path, b"raw image bytes").unwrap();

        let (hash, len) = hash_decompressed_source(&path).unwrap();
        assert_eq!(len, 15);
        // The reference the read-back compares against must match the same
        // SHA-256 the rest of the flash pipeline uses for a raw .img.
        assert_eq!(hash, compute_file_sha256(&path).unwrap());
    }

    /// Parse size string like "32G" or "16.5G" to bytes
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test helper - fractional bytes truncated intentionally"
    )]
    fn parse_size_string(s: &str) -> u64 {
        let s = s.trim();
        if s.is_empty() || s == "0B" {
            return 0;
        }

        let multiplier = match s.chars().last() {
            Some('B') => 1,
            Some('K') => 1024,
            Some('M') => 1024 * 1024,
            Some('G') => 1024 * 1024 * 1024,
            Some('T') => 1024 * 1024 * 1024 * 1024,
            _ => return 0,
        };

        let num_str: String = s
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        num_str.parse::<f64>().unwrap_or(0.0) as u64 * multiplier
    }

    /// Build lsblk JSON in the shape of `lsblk -d -o NAME,TYPE,TRAN,RM,SIZE,MODEL --json`
    #[cfg(target_os = "linux")]
    fn lsblk_json(devices: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "blockdevices": devices })
    }

    #[test]
    fn whole_disks_are_not_flagged_as_partitions() {
        for name in ["sda", "sdc", "mmcblk0", "nvme0n1", "loop0"] {
            assert!(!looks_like_partition(name), "{name} is a whole disk");
        }
    }

    #[test]
    fn partition_names_are_flagged() {
        for name in ["sda1", "sdc12", "mmcblk0p1", "nvme0n1p3", "loop0p1"] {
            assert!(looks_like_partition(name), "{name} is a partition");
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_includes_removable_usb_disk() {
        let json = lsblk_json(&serde_json::json!([
            {"name": "sdb", "type": "disk", "tran": "usb", "rm": true, "size": "29.7G", "model": " UHSII uSD Reader "}
        ]));
        let devices = filter_removable_devices(&json);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "sdb");
        assert_eq!(devices[0].path, PathBuf::from("/dev/sdb"));
        assert_eq!(devices[0].transport, "usb");
        assert_eq!(devices[0].size, "29.7G");
        assert_eq!(devices[0].model, "UHSII uSD Reader");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_excludes_internal_sata_and_nvme_disks() {
        let json = lsblk_json(&serde_json::json!([
            {"name": "sda", "type": "disk", "tran": "sata", "rm": false, "size": "476.9G", "model": "Samsung SSD 860"},
            {"name": "nvme0n1", "type": "disk", "tran": "nvme", "rm": false, "size": "1.8T", "model": "WD_BLACK SN850X"}
        ]));
        assert!(filter_removable_devices(&json).is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_excludes_empty_usb_reader_slot() {
        let json = lsblk_json(&serde_json::json!([
            {"name": "sdb", "type": "disk", "tran": "usb", "rm": true, "size": "0B", "model": "UHSII uSD Reader"}
        ]));
        assert!(filter_removable_devices(&json).is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_includes_mmcblk_with_mmc_transport() {
        // util-linux >= 2.39 reports TRAN "mmc" for mmcblk devices
        let json = lsblk_json(&serde_json::json!([
            {"name": "mmcblk0", "type": "disk", "tran": "mmc", "rm": true, "size": "29.7G", "model": null}
        ]));
        let devices = filter_removable_devices(&json);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "mmcblk0");
        assert_eq!(devices[0].path, PathBuf::from("/dev/mmcblk0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_includes_mmcblk_with_null_transport() {
        // util-linux <= 2.38 reports no TRAN for mmcblk devices
        let json = lsblk_json(&serde_json::json!([
            {"name": "mmcblk0", "type": "disk", "tran": null, "rm": true, "size": "29.7G", "model": null}
        ]));
        let devices = filter_removable_devices(&json);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "mmcblk0");
        assert_eq!(devices[0].path, PathBuf::from("/dev/mmcblk0"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_excludes_soldered_emmc() {
        let json = lsblk_json(&serde_json::json!([
            {"name": "mmcblk1", "type": "disk", "tran": null, "rm": false, "size": "58.2G", "model": null}
        ]));
        assert!(filter_removable_devices(&json).is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_excludes_emmc_boot_partition() {
        let json = lsblk_json(&serde_json::json!([
            {"name": "mmcblk1boot0", "type": "disk", "tran": null, "rm": false, "size": "4M", "model": null}
        ]));
        assert!(filter_removable_devices(&json).is_empty());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn filter_normalizes_mmcblk_transport_to_mmc() {
        // Both lsblk variants must store the same transport
        let json = lsblk_json(&serde_json::json!([
            {"name": "mmcblk0", "type": "disk", "tran": "mmc", "rm": true, "size": "29.7G", "model": null},
            {"name": "mmcblk1", "type": "disk", "tran": null, "rm": true, "size": "58.2G", "model": null}
        ]));
        let devices = filter_removable_devices(&json);
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().all(|d| d.transport == "mmc"));
    }

    #[test]
    fn key_source_flags_are_mutually_exclusive() {
        let p = Path::new("/dev/sdx");
        assert!(
            check_key_source_exclusive(Some(p), Some(p)).is_err(),
            "both --restore-keys and --migrate-keys must be rejected"
        );
        assert!(check_key_source_exclusive(Some(p), None).is_ok());
        assert!(check_key_source_exclusive(None, Some(p)).is_ok());
        assert!(check_key_source_exclusive(None, None).is_ok());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_parse_size_string() {
        assert_eq!(parse_size_string("32G"), 32 * 1024 * 1024 * 1024);
        assert_eq!(parse_size_string("16M"), 16 * 1024 * 1024);
        assert_eq!(parse_size_string("0B"), 0);
    }

    #[test]
    fn test_generate_card_id_format() {
        let id = generate_card_id().unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_card_id_unique() {
        let id1 = generate_card_id().unwrap();
        let id2 = generate_card_id().unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_compute_file_sha256() {
        use std::io::Write as _;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        tmp.flush().unwrap();

        let hash = compute_file_sha256(tmp.path()).unwrap();
        // sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
