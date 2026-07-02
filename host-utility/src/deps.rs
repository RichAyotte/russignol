//! External-dependency checks and guided octez installation.
//!
//! octez-client is always required (all node RPC goes through it), but
//! octez-node only matters when the RPC endpoint is a local node. When octez
//! binaries are missing the user is offered the official static binaries
//! (GitLab package registry, sha256-verified) installed to ~/.local/bin — no
//! root needed — alongside the apt/brew alternatives.

use anyhow::Result;

use crate::constants::{OCTEZ_CLIENT, OCTEZ_NODE, SYSTEM_COMMANDS};

/// Whether the endpoint points at a node on this machine.
pub fn endpoint_is_localhost(endpoint: &str) -> bool {
    let after_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?']).next().unwrap_or("");
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host == "localhost" || host == "::1" || host == "0.0.0.0" || host.starts_with("127.")
}

/// The octez binaries a run needs: octez-client always, octez-node only when
/// the endpoint is a local node.
pub fn required_octez_commands(endpoint: &str) -> Vec<&'static str> {
    if endpoint_is_localhost(endpoint) {
        vec![OCTEZ_CLIENT, OCTEZ_NODE]
    } else {
        vec![OCTEZ_CLIENT]
    }
}

/// apt/dnf install lines for missing system tools.
pub fn system_install_hint(missing: &[&str]) -> String {
    fn packages(missing: &[&str], map: fn(&str) -> &str) -> String {
        let mut pkgs: Vec<&str> = missing.iter().map(|tool| map(tool)).collect();
        pkgs.sort_unstable();
        pkgs.dedup();
        pkgs.join(" ")
    }
    let apt = packages(missing, |tool| match tool {
        "ps" => "procps",
        "ip" => "iproute2",
        "ping" => "iputils-ping",
        "udevadm" => "udev",
        "lsusb" => "usbutils",
        other => other,
    });
    let dnf = packages(missing, |tool| match tool {
        "ps" => "procps-ng",
        "ip" => "iproute",
        "ping" => "iputils",
        "udevadm" => "systemd-udev",
        "lsusb" => "usbutils",
        other => other,
    });
    format!(
        "Install with: sudo apt install {apt}  (Debian/Ubuntu)\n              sudo dnf install {dnf}  (Fedora)"
    )
}

/// The architecture prefix octez release assets use for this machine, or
/// `None` when no static binaries are published for it.
pub fn octez_asset_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// A stable octez static-binaries release in the GitLab package registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OctezRelease {
    pub id: i64,
    /// Full package name as it appears in the generic download URL
    /// (e.g. "octez-binaries-25.0").
    pub package_name: String,
    pub version: String,
}

/// A stable release version: dotted numeric components only, which excludes
/// rc/beta suffixes and datestamped dev builds.
fn parse_stable_version(version: &str) -> Option<Vec<u64>> {
    if !version.contains('.') {
        return None;
    }
    version
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

/// Pick the newest stable `octez-binaries-*` release from the GitLab
/// packages listing. Pre-releases (rc/beta suffixes) and datestamped dev
/// builds are skipped.
pub fn parse_octez_packages(json: &serde_json::Value) -> Option<OctezRelease> {
    json.as_array()?
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?;
            if !name.starts_with("octez-binaries-") {
                return None;
            }
            let version = pkg.get("version")?.as_str()?;
            let key = parse_stable_version(version)?;
            Some((
                key,
                OctezRelease {
                    id: pkg.get("id")?.as_i64()?,
                    package_name: name.to_string(),
                    version: version.to_string(),
                },
            ))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, release)| release)
}

/// Find a file's sha256 in a GitLab `package_files` listing.
pub fn find_package_file_sha256(json: &serde_json::Value, file_name: &str) -> Option<String> {
    json.as_array()?.iter().find_map(|file| {
        (file.get("file_name")?.as_str()? == file_name)
            .then(|| file.get("file_sha256")?.as_str().map(str::to_string))
            .flatten()
    })
}

const GITLAB_API_BASE: &str = "https://gitlab.com/api/v4/projects/tezos%2Ftezos";

/// Offer to install missing octez binaries, or fail with instructions.
///
/// Runs before any spinner starts: inquire prompts and indicatif spinners
/// fight over the terminal.
pub fn ensure_octez_available(endpoint: &str, interactive: bool) -> Result<()> {
    let missing: Vec<&str> = required_octez_commands(endpoint)
        .into_iter()
        .filter(|cmd| !crate::utils::command_exists(cmd))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    crate::utils::warning(&format!("Missing octez binaries: {}", missing.join(", ")));
    println!();
    crate::utils::info(&octez_install_alternatives());
    println!();

    if !interactive {
        anyhow::bail!(
            "Missing octez binaries: {}. Install them and re-run.",
            missing.join(", ")
        );
    }

    let download =
        inquire::Confirm::new("Download the official static binaries to ~/.local/bin now?")
            .with_default(true)
            .with_render_config(crate::utils::create_orange_theme())
            .prompt()
            .unwrap_or(false);
    if !download {
        anyhow::bail!(
            "Missing octez binaries: {}. Install them with one of the options above and re-run.",
            missing.join(", ")
        );
    }
    install_octez_static(&missing, &crate::install::get_install_dir()?)?;

    crate::install::warn_if_not_in_path(&crate::install::get_install_dir()?);
    let still_missing: Vec<&&str> = missing
        .iter()
        .filter(|cmd| !crate::utils::command_exists(cmd))
        .collect();
    if !still_missing.is_empty() {
        crate::utils::warning(
            "Installed binaries are not yet visible on PATH; fix PATH as above, then re-run.",
        );
    }
    Ok(())
}

/// Download the official static binaries from the GitLab package registry,
/// sha256-verify them, and install into `install_dir`.
fn install_octez_static(missing: &[&str], install_dir: &std::path::Path) -> Result<()> {
    use anyhow::Context;

    let arch = octez_asset_arch(std::env::consts::ARCH).with_context(|| {
        format!(
            "No official octez static binaries are published for {}",
            std::env::consts::ARCH
        )
    })?;
    let agent = crate::utils::create_http_agent(30);
    let packages = crate::utils::http_get_json(
        &agent,
        &format!("{GITLAB_API_BASE}/packages?order_by=created_at&sort=desc&per_page=50"),
    )
    .context("Failed to query the octez package registry")?;
    let release = parse_octez_packages(&packages)
        .context("No stable octez-binaries release found in the GitLab package registry")?;
    crate::utils::info(&format!("Latest stable octez release: {}", release.version));

    let files = crate::utils::http_get_json(
        &agent,
        &format!(
            "{GITLAB_API_BASE}/packages/{}/package_files?per_page=100",
            release.id
        ),
    )
    .context("Failed to list octez release files")?;

    std::fs::create_dir_all(install_dir)
        .with_context(|| format!("Failed to create {}", install_dir.display()))?;

    for cmd in missing {
        let asset = format!("{arch}-{cmd}");
        let sha256 = find_package_file_sha256(&files, &asset)
            .with_context(|| format!("{asset} not found in octez release {}", release.version))?;
        let url = format!(
            "{GITLAB_API_BASE}/packages/generic/{}/{}/{asset}",
            release.package_name, release.version
        );
        crate::utils::info(&format!("Downloading {asset}..."));
        let temp = download_with_retry(&agent, &url)?;
        crate::upgrade::verify_checksum(temp.path(), &sha256)?;
        let dest = install_dir.join(cmd);
        std::fs::copy(temp.path(), &dest)
            .with_context(|| format!("Failed to install to {}", dest.display()))?;
        crate::install::make_executable(&dest)?;
        crate::utils::success(&format!("Installed {}", dest.display()));
    }
    Ok(())
}

fn download_with_retry(agent: &ureq::Agent, url: &str) -> Result<tempfile::NamedTempFile> {
    for attempt in 1..=3u32 {
        match crate::upgrade::download_with_progress(agent, url, 0) {
            Ok(file) => return Ok(file),
            Err(e) if attempt < 3 => {
                crate::utils::warning(&format!("Download failed (attempt {attempt}/3): {e}"));
                std::thread::sleep(std::time::Duration::from_secs(2u64.pow(attempt)));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Human instructions for installing octez through the official channels.
pub fn octez_install_alternatives() -> String {
    format!(
        "Official octez install options:\n  \
         • Debian/Ubuntu packages: https://packages.nomadic-labs.com \
         (then: sudo apt install octez-client octez-node)\n  \
         • macOS: brew formula from https://packages.nomadic-labs.com/homebrew/Formula/octez.rb\n  \
         • Static binaries: https://gitlab.com/tezos/tezos/-/packages \
         (this utility can download these for you)\n  \
         Missing binaries checked: {OCTEZ_CLIENT}, {OCTEZ_NODE} (node only needed for localhost endpoints)"
    )
}

/// Verify system tools and octez binaries, with actionable install guidance.
///
/// Never prompts (safe inside spinners); interactive installation is offered
/// separately by `ensure_octez_available`.
pub fn verify_dependencies(endpoint: &str) -> Result<()> {
    let missing_octez: Vec<&str> = required_octez_commands(endpoint)
        .into_iter()
        .filter(|cmd| !crate::utils::command_exists(cmd))
        .collect();
    let missing_system: Vec<&str> = SYSTEM_COMMANDS
        .iter()
        .copied()
        .filter(|cmd| !crate::utils::command_exists(cmd))
        .collect();

    if missing_octez.is_empty() && missing_system.is_empty() {
        return Ok(());
    }

    let mut sections = Vec::new();
    if !missing_octez.is_empty() {
        sections.push(format!(
            "Missing octez binaries: {}\n{}",
            missing_octez.join(", "),
            octez_install_alternatives()
        ));
    }
    if !missing_system.is_empty() {
        sections.push(format!(
            "Missing system tools: {}\n{}",
            missing_system.join(", "),
            system_install_hint(&missing_system)
        ));
    }
    anyhow::bail!("{}", sections.join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_endpoints_require_octez_node() {
        for endpoint in [
            "http://localhost:8732",
            "http://127.0.0.1:8733",
            "http://[::1]:8732",
            "http://0.0.0.0:8732",
        ] {
            assert_eq!(
                required_octez_commands(endpoint),
                vec![OCTEZ_CLIENT, OCTEZ_NODE],
                "{endpoint} is local"
            );
        }
    }

    #[test]
    fn remote_endpoints_need_only_octez_client() {
        for endpoint in [
            "https://rpc.tzbeta.net",
            "https://rpc.shadownet.teztnets.com",
            "http://192.168.1.10:8732",
        ] {
            assert_eq!(
                required_octez_commands(endpoint),
                vec![OCTEZ_CLIENT],
                "{endpoint} is remote"
            );
        }
    }

    #[test]
    fn asset_arch_matches_octez_naming() {
        assert_eq!(octez_asset_arch("x86_64"), Some("x86_64"));
        assert_eq!(octez_asset_arch("aarch64"), Some("arm64"));
        assert_eq!(octez_asset_arch("riscv64"), None);
    }

    #[test]
    fn system_hint_names_packages_for_both_apt_and_dnf() {
        let hint = system_install_hint(&["lsusb", "ip"]);
        assert!(hint.contains("usbutils"), "lsusb -> usbutils: {hint}");
        assert!(hint.contains("iproute2"), "ip -> iproute2 (apt): {hint}");
        assert!(hint.contains("apt"), "apt line: {hint}");
        assert!(hint.contains("dnf"), "dnf line: {hint}");
    }

    /// Mirrors the live shape of
    /// GET /`projects/tezos%2Ftezos/packages?order_by=created_at&sort=desc`
    fn packages_fixture() -> serde_json::Value {
        serde_json::json!([
            {"id": 63_279_889, "name": "octez-evm-node-0.62", "version": "0.62", "package_type": "generic"},
            {"id": 62_219_422, "name": "octez-source-25.0", "version": "25.0", "package_type": "generic"},
            {"id": 59_967_980, "name": "octez-binaries-25.0-rc1", "version": "25.0-rc1", "package_type": "generic"},
            {"id": 57_209_896, "name": "octez-binaries-202604010917+9edf501c", "version": "202604010917+9edf501c", "package_type": "generic"},
            {"id": 58_403_971, "name": "octez-binaries-24.4", "version": "24.4", "package_type": "generic"},
            {"id": 62_218_332, "name": "octez-binaries-25.0", "version": "25.0", "package_type": "generic"},
        ])
    }

    #[test]
    fn picks_newest_stable_octez_binaries_release() {
        let release = parse_octez_packages(&packages_fixture()).expect("release found");
        assert_eq!(
            release,
            OctezRelease {
                id: 62_218_332,
                package_name: "octez-binaries-25.0".to_string(),
                version: "25.0".to_string(),
            }
        );
    }

    #[test]
    fn ignores_listing_without_stable_binaries() {
        let json = serde_json::json!([
            {"id": 1, "name": "octez-binaries-25.0-beta1", "version": "25.0-beta1", "package_type": "generic"},
            {"id": 2, "name": "octez-evm-node-0.62", "version": "0.62", "package_type": "generic"},
        ]);
        assert_eq!(parse_octez_packages(&json), None);
    }

    /// Exercises the live GitLab package registry end-to-end (~100 MB
    /// download): run explicitly with `cargo test -- --ignored`.
    #[test]
    #[ignore = "network: downloads octez-client from the GitLab package registry"]
    fn installs_octez_client_from_live_registry() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        install_octez_static(&["octez-client"], dir.path()).expect("install succeeds");
        let installed = dir.path().join("octez-client");
        let meta = std::fs::metadata(&installed).expect("binary installed");
        assert!(meta.permissions().mode() & 0o111 != 0, "must be executable");
        assert!(meta.len() > 10_000_000, "static binary should be large");
    }

    #[test]
    fn finds_file_sha256_in_package_files_listing() {
        // Mirrors the live shape of GET /packages/:id/package_files
        let json = serde_json::json!([
            {"file_name": "x86_64-octez-client", "file_sha256": "d946cbcb"},
            {"file_name": "x86_64-octez-client.sig", "file_sha256": "4a2d65e9"},
        ]);
        assert_eq!(
            find_package_file_sha256(&json, "x86_64-octez-client"),
            Some("d946cbcb".to_string())
        );
        assert_eq!(find_package_file_sha256(&json, "arm64-octez-client"), None);
    }
}
