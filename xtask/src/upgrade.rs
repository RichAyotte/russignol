use anyhow::{Context, Result, bail};
use colored::Colorize;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::image::{
    BUILDROOT_CONFIG, KernelTreeState, buildroot_commit, kernel_commit_from_config, needs_dirclean,
};
use crate::utils::{get_config_name, run_buildroot_make};

const BUILDROOT_DIR: &str = "buildroot";
const RPI_LINUX_DIR: &str = "rpi-linux";
const KERNEL_DEFCONFIG: &str =
    "rpi-signer/buildroot-external/board/russignol/linux-russignol_defconfig";
const LINUX_HASH_FILE: &str = "rpi-signer/buildroot-external/patches/linux/linux.hash";
const SHORT_COMMIT_LEN: usize = 12;
const DEFCONFIG_FILES: &[&str] = &[
    "rpi-signer/buildroot-external/configs/russignol_defconfig",
    "rpi-signer/buildroot-external/configs/russignol_hardened_defconfig",
];

// ============================================================================
// REPORT
// ============================================================================

/// A package whose locked version moved between two `Cargo.lock` revisions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageChange {
    pub name: String,
    pub from: String,
    pub to: String,
}

/// A package that only exists on one side of the comparison
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyDiff {
    pub changed: Vec<PackageChange>,
    pub added: Vec<PackageRef>,
    pub removed: Vec<PackageRef>,
}

impl DependencyDiff {
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }
}

/// Counts of what moved in `Cargo.lock`.
///
/// Held as totals rather than a listing: the lock is mostly transitive packages
/// nobody declared, so enumerating it buries the handful of requirements that
/// were actually edited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LockSummary {
    pub changed: usize,
    pub added: usize,
    pub removed: usize,
}

impl LockSummary {
    pub fn is_empty(&self) -> bool {
        self.changed == 0 && self.added == 0 && self.removed == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildrootChange {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelChange {
    pub branch: String,
    pub from_version: String,
    pub from_commit: String,
    pub to_version: String,
    pub to_commit: String,
}

/// Everything the working tree carries relative to `HEAD` after an upgrade run.
///
/// Derived from git rather than from each step's own before/after so that the
/// printed summary and the commit message describe the same thing the commit
/// actually contains, including changes an earlier interrupted run left behind.
#[derive(Debug, Clone, Default)]
pub struct UpgradeReport {
    /// Requirements declared in the workspace manifests
    pub dependencies: DependencyDiff,
    /// Totals for the resolved graph behind those requirements
    pub locked: LockSummary,
    pub buildroot: Option<BuildrootChange>,
    pub kernel: Option<KernelChange>,
    pub kernel_defconfig_changed: bool,
}

impl UpgradeReport {
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
            && self.locked.is_empty()
            && self.buildroot.is_none()
            && self.kernel.is_none()
            && !self.kernel_defconfig_changed
    }

    /// Whether anything in this report is only exercised by the SD image build.
    ///
    /// Buildroot, the kernel and its defconfig are compiled nowhere else: the
    /// host checks and the cross-compiled signer build never read them, so
    /// without the image build a change to any of them has been verified by
    /// nothing at all.
    pub fn needs_image_verification(&self) -> bool {
        self.buildroot.is_some() || self.kernel.is_some() || self.kernel_defconfig_changed
    }

    pub fn commit_message(&self) -> String {
        let mut subjects = Vec::new();
        if !self.dependencies.is_empty() || !self.locked.is_empty() {
            subjects.push("cargo dependencies");
        }
        if self.buildroot.is_some() {
            subjects.push("buildroot");
        }
        if self.kernel.is_some() || self.kernel_defconfig_changed {
            subjects.push("rpi-linux");
        }

        let mut message = format!("chore(deps): upgrade {}\n", join_and(&subjects));

        if !self.dependencies.is_empty() {
            message.push_str("\nCargo:\n");
            for change in &self.dependencies.changed {
                let _ = writeln!(
                    message,
                    "  {} {} -> {}",
                    change.name, change.from, change.to
                );
            }
            for pkg in &self.dependencies.added {
                let _ = writeln!(message, "  + {} {}", pkg.name, pkg.version);
            }
            for pkg in &self.dependencies.removed {
                let _ = writeln!(message, "  - {} {}", pkg.name, pkg.version);
            }
        }

        if !self.locked.is_empty() {
            let _ = write!(
                message,
                "\nCargo.lock: {} changed, {} added, {} removed\n",
                self.locked.changed, self.locked.added, self.locked.removed
            );
        }

        if let Some(buildroot) = &self.buildroot {
            let _ = write!(
                message,
                "\nbuildroot {} -> {}\n",
                buildroot.from, buildroot.to
            );
        }

        if let Some(kernel) = &self.kernel {
            let _ = write!(
                message,
                "\nrpi-linux ({}) {} {} -> {} {}\n",
                kernel.branch,
                kernel.from_version,
                short_commit(&kernel.from_commit),
                kernel.to_version,
                short_commit(&kernel.to_commit),
            );
        }

        if self.kernel_defconfig_changed {
            message.push_str("\nKernel defconfig regenerated against the new source.\n");
        }

        message
    }
}

fn short_commit(commit: &str) -> &str {
    &commit[..SHORT_COMMIT_LEN.min(commit.len())]
}

/// `(name, version)` for every package pinned in a `Cargo.lock`
///
/// Package keys sit at column zero while `dependencies` entries are indented,
/// so anchoring the match to the line start is what keeps a dependency listing
/// from being read as a package of its own.
fn parse_lock_packages(lock: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut pending_name: Option<&str> = None;

    for line in lock.lines() {
        if line == "[[package]]" {
            pending_name = None;
        } else if let Some(rest) = line.strip_prefix("name = \"") {
            pending_name = rest.strip_suffix('"');
        } else if let Some(rest) = line.strip_prefix("version = \"")
            && let Some(version) = rest.strip_suffix('"')
            && let Some(name) = pending_name.take()
        {
            packages.push((name.to_string(), version.to_string()));
        }
    }

    packages
}

/// Version requirements declared by a `Cargo.toml`, as `(name, requirement)`
///
/// Only `*dependencies` tables are read, so the package's own `version` key and
/// anything under `[features]` cannot be mistaken for a requirement. Entries
/// carrying no version of their own — `{ workspace = true }`, path-only deps —
/// have nothing to report and are left out.
fn parse_manifest_dependencies(manifest: &str) -> Vec<(String, String)> {
    let mut dependencies = Vec::new();
    let mut in_dependencies = false;

    for line in manifest.lines() {
        let line = line.trim();

        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_dependencies = section.ends_with("dependencies");
            continue;
        }

        if !in_dependencies || line.starts_with('#') {
            continue;
        }

        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }

        if let Some(requirement) = parse_requirement(value.trim()) {
            dependencies.push((name.to_string(), requirement));
        }
    }

    dependencies
}

/// The version out of either `"1.0"` or `{ version = "1.0", .. }`
fn parse_requirement(value: &str) -> Option<String> {
    let quoted = if value.starts_with('"') {
        value
    } else if value.starts_with('{') {
        let version = value.find("version")?;
        value[version..].split_once('=')?.1
    } else {
        return None;
    };

    let rest = quoted.trim().strip_prefix('"')?;
    rest.find('"').map(|end| rest[..end].to_string())
}

/// Drop duplicate `(name, version)` pairs so a requirement repeated across
/// manifests still resolves to a single entry when paired up
fn dedup_pairs(mut pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

fn lock_summary(old: &str, new: &str) -> LockSummary {
    let diff = diff_packages(&parse_lock_packages(old), &parse_lock_packages(new));

    LockSummary {
        changed: diff.changed.len(),
        added: diff.added.len(),
        removed: diff.removed.len(),
    }
}

fn diff_packages(
    old_packages: &[(String, String)],
    new_packages: &[(String, String)],
) -> DependencyDiff {
    let gone = versions_by_name(old_packages, new_packages);
    let fresh = versions_by_name(new_packages, old_packages);

    let mut diff = DependencyDiff::default();
    let mut names: Vec<&String> = gone.keys().chain(fresh.keys()).collect();
    names.sort_unstable();
    names.dedup();

    for name in names {
        // Pairing only holds when the name resolved to exactly one version on
        // each side; a crate locked at several majors keeps its versions listed
        // separately so a dropped major never reads as a downgrade of the rest.
        match (gone.get(name), fresh.get(name)) {
            (Some(from), Some(to)) if from.len() == 1 && to.len() == 1 => {
                diff.changed.push(PackageChange {
                    name: name.clone(),
                    from: from[0].clone(),
                    to: to[0].clone(),
                });
            }
            (from, to) => {
                for version in to.into_iter().flatten() {
                    diff.added.push(PackageRef {
                        name: name.clone(),
                        version: version.clone(),
                    });
                }
                for version in from.into_iter().flatten() {
                    diff.removed.push(PackageRef {
                        name: name.clone(),
                        version: version.clone(),
                    });
                }
            }
        }
    }

    diff
}

/// Versions present in `packages` but absent from `other`, grouped by name
fn versions_by_name(
    packages: &[(String, String)],
    other: &[(String, String)],
) -> BTreeMap<String, Vec<String>> {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, version) in packages {
        if !other.contains(&(name.clone(), version.clone())) {
            grouped
                .entry(name.clone())
                .or_default()
                .push(version.clone());
        }
    }
    grouped
}

/// Join into prose: `a`, `a and b`, `a, b and c`
fn join_and(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [only] => (*only).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

impl UpgradeReport {
    fn from_git() -> Result<Self> {
        let head_lock = git_output(&["show", "HEAD:Cargo.lock"]).unwrap_or_default();
        let working_lock =
            std::fs::read_to_string("Cargo.lock").context("Failed to read Cargo.lock")?;

        Ok(Self {
            dependencies: declared_dependency_diff()?,
            locked: lock_summary(&head_lock, &working_lock),
            buildroot: detect_buildroot_change(),
            kernel: detect_kernel_change()?,
            kernel_defconfig_changed: differs_from_head(KERNEL_DEFCONFIG)?,
        })
    }
}

/// Requirement changes across every workspace manifest the upgrade edited
fn declared_dependency_diff() -> Result<DependencyDiff> {
    let mut before = Vec::new();
    let mut after = Vec::new();

    for path in changed_manifests()? {
        let head = git_output(&["show", &format!("HEAD:{path}")]).unwrap_or_default();
        let working =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {path}"))?;

        before.extend(parse_manifest_dependencies(&head));
        after.extend(parse_manifest_dependencies(&working));
    }

    Ok(diff_packages(&dedup_pairs(before), &dedup_pairs(after)))
}

/// The commit recorded for a submodule in `HEAD` and the one checked out now
fn submodule_commit_change(path: &str) -> Option<(String, String)> {
    let head = git_output(&["rev-parse", &format!("HEAD:{path}")]).ok()?;
    let current = git_output(&["-C", path, "rev-parse", "HEAD"]).ok()?;
    (head != current).then_some((head, current))
}

fn detect_buildroot_change() -> Option<BuildrootChange> {
    let (from, to) = submodule_commit_change(BUILDROOT_DIR)?;
    Some(BuildrootChange {
        from: buildroot_release(&from),
        to: buildroot_release(&to),
    })
}

/// Release tag for a buildroot commit, falling back to the short commit when it
/// is not sitting on a release
fn buildroot_release(commit: &str) -> String {
    git_output(&[
        "-C",
        BUILDROOT_DIR,
        "describe",
        "--tags",
        "--exact-match",
        commit,
    ])
    .unwrap_or_else(|_| short_commit(commit).to_string())
}

fn detect_kernel_change() -> Result<Option<KernelChange>> {
    let Some((from_commit, to_commit)) = submodule_commit_change(RPI_LINUX_DIR) else {
        return Ok(None);
    };

    Ok(Some(KernelChange {
        branch: get_rpi_linux_branch()?,
        from_version: kernel_version_at(&from_commit)?,
        from_commit,
        to_version: get_kernel_version(RPI_LINUX_DIR)?,
        to_commit,
    }))
}

fn kernel_version_at(commit: &str) -> Result<String> {
    let makefile = git_output(&["-C", RPI_LINUX_DIR, "show", &format!("{commit}:Makefile")])
        .with_context(|| format!("Failed to read kernel Makefile at {commit}"))?;
    parse_kernel_version(&makefile)
}

/// Whether `path` differs between `HEAD` and the working tree
fn differs_from_head(path: &str) -> Result<bool> {
    let status = Command::new("git")
        .args(["diff", "--quiet", "HEAD", "--", path])
        .status()
        .with_context(|| format!("Failed to run git diff for {path}"))?;

    Ok(!status.success())
}

fn print_report(report: &UpgradeReport) {
    println!("{}", "Upgrade summary".cyan().bold());

    if report.dependencies.is_empty() {
        println!("  Cargo dependencies   {}", "unchanged".dimmed());
    } else {
        println!(
            "  Cargo dependencies   {} changed, {} added, {} removed",
            report.dependencies.changed.len(),
            report.dependencies.added.len(),
            report.dependencies.removed.len()
        );
        for change in &report.dependencies.changed {
            println!(
                "    {} {} → {}",
                change.name,
                change.from.dimmed(),
                change.to.green()
            );
        }
        for pkg in &report.dependencies.added {
            println!("    {} {} {}", "+".green(), pkg.name, pkg.version.dimmed());
        }
        for pkg in &report.dependencies.removed {
            println!("    {} {} {}", "-".red(), pkg.name, pkg.version.dimmed());
        }
    }

    if report.locked.is_empty() {
        println!("  Cargo.lock           {}", "unchanged".dimmed());
    } else {
        println!(
            "  Cargo.lock           {} changed, {} added, {} removed",
            report.locked.changed, report.locked.added, report.locked.removed
        );
    }

    match &report.buildroot {
        Some(buildroot) => println!(
            "  Buildroot            {} → {}",
            buildroot.from.dimmed(),
            buildroot.to.green()
        ),
        None => println!("  Buildroot            {}", "unchanged".dimmed()),
    }

    match &report.kernel {
        Some(kernel) => println!(
            "  Linux kernel         {} {} → {} {} ({})",
            kernel.from_version,
            short_commit(&kernel.from_commit).dimmed(),
            kernel.to_version,
            short_commit(&kernel.to_commit).green(),
            kernel.branch
        ),
        None => println!("  Linux kernel         {}", "unchanged".dimmed()),
    }

    if report.kernel_defconfig_changed {
        println!("  Kernel defconfig     {}", "new options captured".green());
    } else {
        println!("  Kernel defconfig     {}", "unchanged".dimmed());
    }
}

// ============================================================================
// VERIFICATION
// ============================================================================

/// What a verification run covered.
///
/// Carries which checks ran rather than a bare pass/fail, so the decision to
/// commit rests on what was actually exercised instead of on which flags the
/// caller happened to pass.
struct Verification {
    passed: Vec<&'static str>,
    image_built: bool,
}

/// Run everything that has to be green before an upgrade may commit itself,
/// stopping at the first failure so a broken upgrade never reaches a commit.
fn run_checks(skip_image: bool) -> Result<Verification> {
    println!("{}", "Verifying".cyan().bold());
    let mut passed = Vec::new();

    println!("  Linting...");
    crate::run_cargo(
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        "Clippy failed after upgrade",
    )?;
    passed.push("clippy");

    println!("  Checking formatting...");
    crate::run_cargo(
        &["fmt", "--all", "--check"],
        "Formatting check failed after upgrade",
    )?;
    passed.push("fmt");

    crate::cmd_test()?;
    passed.push("tests");

    crate::build::build_rpi_signer(false)?;
    passed.push("aarch64 signer");

    // Release builds differ from the test compile by LTO, panic=abort and
    // stripping, so a shipped binary that only ever gets compiled for tests has
    // never been produced the way it is distributed.
    crate::cmd_host_utility(crate::Arch::All, false, false)?;
    passed.push("host utility");

    if skip_image {
        println!("  {} SD image build skipped (--no-image)", "⚠".yellow());
    } else {
        crate::image::build_image(false, false)?;
        passed.push("sd image");
    }

    Ok(Verification {
        passed,
        image_built: !skip_image,
    })
}

// ============================================================================
// COMMIT
// ============================================================================

fn commit_upgrade(message: &str, report: &UpgradeReport) -> Result<String> {
    stage_upgrade_paths(report)?;
    git_run(&["commit", "-m", message])?;
    git_output(&["rev-parse", "--short", "HEAD"])
}

/// Stage only the paths an upgrade owns, so unrelated edits already in the tree
/// stay out of the commit
fn stage_upgrade_paths(report: &UpgradeReport) -> Result<()> {
    let mut paths = vec![
        "Cargo.lock".to_string(),
        LINUX_HASH_FILE.to_string(),
        KERNEL_DEFCONFIG.to_string(),
    ];
    paths.extend(DEFCONFIG_FILES.iter().map(|path| (*path).to_string()));
    paths.extend(changed_manifests()?);
    if report.buildroot.is_some() {
        paths.push(BUILDROOT_DIR.to_string());
    }
    if report.kernel.is_some() {
        paths.push(RPI_LINUX_DIR.to_string());
    }

    let mut args = vec!["add", "--"];
    args.extend(paths.iter().map(String::as_str));
    git_run(&args)
}

fn changed_manifests() -> Result<Vec<String>> {
    let changed = git_output(&["diff", "HEAD", "--name-only"])?;

    Ok(changed
        .lines()
        .filter(|path| path.ends_with("Cargo.toml"))
        .map(str::to_string)
        .collect())
}

// ============================================================================
// ENTRY POINT
// ============================================================================

/// What `cargo xtask upgrade` should do once the upgrades themselves are applied
#[derive(Debug, Clone, Copy)]
pub struct UpgradeOptions {
    pub no_verify: bool,
    pub no_image: bool,
    pub no_commit: bool,
}

pub fn cmd_upgrade(opts: UpgradeOptions) -> Result<()> {
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

    let report = UpgradeReport::from_git()?;
    println!();
    print_report(&report);
    println!();

    if report.is_empty() {
        println!(
            "{}",
            "Already up to date — nothing to verify or commit."
                .green()
                .bold()
        );
        return Ok(());
    }

    let verification = if opts.no_verify {
        println!("  {} Verification skipped (--no-verify)", "⚠".yellow());
        None
    } else {
        let verification = run_checks(opts.no_image)?;
        println!(
            "  {} Passed: {}",
            "✓".green(),
            verification.passed.join(", ")
        );
        Some(verification)
    };

    println!();
    finish(&report, verification.as_ref(), opts.no_commit)
}

fn finish(
    report: &UpgradeReport,
    verification: Option<&Verification>,
    no_commit: bool,
) -> Result<()> {
    if no_commit {
        println!("  {} Commit skipped (--no-commit)", "⚠".yellow());
        return Ok(());
    }

    let Some(verification) = verification else {
        println!(
            "  {} Commit skipped: verification did not run",
            "⚠".yellow()
        );
        return Ok(());
    };

    if report.needs_image_verification() && !verification.image_built {
        println!(
            "  {} Commit skipped: the SD image build is the only check that exercises \
             a buildroot or kernel change",
            "⚠".yellow()
        );
        return Ok(());
    }

    let message = report.commit_message();
    let commit = commit_upgrade(&message, report)?;

    println!(
        "  {} Committed {} {}",
        "✓".green(),
        commit.yellow(),
        message.lines().next().unwrap_or_default()
    );

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

/// Newest stable buildroot release among `tags`.
///
/// Point releases carry the security fixes made to a series after its `YYYY.MM`
/// cut, so `YYYY.MM.N` has to rank above the bare `YYYY.MM` it patches. Ordering
/// on the parsed numbers rather than on the tag text is what keeps `.10` above
/// `.9`, and release candidates are excluded by the pattern.
fn latest_buildroot_release(tags: &str) -> Option<String> {
    let pattern = Regex::new(r"^(\d{4})\.(\d{2})(?:\.(\d+))?$").expect("valid regex");

    tags.lines()
        .filter_map(|tag| {
            let caps = pattern.captures(tag.trim())?;
            let year: u32 = caps[1].parse().ok()?;
            let month: u32 = caps[2].parse().ok()?;
            let point: u32 = caps.get(3).map_or(Some(0), |m| m.as_str().parse().ok())?;

            Some((year, month, point, tag.trim().to_string()))
        })
        .max()
        .map(|(_, _, _, tag)| tag)
}

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

    let tags_output = git_output(&["-C", BUILDROOT_DIR, "tag", "-l"])?;
    let latest =
        latest_buildroot_release(&tags_output).context("No stable buildroot releases in tags")?;

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

    parse_kernel_version(&content).with_context(|| format!("Failed to parse {makefile_path}"))
}

fn parse_kernel_version(content: &str) -> Result<String> {
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
        bail!("No VERSION line in kernel Makefile");
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

    // Check if any defconfig needs updating (use first file to detect)
    let first_content = std::fs::read_to_string(DEFCONFIG_FILES[0])
        .with_context(|| format!("Failed to read {}", DEFCONFIG_FILES[0]))?;
    let already_current = kernel_commit_from_config(&first_content).as_deref() == Some(&new_commit);

    for path in DEFCONFIG_FILES {
        let filename = Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        let content =
            std::fs::read_to_string(path).with_context(|| format!("Failed to read {path}"))?;

        let Some(old_commit) = kernel_commit_from_config(&content) else {
            println!("  {} No tarball URL found in {filename}", "⚠".yellow());
            continue;
        };

        if old_commit == new_commit {
            println!("  {} {filename} already up to date", "✓".green());
            continue;
        }

        let new_content = content.replace(&old_commit, &new_commit);
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
    let dl_dir = PathBuf::from(BUILDROOT_DIR).join("dl/linux");
    let cached_path = dl_dir.join(&tarball_name);

    let sha256_hex = if cached_path.exists() {
        println!("  Computing hash from cached tarball...");
        compute_file_sha256(&cached_path)?
    } else {
        println!("  Downloading kernel tarball for hash verification...");
        std::fs::create_dir_all(&dl_dir)
            .with_context(|| format!("Failed to create {}", dl_dir.display()))?;
        let tmp_path = download_tarball(&tarball_url, &dl_dir, &tarball_name)?;
        let hash = compute_file_sha256(&tmp_path)?;
        if let Err(e) = std::fs::rename(&tmp_path, &cached_path) {
            println!(
                "  {} Could not cache tarball ({e}); it will be re-downloaded at build time",
                "⚠".yellow()
            );
            std::fs::remove_file(&tmp_path).ok();
        }
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
    Ok(hex::encode(hasher.finalize()))
}

/// Download `url` into `dest_dir` under a temporary name. Downloading into the
/// buildroot cache dir keeps the file on the same filesystem as its final
/// location, so the caller's move is a rename rather than a cross-device copy
/// that would fail when `$TMPDIR` is a separate mount.
fn download_tarball(url: &str, dest_dir: &Path, filename: &str) -> Result<PathBuf> {
    let tmp_path = dest_dir.join(format!("{filename}.tmp"));

    let status = Command::new("wget")
        .args(["-q", "-O"])
        .arg(&tmp_path)
        .arg(url)
        .status()
        .context("Failed to run wget")?;

    if !status.success() {
        std::fs::remove_file(&tmp_path).ok();
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
    let config_name = get_config_name(false);
    let external_tree = std::env::current_dir()?.join("rpi-signer/buildroot-external");
    println!("  Loading buildroot config...");
    run_buildroot_make(&buildroot_dir, &external_tree, &[config_name])?;

    // Buildroot's stamps record that a step ran, not what it ran against, so a
    // tree left behind by earlier inputs is reused as it stands: linux-configure
    // is a no-op and linux-update-defconfig then saves those earlier inputs'
    // config. Removing the tree whenever the source, buildroot or config moved is
    // what makes the saved defconfig come from the current ones, and what stops
    // the next image build from packing a kernel built from the previous ones.
    // Keeping it otherwise preserves a kernel that would be compiled again from
    // scratch.
    let loaded_config = std::fs::read_to_string(buildroot_dir.join(BUILDROOT_CONFIG))
        .with_context(|| format!("Failed to read the loaded {BUILDROOT_CONFIG}"))?;
    let kernel_state = KernelTreeState {
        config: config_name.to_string(),
        buildroot_commit: buildroot_commit(&buildroot_dir)?,
        kernel_commit: kernel_commit_from_config(&loaded_config)
            .context("No kernel source commit pinned by the loaded configuration")?,
    };

    if needs_dirclean(
        KernelTreeState::read(&buildroot_dir).as_ref(),
        &kernel_state,
    ) {
        println!("  Clearing previous kernel build...");
        run_buildroot_make(&buildroot_dir, &external_tree, &["linux-dirclean"])?;
    }

    // Configure the kernel (rsyncs from the local submodule when available),
    // then save back as a minimal defconfig, capturing any new options with defaults.
    println!("  Configuring kernel (this may take a moment)...");
    run_buildroot_make(&buildroot_dir, &external_tree, &["linux-configure"])?;
    println!("  Saving kernel defconfig...");
    run_buildroot_make(&buildroot_dir, &external_tree, &["linux-update-defconfig"])?;

    kernel_state.save(&buildroot_dir)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_LOCK: &str = r#"version = 4

[[package]]
name = "anyhow"
version = "1.0.103"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaa"

[[package]]
name = "blst"
version = "0.3.16"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbb"

[[package]]
name = "proc-macro-error2"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ccc"

[[package]]
name = "russignol-signer"
version = "0.26.0"
dependencies = [
 "anyhow",
 "blst",
]
"#;

    const NEW_LOCK: &str = r#"version = 4

[[package]]
name = "anyhow"
version = "1.0.104"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ddd"

[[package]]
name = "blst"
version = "0.3.17"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eee"

[[package]]
name = "jiff-core"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fff"

[[package]]
name = "russignol-signer"
version = "0.26.0"
dependencies = [
 "anyhow",
 "blst",
]
"#;

    const OLD_MANIFEST: &str = r#"[package]
name = "russignol-signer"
version = "0.26.0"

[features]
perf-trace = []

[dependencies]
anyhow = "1.0.103"
clap = { version = "4.6.1", features = ["derive"] }
log = { workspace = true }
russignol-storage = { version = "0.1.0", path = "../storage" }
russignol-ui = { path = "../libs/ui" }

[dev-dependencies]
tempfile = "3.26.0"
"#;

    const NEW_MANIFEST: &str = r#"[package]
name = "russignol-signer"
version = "0.26.0"

[features]
perf-trace = []

[dependencies]
anyhow = "1.0.104"
bytes = "1.12.1"
clap = { version = "4.6.5", features = ["derive"] }
log = { workspace = true }
russignol-storage = { version = "0.1.0", path = "../storage" }
russignol-ui = { path = "../libs/ui" }

[dev-dependencies]
tempfile = "3.27.0"
"#;

    fn lock_diff(old: &str, new: &str) -> DependencyDiff {
        diff_packages(&parse_lock_packages(old), &parse_lock_packages(new))
    }

    fn manifest_diff() -> DependencyDiff {
        diff_packages(
            &dedup_pairs(parse_manifest_dependencies(OLD_MANIFEST)),
            &dedup_pairs(parse_manifest_dependencies(NEW_MANIFEST)),
        )
    }

    fn kernel_change() -> KernelChange {
        KernelChange {
            branch: "rpi-6.18.y".to_string(),
            from_version: "6.18.0".to_string(),
            from_commit: "f2f1e849f4fe4fde70eaa20b136061a1552bf014".to_string(),
            to_version: "6.18.0".to_string(),
            to_commit: "825dba6c63eeb40a62699d1f8a4aa3f02b0eaf49".to_string(),
        }
    }

    #[test]
    fn parses_name_and_version_of_each_locked_package() {
        let pkgs = parse_lock_packages(OLD_LOCK);

        assert_eq!(
            pkgs,
            vec![
                ("anyhow".to_string(), "1.0.103".to_string()),
                ("blst".to_string(), "0.3.16".to_string()),
                ("proc-macro-error2".to_string(), "2.0.1".to_string()),
                ("russignol-signer".to_string(), "0.26.0".to_string()),
            ]
        );
    }

    #[test]
    fn ignores_dependency_lists_and_the_lock_format_version() {
        // `dependencies = [ "anyhow", ]` names packages without versions, and the
        // leading `version = 4` is the lock format rather than a package.
        let pkgs = parse_lock_packages(NEW_LOCK);

        assert_eq!(pkgs.len(), 4);
        assert!(!pkgs.iter().any(|(name, _)| name == "version"));
    }

    #[test]
    fn diff_reports_version_moves_as_changes() {
        let diff = lock_diff(OLD_LOCK, NEW_LOCK);

        assert_eq!(
            diff.changed,
            vec![
                PackageChange {
                    name: "anyhow".to_string(),
                    from: "1.0.103".to_string(),
                    to: "1.0.104".to_string(),
                },
                PackageChange {
                    name: "blst".to_string(),
                    from: "0.3.16".to_string(),
                    to: "0.3.17".to_string(),
                },
            ]
        );
    }

    #[test]
    fn diff_separates_packages_that_only_appear_on_one_side() {
        let diff = lock_diff(OLD_LOCK, NEW_LOCK);

        assert_eq!(
            diff.added,
            vec![PackageRef {
                name: "jiff-core".to_string(),
                version: "0.1.0".to_string(),
            }]
        );
        assert_eq!(
            diff.removed,
            vec![PackageRef {
                name: "proc-macro-error2".to_string(),
                version: "2.0.1".to_string(),
            }]
        );
    }

    #[test]
    fn diff_of_identical_locks_is_empty() {
        assert!(lock_diff(OLD_LOCK, OLD_LOCK).is_empty());
    }

    #[test]
    fn a_package_locked_at_two_versions_is_not_collapsed_into_a_change() {
        // getrandom 0.3 and 0.4 coexist in this workspace; dropping one is a
        // removal, not a downgrade of the one that stayed.
        let old = "[[package]]\nname = \"getrandom\"\nversion = \"0.2.16\"\n\n[[package]]\nname = \"getrandom\"\nversion = \"0.3.4\"\n";
        let new = "[[package]]\nname = \"getrandom\"\nversion = \"0.3.4\"\n";

        let diff = lock_diff(old, new);

        assert!(diff.changed.is_empty());
        assert_eq!(
            diff.removed,
            vec![PackageRef {
                name: "getrandom".to_string(),
                version: "0.2.16".to_string(),
            }]
        );
    }

    #[test]
    fn manifest_parse_reads_both_plain_and_inline_table_requirements() {
        let deps = parse_manifest_dependencies(OLD_MANIFEST);

        assert!(deps.contains(&("anyhow".to_string(), "1.0.103".to_string())));
        assert!(deps.contains(&("clap".to_string(), "4.6.1".to_string())));
        assert!(deps.contains(&("tempfile".to_string(), "3.26.0".to_string())));
    }

    #[test]
    fn manifest_parse_skips_entries_that_declare_no_version() {
        let deps = parse_manifest_dependencies(OLD_MANIFEST);

        assert!(!deps.iter().any(|(name, _)| name == "log"));
        assert!(!deps.iter().any(|(name, _)| name == "russignol-ui"));
    }

    #[test]
    fn manifest_parse_ignores_keys_outside_dependency_tables() {
        // `[package] version` and `[features] perf-trace` sit in the same file
        // and would otherwise read as requirements.
        let deps = parse_manifest_dependencies(OLD_MANIFEST);

        assert!(!deps.iter().any(|(name, _)| name == "version"));
        assert!(!deps.iter().any(|(name, _)| name == "name"));
        assert!(!deps.iter().any(|(name, _)| name == "perf-trace"));
    }

    #[test]
    fn manifest_parse_keeps_a_path_dependency_that_pins_a_version() {
        let deps = parse_manifest_dependencies(OLD_MANIFEST);

        assert!(deps.contains(&("russignol-storage".to_string(), "0.1.0".to_string())));
    }

    #[test]
    fn a_requirement_repeated_across_manifests_collapses_to_one_entry() {
        let both = dedup_pairs(
            [
                parse_manifest_dependencies(OLD_MANIFEST),
                parse_manifest_dependencies(OLD_MANIFEST),
            ]
            .concat(),
        );

        assert_eq!(both.iter().filter(|(name, _)| name == "anyhow").count(), 1);
    }

    const BUILDROOT_TAGS: &str = "2025.11\n2025.11-rc1\n2025.11.3\n2026.02\n2026.02-rc3\n2026.02.3\n2026.05\n2026.05-rc4\n2026.05.1\n";

    #[test]
    fn a_point_release_outranks_the_series_it_patches() {
        assert_eq!(
            latest_buildroot_release(BUILDROOT_TAGS).as_deref(),
            Some("2026.05.1")
        );
    }

    #[test]
    fn release_candidates_are_not_releases() {
        assert_eq!(
            latest_buildroot_release("2026.05\n2026.08-rc1\n2026.08-rc2\n").as_deref(),
            Some("2026.05")
        );
    }

    #[test]
    fn a_new_series_outranks_an_older_series_point_release() {
        assert_eq!(
            latest_buildroot_release("2026.02.9\n2026.05\n").as_deref(),
            Some("2026.05")
        );
    }

    #[test]
    fn point_releases_are_ordered_numerically() {
        // Ordering on tag text would put .9 above .10.
        assert_eq!(
            latest_buildroot_release("2026.05.9\n2026.05.10\n").as_deref(),
            Some("2026.05.10")
        );
    }

    #[test]
    fn unrelated_tags_are_ignored() {
        assert_eq!(latest_buildroot_release("v1.2.3\nnightly\n"), None);
    }

    #[test]
    fn kernel_version_comes_from_the_makefile_preamble() {
        let makefile = "# SPDX-License-Identifier: GPL-2.0\nVERSION = 6\nPATCHLEVEL = 18\nSUBLEVEL = 0\nEXTRAVERSION =\nNAME = Baby Opossum Posse\n";

        assert_eq!(parse_kernel_version(makefile).unwrap(), "6.18.0");
    }

    #[test]
    fn kernel_version_parse_fails_without_a_version_line() {
        assert!(parse_kernel_version("NAME = nothing useful\n").is_err());
    }

    #[test]
    fn join_and_reads_as_prose() {
        assert_eq!(join_and(&["a"]), "a");
        assert_eq!(join_and(&["a", "b"]), "a and b");
        assert_eq!(join_and(&["a", "b", "c"]), "a, b and c");
    }

    #[test]
    fn commit_subject_names_only_what_actually_moved() {
        let cargo_only = UpgradeReport {
            dependencies: manifest_diff(),
            locked: lock_summary(OLD_LOCK, NEW_LOCK),
            ..UpgradeReport::default()
        };
        assert_eq!(
            cargo_only.commit_message().lines().next().unwrap(),
            "chore(deps): upgrade cargo dependencies"
        );

        let cargo_and_kernel = UpgradeReport {
            dependencies: manifest_diff(),
            locked: lock_summary(OLD_LOCK, NEW_LOCK),
            kernel: Some(kernel_change()),
            ..UpgradeReport::default()
        };
        assert_eq!(
            cargo_and_kernel.commit_message().lines().next().unwrap(),
            "chore(deps): upgrade cargo dependencies and rpi-linux"
        );

        let everything = UpgradeReport {
            dependencies: manifest_diff(),
            locked: lock_summary(OLD_LOCK, NEW_LOCK),
            buildroot: Some(BuildrootChange {
                from: "2026.02".to_string(),
                to: "2026.05".to_string(),
            }),
            kernel: Some(kernel_change()),
            kernel_defconfig_changed: true,
        };
        assert_eq!(
            everything.commit_message().lines().next().unwrap(),
            "chore(deps): upgrade cargo dependencies, buildroot and rpi-linux"
        );
    }

    #[test]
    fn commit_body_lists_declared_requirements() {
        let report = UpgradeReport {
            dependencies: manifest_diff(),
            ..UpgradeReport::default()
        };

        let message = report.commit_message();

        assert!(message.contains("anyhow 1.0.103 -> 1.0.104"));
        assert!(message.contains("clap 4.6.1 -> 4.6.5"));
        assert!(message.contains("tempfile 3.26.0 -> 3.27.0"));
        assert!(message.contains("+ bytes 1.12.1"));
    }

    #[test]
    fn commit_body_summarises_the_lock_instead_of_listing_it() {
        let report = UpgradeReport {
            dependencies: manifest_diff(),
            locked: lock_summary(OLD_LOCK, NEW_LOCK),
            ..UpgradeReport::default()
        };

        let message = report.commit_message();

        assert!(message.contains("Cargo.lock: 2 changed, 1 added, 1 removed"));
        // blst moved and jiff-core appeared in the lock alone; neither was
        // declared, so neither belongs in the list of requirements.
        assert!(!message.contains("blst"));
        assert!(!message.contains("jiff-core"));
    }

    #[test]
    fn a_lock_only_change_is_still_worth_committing() {
        let report = UpgradeReport {
            locked: lock_summary(OLD_LOCK, NEW_LOCK),
            ..UpgradeReport::default()
        };

        assert!(!report.is_empty());
        assert_eq!(
            report.commit_message().lines().next().unwrap(),
            "chore(deps): upgrade cargo dependencies"
        );
    }

    #[test]
    fn commit_body_records_submodule_moves_with_short_commits() {
        let report = UpgradeReport {
            buildroot: Some(BuildrootChange {
                from: "2026.02".to_string(),
                to: "2026.05".to_string(),
            }),
            kernel: Some(kernel_change()),
            ..UpgradeReport::default()
        };

        let message = report.commit_message();

        assert!(message.contains("buildroot 2026.02 -> 2026.05"));
        assert!(
            message.contains("rpi-linux (rpi-6.18.y) 6.18.0 f2f1e849f4fe -> 6.18.0 825dba6c63ee")
        );
    }

    #[test]
    fn subject_and_body_are_separated_by_a_blank_line() {
        let report = UpgradeReport {
            dependencies: manifest_diff(),
            ..UpgradeReport::default()
        };

        let message = report.commit_message();
        let mut lines = message.lines();
        lines.next().expect("subject");

        assert_eq!(lines.next(), Some(""));
    }

    #[test]
    fn an_unchanged_tree_reports_nothing_to_commit() {
        assert!(UpgradeReport::default().is_empty());
    }

    #[test]
    fn cargo_dependencies_alone_are_covered_without_an_image() {
        let report = UpgradeReport {
            dependencies: manifest_diff(),
            locked: lock_summary(OLD_LOCK, NEW_LOCK),
            ..UpgradeReport::default()
        };

        assert!(!report.needs_image_verification());
    }

    #[test]
    fn a_buildroot_move_is_only_exercised_by_the_image_build() {
        let report = UpgradeReport {
            buildroot: Some(BuildrootChange {
                from: "2026.02".to_string(),
                to: "2026.05".to_string(),
            }),
            ..UpgradeReport::default()
        };

        assert!(report.needs_image_verification());
    }

    #[test]
    fn a_kernel_move_is_only_exercised_by_the_image_build() {
        let report = UpgradeReport {
            kernel: Some(kernel_change()),
            ..UpgradeReport::default()
        };

        assert!(report.needs_image_verification());
    }

    #[test]
    fn a_regenerated_kernel_defconfig_is_only_exercised_by_the_image_build() {
        let report = UpgradeReport {
            kernel_defconfig_changed: true,
            ..UpgradeReport::default()
        };

        assert!(report.needs_image_verification());
    }

    #[test]
    fn a_regenerated_kernel_defconfig_alone_is_still_a_change() {
        let report = UpgradeReport {
            kernel_defconfig_changed: true,
            ..UpgradeReport::default()
        };

        assert!(!report.is_empty());
        assert_eq!(
            report.commit_message().lines().next().unwrap(),
            "chore(deps): upgrade rpi-linux"
        );
    }
}
