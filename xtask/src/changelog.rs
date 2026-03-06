//! Changelog generation from Conventional Commits

use anyhow::{Context, Result, bail};
use chrono::{Local, NaiveDate};
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::{Command, Stdio};

/// Semantic version bump type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BumpType {
    /// Breaking change - increment major version
    Major,
    /// New feature - increment minor version
    Minor,
    /// Bug fix or other change - increment patch version
    Patch,
}

impl std::fmt::Display for BumpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Major => write!(f, "major"),
            Self::Minor => write!(f, "minor"),
            Self::Patch => write!(f, "patch"),
        }
    }
}

/// Type of commit according to Conventional Commits spec
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitType {
    Feat,
    Fix,
    Docs,
    Refactor,
    Test,
    Chore,
    Perf,
    Style,
    Ci,
    Build,
    Other,
}

impl CommitType {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "feat" => Self::Feat,
            "fix" => Self::Fix,
            "docs" => Self::Docs,
            "refactor" => Self::Refactor,
            "test" => Self::Test,
            "chore" => Self::Chore,
            "perf" => Self::Perf,
            "style" => Self::Style,
            "ci" => Self::Ci,
            "build" => Self::Build,
            _ => Self::Other,
        }
    }

    fn section_title(self) -> &'static str {
        match self {
            Self::Feat => "Added",
            Self::Fix => "Fixed",
            Self::Docs => "Documentation",
            Self::Refactor => "Refactoring",
            Self::Test => "Tests",
            Self::Chore => "Chores",
            Self::Perf => "Changed",
            Self::Style => "Style",
            Self::Ci => "CI",
            Self::Build => "Build",
            Self::Other => "Other",
        }
    }

    /// Order for display - lower is higher priority
    fn display_order(self) -> u8 {
        match self {
            Self::Feat => 0,
            Self::Fix => 1,
            Self::Perf => 2,
            Self::Refactor => 3,
            Self::Docs => 4,
            Self::Test => 5,
            Self::Build => 6,
            Self::Ci => 7,
            Self::Style => 8,
            Self::Chore => 9,
            Self::Other => 10,
        }
    }

    /// Whether this commit type should be excluded from changelogs
    fn is_excluded(self) -> bool {
        matches!(
            self,
            Self::Docs | Self::Refactor | Self::Test | Self::Style | Self::Ci | Self::Other
        )
    }
}

/// Scopes excluded from release changelogs (not part of the shipped product)
const EXCLUDED_SCOPES: &[&str] = &["website"];

/// A parsed conventional commit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommit {
    pub commit_type: CommitType,
    pub scope: Option<String>,
    pub description: String,
    pub hash: String,
    pub breaking: bool,
}

impl ParsedCommit {
    /// Whether this commit's scope is excluded from release changelogs
    fn is_excluded_scope(&self) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|s| EXCLUDED_SCOPES.contains(&s.as_str()))
    }
}

/// Parse a commit line in format "hash|subject"
#[must_use]
pub fn parse_commit(line: &str) -> Option<ParsedCommit> {
    let (hash, subject) = line.split_once('|')?;
    let hash = hash.trim().to_string();
    let subject = subject.trim();

    // Match: type(scope)!: description OR type!: description OR type(scope): description OR type: description
    let re = Regex::new(r"^(\w+)(?:\(([^)]+)\))?(!)?: (.+)$").ok()?;

    if let Some(caps) = re.captures(subject) {
        let type_str = caps.get(1)?.as_str();
        let scope = caps.get(2).map(|m| m.as_str().to_string());
        let breaking = caps.get(3).is_some();
        let description = caps.get(4)?.as_str().to_string();

        Some(ParsedCommit {
            commit_type: CommitType::from_str(type_str),
            scope,
            description,
            hash,
            breaking,
        })
    } else {
        // Non-conventional commit - treat as Other
        Some(ParsedCommit {
            commit_type: CommitType::Other,
            scope: None,
            description: subject.to_string(),
            hash,
            breaking: false,
        })
    }
}

/// Get the most recent tag reachable from HEAD
///
/// # Errors
///
/// Returns an error if the git command fails.
pub fn get_current_tag() -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0", "HEAD"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("Failed to run git describe")?;

    if output.status.success() {
        let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if tag.is_empty() {
            Ok(None)
        } else {
            Ok(Some(tag))
        }
    } else {
        Ok(None)
    }
}

/// Check if HEAD is exactly at a tag (no commits after it)
///
/// # Errors
///
/// Returns an error if the git command fails.
pub fn head_is_tagged() -> Result<bool> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match", "HEAD"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("Failed to run git describe")?;

    Ok(output.status.success())
}

/// Check if a specific tag exists
///
/// # Errors
///
/// Returns an error if the git command fails.
pub fn tag_exists(tag: &str) -> Result<bool> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", &format!("refs/tags/{tag}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to check tag existence")?;

    Ok(output.success())
}

/// Get the previous tag from git history (tag before HEAD)
///
/// # Errors
///
/// Returns an error if the git command fails.
pub fn get_previous_tag() -> Result<Option<String>> {
    get_tag_before("HEAD")
}

/// Get the tag before a given reference (tag or commit)
///
/// # Errors
///
/// Returns an error if the git command fails.
pub fn get_tag_before(reference: &str) -> Result<Option<String>> {
    let ref_parent = format!("{reference}^");
    let output = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0", &ref_parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("Failed to run git describe")?;

    if output.status.success() {
        let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if tag.is_empty() {
            Ok(None)
        } else {
            Ok(Some(tag))
        }
    } else {
        Ok(None)
    }
}

/// Get the previous tag for a specific component (e.g., "signer-v0.13.3")
///
/// # Errors
///
/// Returns an error if the git command fails.
pub fn get_previous_component_tag(component_prefix: &str) -> Result<Option<String>> {
    // Use git tag -l with pattern to find matching tags, sorted by version
    let pattern = format!("{component_prefix}-v*");
    let output = Command::new("git")
        .args(["tag", "-l", &pattern, "--sort=-v:refname"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("Failed to run git tag")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Get the first (most recent) tag
        if let Some(tag) = stdout.lines().next() {
            let tag = tag.trim();
            if !tag.is_empty() {
                return Ok(Some(tag.to_string()));
            }
        }
    }
    Ok(None)
}

/// Get the current date in YYYY-MM-DD format
#[must_use]
pub fn get_current_date() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

/// Get the date a tag was created in YYYY-MM-DD format
///
/// # Errors
///
/// Returns an error if the git command fails.
pub fn get_tag_date(tag: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["log", "-1", "--format=%ci", tag])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("Failed to run git log")?;

    if output.status.success() {
        let date_str = String::from_utf8_lossy(&output.stdout);
        // Parse YYYY-MM-DD from "YYYY-MM-DD HH:MM:SS +ZZZZ"
        if let Some(date_part) = date_str.split_whitespace().next()
            && NaiveDate::parse_from_str(date_part, "%Y-%m-%d").is_ok()
        {
            return Ok(date_part.to_string());
        }
    }

    // Fall back to current date if we can't get the tag date
    Ok(get_current_date())
}

/// Fetch tags from remote to ensure we have all tags for changelog generation
///
/// # Errors
///
/// Returns an error if the git fetch command fails.
pub fn fetch_remote_tags() -> Result<()> {
    eprintln!("Fetching tags from remote...");
    let output = Command::new("git")
        .args(["fetch", "--tags"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to run git fetch --tags")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git fetch --tags failed: {stderr}");
    }

    Ok(())
}

/// Get full commit messages (subject + body) for a range, for Claude context
///
/// # Errors
///
/// Returns an error if the git log command fails.
pub fn get_full_commit_messages(tag: Option<&str>, end_ref: &str) -> Result<String> {
    let range = match tag {
        Some(t) => format!("{t}..{end_ref}"),
        None => end_ref.to_string(),
    };

    let output = Command::new("git")
        .args(["log", &range, "--format=### %h %s%n%b"])
        .stdout(Stdio::piped())
        .output()
        .context("Failed to run git log")?;

    if !output.status.success() {
        return Ok(String::new());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get commits since a tag (or all commits if no tag), optionally filtered by scope
///
/// - `tag`: The starting tag (exclusive). If None, gets all commits up to `end_ref`.
/// - `end_ref`: The ending reference (inclusive). Usually a tag or "HEAD".
/// - `scope_filter`: Optional scope to filter commits by.
///
/// # Errors
///
/// Returns an error if the git log command fails.
pub fn get_commits_since(
    tag: Option<&str>,
    end_ref: &str,
    scope_filter: Option<&str>,
) -> Result<Vec<String>> {
    let range = match tag {
        Some(t) => format!("{t}..{end_ref}"),
        None => end_ref.to_string(),
    };

    let output = Command::new("git")
        .args(["log", &range, "--format=%h|%s"])
        .stdout(Stdio::piped())
        .output()
        .context("Failed to run git log")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let commits: Vec<String> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect();

    // If no scope filter, return all commits
    let Some(scope) = scope_filter else {
        return Ok(commits);
    };

    // Filter commits by scope
    Ok(commits
        .into_iter()
        .filter(|line| {
            // Parse commit to check scope
            if let Some(commit) = parse_commit(line) {
                commit.scope.as_ref().is_some_and(|s| s.as_str() == scope)
            } else {
                false
            }
        })
        .collect())
}

/// Determine the version bump type from commits
///
/// Rules based on Conventional Commits:
/// - Any breaking change (!) → Major
/// - Any `feat` commit → Minor
/// - Otherwise → Patch
#[must_use]
pub fn determine_bump_type(commits: &[ParsedCommit]) -> BumpType {
    let has_breaking = commits.iter().any(|c| c.breaking);
    if has_breaking {
        return BumpType::Major;
    }

    let has_feat = commits.iter().any(|c| c.commit_type == CommitType::Feat);
    if has_feat {
        return BumpType::Minor;
    }

    BumpType::Patch
}

/// Check if a commit is a release meta-commit that shouldn't trigger a version bump
fn is_release_commit(commit: &ParsedCommit) -> bool {
    commit.commit_type == CommitType::Chore
        && commit
            .scope
            .as_ref()
            .is_some_and(|s| s == "release" || s == "xtask")
}

/// Determine bump type from commits since the last tag for a component
///
/// # Errors
///
/// Returns an error if HEAD is already tagged, no commits are found, or git commands fail.
pub fn get_bump_type_for_component(
    component_prefix: Option<&str>,
    scope_filter: Option<&str>,
) -> Result<BumpType> {
    fetch_remote_tags()?;

    // Check if HEAD is already tagged - if so, nothing to bump
    if head_is_tagged()? {
        bail!("HEAD is already tagged. Nothing to bump.");
    }

    // Get the most recent tag reachable from HEAD
    let tag = if let Some(prefix) = component_prefix {
        get_previous_component_tag(prefix)?.or(get_current_tag()?)
    } else {
        get_current_tag()?
    };

    let commit_lines = get_commits_since(tag.as_deref(), "HEAD", scope_filter)?;

    if commit_lines.is_empty() {
        bail!("No commits found since last release. Nothing to bump.");
    }

    // Filter out release meta-commits (chore(release), chore(xtask))
    let commits: Vec<ParsedCommit> = commit_lines
        .iter()
        .filter_map(|line| parse_commit(line))
        .filter(|c| !is_release_commit(c))
        .collect();

    if commits.is_empty() {
        bail!("No substantive commits found since last release. Nothing to bump.");
    }

    Ok(determine_bump_type(&commits))
}

/// Parse a semantic version string into (major, minor, patch)
///
/// Strips any pre-release suffix before parsing (e.g., "1.2.3-beta.1" → (1, 2, 3)).
///
/// # Errors
///
/// Returns an error if the version string is not in `MAJOR.MINOR.PATCH` format.
pub fn parse_version(version: &str) -> Result<(u32, u32, u32)> {
    let base = base_version(version);
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid version format: {version}. Expected MAJOR.MINOR.PATCH");
    }

    let major = parts[0]
        .parse()
        .with_context(|| format!("Invalid major version: {}", parts[0]))?;
    let minor = parts[1]
        .parse()
        .with_context(|| format!("Invalid minor version: {}", parts[1]))?;
    let patch = parts[2]
        .parse()
        .with_context(|| format!("Invalid patch version: {}", parts[2]))?;

    Ok((major, minor, patch))
}

/// Bump a version according to the bump type
///
/// # Errors
///
/// Returns an error if the version string cannot be parsed.
pub fn bump_version(version: &str, bump_type: BumpType) -> Result<String> {
    let (major, minor, patch) = parse_version(version)?;

    let (new_major, new_minor, new_patch) = match bump_type {
        BumpType::Major => (major + 1, 0, 0),
        BumpType::Minor => (major, minor + 1, 0),
        BumpType::Patch => (major, minor, patch + 1),
    };

    Ok(format!("{new_major}.{new_minor}.{new_patch}"))
}

/// Extract the base version (without pre-release suffix) from a version string
///
/// "1.2.3" → "1.2.3", "1.2.3-beta.1" → "1.2.3"
#[must_use]
pub fn base_version(version: &str) -> &str {
    version.split_once('-').map_or(version, |(base, _)| base)
}

/// Extract the pre-release suffix from a version string
///
/// "1.2.3" → None, "1.2.3-beta.1" → Some("beta.1")
#[must_use]
pub fn pre_release(version: &str) -> Option<&str> {
    version.split_once('-').map(|(_, suffix)| suffix)
}

/// Find the next beta number for a given base version by scanning git tags
///
/// Searches for tags matching `v{base}-beta.*` (or `{prefix}-v{base}-beta.*`)
/// and returns max+1 (or 1 if none exist).
///
/// # Errors
///
/// Returns an error if the git tag command fails.
pub fn next_beta_number(tag_prefix: Option<&str>, base_ver: &str) -> Result<u32> {
    let pattern = if let Some(prefix) = tag_prefix {
        format!("{prefix}-v{base_ver}-beta.*")
    } else {
        format!("v{base_ver}-beta.*")
    };

    let output = Command::new("git")
        .args(["tag", "-l", &pattern])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("Failed to run git tag")?;

    if !output.status.success() {
        bail!("git tag -l failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let max_beta = stdout
        .lines()
        .filter_map(|tag| tag.rsplit_once("-beta."))
        .filter_map(|(_, n)| n.parse::<u32>().ok())
        .max();

    Ok(max_beta.map_or(1, |n| n + 1))
}

/// Generate changelog markdown from parsed commits
///
/// - `version`: The version string (e.g., "1.2.3")
/// - `date`: The release date in YYYY-MM-DD format
/// - `previous_tag`: The previous version tag for the compare link (e.g., "v1.2.2")
/// - `commits`: The parsed commits to include
#[must_use]
pub fn generate(
    version: &str,
    date: &str,
    previous_tag: Option<&str>,
    commits: &[ParsedCommit],
) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "## [{version}] - {date}");

    // Separate breaking changes
    let breaking: Vec<_> = commits.iter().filter(|c| c.breaking).collect();
    let non_breaking: Vec<_> = commits.iter().filter(|c| !c.breaking).collect();

    // Breaking changes first
    if !breaking.is_empty() {
        output.push_str("\n### Breaking Changes\n");
        for commit in breaking {
            output.push_str(&format_commit(commit));
        }
    }

    // Group non-breaking by type
    let mut by_type: HashMap<CommitType, Vec<&ParsedCommit>> = HashMap::new();
    for commit in non_breaking {
        by_type.entry(commit.commit_type).or_default().push(commit);
    }

    // Sort types by display order
    let mut types: Vec<_> = by_type.keys().copied().collect();
    types.sort_by_key(|&t| t.display_order());

    for commit_type in types {
        let commits = &by_type[&commit_type];
        let _ = write!(output, "\n### {}\n", commit_type.section_title());
        for commit in commits {
            output.push_str(&format_commit(commit));
        }
    }

    // Compare link: previous_tag...v{version}
    if let Some(prev) = previous_tag {
        let _ = write!(
            output,
            "\n**Full Changelog**: https://github.com/RichAyotte/russignol/compare/{prev}...v{version}\n"
        );
    }

    output
}

/// Generate a user-facing changelog using Claude CLI
///
/// Passes the full commit messages through `claude -p` which generates a formatted
/// changelog emphasizing user benefits. Falls back gracefully if `claude` is not
/// installed or the generation fails.
fn generate_with_claude(
    version: &str,
    date: &str,
    previous_tag: Option<&str>,
    full_messages: &str,
) -> Result<String> {
    let compare_link = previous_tag
        .map(|prev| {
            format!(
                "\n**Full Changelog**: \
                 https://github.com/RichAyotte/russignol/compare/{prev}...v{version}\n"
            )
        })
        .unwrap_or_default();

    let prompt = format!(
        "Russignol is a Tezos blockchain signer that runs on a Raspberry Pi Zero 2W. \
         It signs consensus operations (blocks and attestations) using BLS12-381 keys. \
         The device runs 24/7 in a home environment, so power consumption, temperature, \
         reliability, and security are key concerns for users. The host utility runs on \
         the user's desktop to manage the device (flashing SD cards, backing up keys, \
         upgrading firmware).\n\n\
         Generate a changelog from these git commits. Group entries under these markdown \
         sections in order: Added, Fixed, Changed, Chores. Only include sections that \
         have entries. Each entry should be a bullet point: `- **scope:** description (hash)` \
         or `- description (hash)` if no scope. Descriptions should emphasize user-facing \
         benefits (reliability, power efficiency, temperature, performance, security, \
         usability) instead of implementation details. Be concise — each description \
         should be a single short sentence.\n\n\
         Skip commits with type docs, refactor, test, style, ci, or scope website. \
         Skip release meta-commits (chore(release), chore(xtask)).\n\n\
         When a fix commit is a follow-up correction to a new feature introduced in the \
         same release, fold its details into the parent feature's description instead of \
         listing it as a separate fix. Only list a commit under Fixed if it fixes a bug \
         that existed in a previous release.\n\n\
         Start with this exact header line:\n\
         ## [{version}] - {date}\n\n\
         End with this exact line:\n\
         {compare_link}\n\
         Format as GitHub Flavored Markdown. \
         Output only the changelog with no surrounding commentary.\n\n\
         Here are the full commit messages:\n\n{full_messages}"
    );

    let output = Command::new("claude")
        .args(["--print", "--model", "sonnet", &prompt])
        .env_remove("CLAUDECODE")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to run claude CLI")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("claude exited with {}: {stderr}", output.status);
    }

    let rewritten = String::from_utf8(output.stdout)
        .context("claude output was not valid UTF-8")?
        .trim()
        .to_string();

    if rewritten.is_empty() {
        bail!("claude returned empty output");
    }

    Ok(rewritten)
}

fn format_commit(commit: &ParsedCommit) -> String {
    if let Some(scope) = &commit.scope {
        format!(
            "- **{}:** {} ({})\n",
            scope, commit.description, commit.hash
        )
    } else {
        format!("- {} ({})\n", commit.description, commit.hash)
    }
}

/// Create changelog file for a component release
///
/// - `component_prefix`: The tag prefix (e.g., "signer") for finding previous tag
/// - `scope_filter`: The commit scope to filter by (e.g., "signer")
///
/// # Errors
///
/// Returns an error if git commands fail or the changelog file cannot be written.
pub fn create_changelog_file_for_component(
    version: &str,
    component_prefix: Option<&str>,
    scope_filter: Option<&str>,
) -> Result<String> {
    fetch_remote_tags()?;

    // Construct the current version's tag name
    let current_tag = if let Some(prefix) = component_prefix {
        format!("{prefix}-v{version}")
    } else {
        format!("v{version}")
    };

    // Get the previous tag relative to the current version's tag
    // This ensures we get the correct range even when called after the release commit
    // (e.g., during publish --github retry after a failed release)
    // Determine the commit range: previous_tag..end_ref
    // When current_tag exists, use it as end_ref to avoid including commits after this release
    let (tag, end_ref) = if tag_exists(&current_tag)? {
        // Current tag exists - find the tag before it and use current tag as end
        (get_tag_before(&current_tag)?, current_tag.clone())
    } else if let Some(prefix) = component_prefix {
        // Current tag doesn't exist yet - use component tag or fall back to release tag
        (
            get_previous_component_tag(prefix)?.or(get_previous_tag()?),
            "HEAD".to_string(),
        )
    } else {
        (get_previous_tag()?, "HEAD".to_string())
    };

    let commit_lines = get_commits_since(tag.as_deref(), &end_ref, scope_filter)?;

    // Include all commit types except excluded ones (docs, refactor, test, style, ci, other),
    // release meta-commits, and non-product scopes like website
    let commits: Vec<ParsedCommit> = commit_lines
        .iter()
        .filter_map(|line| parse_commit(line))
        .filter(|c| !c.commit_type.is_excluded())
        .filter(|c| !c.is_excluded_scope())
        .filter(|c| !is_release_commit(c))
        .collect();

    // Get date: if tag exists, use tag date; otherwise use current date
    let date = if tag_exists(&current_tag)? {
        get_tag_date(&current_tag)?
    } else {
        get_current_date()
    };

    let full_messages = get_full_commit_messages(tag.as_deref(), &end_ref).unwrap_or_default();
    let changelog = generate_with_claude(version, &date, tag.as_deref(), &full_messages)
        .unwrap_or_else(|e| {
            eprintln!("  Note: Claude generation skipped ({e}), using raw commit messages");
            generate(version, &date, tag.as_deref(), &commits)
        });

    // Include component prefix in filename if present
    let path = if let Some(prefix) = component_prefix {
        format!("target/CHANGELOG-{prefix}-{version}.md")
    } else {
        format!("target/CHANGELOG-{version}.md")
    };

    let file = File::create(&path).with_context(|| format!("Failed to create {path}"))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(changelog.as_bytes())
        .context("Failed to write changelog")?;
    writer.flush()?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_version_stable() {
        assert_eq!(base_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn test_base_version_beta() {
        assert_eq!(base_version("1.2.3-beta.1"), "1.2.3");
    }

    #[test]
    fn test_pre_release_none() {
        assert_eq!(pre_release("1.2.3"), None);
    }

    #[test]
    fn test_pre_release_beta() {
        assert_eq!(pre_release("1.2.3-beta.1"), Some("beta.1"));
    }

    #[test]
    fn test_parse_commit_with_scope() {
        let commit = parse_commit("abc1234|feat(host-utility): add --endpoint flag").unwrap();
        assert_eq!(commit.commit_type, CommitType::Feat);
        assert_eq!(commit.scope, Some("host-utility".to_string()));
        assert_eq!(commit.description, "add --endpoint flag");
        assert_eq!(commit.hash, "abc1234");
        assert!(!commit.breaking);
    }

    #[test]
    fn test_parse_commit_without_scope() {
        let commit = parse_commit("def5678|docs: update README").unwrap();
        assert_eq!(commit.commit_type, CommitType::Docs);
        assert_eq!(commit.scope, None);
        assert_eq!(commit.description, "update README");
        assert_eq!(commit.hash, "def5678");
        assert!(!commit.breaking);
    }

    #[test]
    fn test_parse_commit_breaking_change() {
        let commit = parse_commit("ghi9012|feat!: remove deprecated API").unwrap();
        assert_eq!(commit.commit_type, CommitType::Feat);
        assert_eq!(commit.scope, None);
        assert_eq!(commit.description, "remove deprecated API");
        assert!(commit.breaking);
    }

    #[test]
    fn test_parse_commit_breaking_change_with_scope() {
        let commit = parse_commit("jkl3456|fix(api)!: change return type").unwrap();
        assert_eq!(commit.commit_type, CommitType::Fix);
        assert_eq!(commit.scope, Some("api".to_string()));
        assert_eq!(commit.description, "change return type");
        assert!(commit.breaking);
    }

    #[test]
    fn test_parse_commit_unknown_type() {
        let commit = parse_commit("mno7890|random: some message").unwrap();
        assert_eq!(commit.commit_type, CommitType::Other);
        assert_eq!(commit.scope, None);
        assert_eq!(commit.description, "some message");
    }

    #[test]
    fn test_parse_commit_invalid_format() {
        let commit = parse_commit("pqr1234|this is not a conventional commit").unwrap();
        assert_eq!(commit.commit_type, CommitType::Other);
        assert_eq!(commit.scope, None);
        assert_eq!(commit.description, "this is not a conventional commit");
    }

    #[test]
    fn test_generate_groups_by_type() {
        let commits = vec![
            ParsedCommit {
                commit_type: CommitType::Docs,
                scope: None,
                description: "update docs".to_string(),
                hash: "aaa1111".to_string(),
                breaking: false,
            },
            ParsedCommit {
                commit_type: CommitType::Feat,
                scope: Some("cli".to_string()),
                description: "add new flag".to_string(),
                hash: "bbb2222".to_string(),
                breaking: false,
            },
            ParsedCommit {
                commit_type: CommitType::Fix,
                scope: None,
                description: "fix bug".to_string(),
                hash: "ccc3333".to_string(),
                breaking: false,
            },
        ];

        let changelog = generate("1.0.0", "2024-01-15", Some("v0.9.0"), &commits);

        // Added should come before Fixed, which should come before Documentation
        let feat_pos = changelog.find("### Added").unwrap();
        let fix_pos = changelog.find("### Fixed").unwrap();
        let docs_pos = changelog.find("### Documentation").unwrap();

        assert!(feat_pos < fix_pos, "Added should come before Fixed");
        assert!(fix_pos < docs_pos, "Fixed should come before Documentation");
    }

    #[test]
    fn test_generate_breaking_changes_first() {
        let commits = vec![
            ParsedCommit {
                commit_type: CommitType::Feat,
                scope: None,
                description: "normal feature".to_string(),
                hash: "aaa1111".to_string(),
                breaking: false,
            },
            ParsedCommit {
                commit_type: CommitType::Feat,
                scope: Some("api".to_string()),
                description: "breaking feature".to_string(),
                hash: "bbb2222".to_string(),
                breaking: true,
            },
        ];

        let changelog = generate("1.0.0", "2024-01-15", Some("v0.9.0"), &commits);

        let breaking_pos = changelog.find("### Breaking Changes").unwrap();
        let feat_pos = changelog.find("### Added").unwrap();

        assert!(
            breaking_pos < feat_pos,
            "Breaking Changes should come before Added"
        );
    }

    #[test]
    fn test_generate_header_and_compare_link() {
        let commits = vec![ParsedCommit {
            commit_type: CommitType::Feat,
            scope: None,
            description: "new feature".to_string(),
            hash: "abc1234".to_string(),
            breaking: false,
        }];

        let changelog = generate("1.2.0", "2024-03-15", Some("v1.1.0"), &commits);

        // Check version header format: ## [version] - YYYY-MM-DD
        assert!(
            changelog.contains("## [1.2.0] - 2024-03-15"),
            "Should have Keep a Changelog header format"
        );

        // Check compare link format: compare/previous_tag...v{version}
        assert!(
            changelog.contains("compare/v1.1.0...v1.2.0"),
            "Should have correct compare link format"
        );
    }

    #[test]
    fn test_generate_no_previous_tag() {
        let commits = vec![ParsedCommit {
            commit_type: CommitType::Feat,
            scope: None,
            description: "initial feature".to_string(),
            hash: "abc1234".to_string(),
            breaking: false,
        }];

        let changelog = generate("0.1.0", "2024-01-01", None, &commits);

        // Header should still be present
        assert!(changelog.contains("## [0.1.0] - 2024-01-01"));

        // Compare link should be omitted when no previous tag
        assert!(
            !changelog.contains("Full Changelog"),
            "Should not have compare link without previous tag"
        );
    }

    #[test]
    fn test_format_commit_with_scope() {
        let commit = ParsedCommit {
            commit_type: CommitType::Feat,
            scope: Some("cli".to_string()),
            description: "add flag".to_string(),
            hash: "abc1234".to_string(),
            breaking: false,
        };
        let formatted = format_commit(&commit);
        assert_eq!(formatted, "- **cli:** add flag (abc1234)\n");
    }

    #[test]
    fn test_format_commit_without_scope() {
        let commit = ParsedCommit {
            commit_type: CommitType::Fix,
            scope: None,
            description: "fix bug".to_string(),
            hash: "def5678".to_string(),
            breaking: false,
        };
        let formatted = format_commit(&commit);
        assert_eq!(formatted, "- fix bug (def5678)\n");
    }

    #[test]
    fn test_parse_version_valid() {
        let (major, minor, patch) = parse_version("1.2.3").unwrap();
        assert_eq!((major, minor, patch), (1, 2, 3));
    }

    #[test]
    fn test_parse_version_zero() {
        let (major, minor, patch) = parse_version("0.0.0").unwrap();
        assert_eq!((major, minor, patch), (0, 0, 0));
    }

    #[test]
    fn test_parse_version_invalid() {
        assert!(parse_version("1.2").is_err());
        assert!(parse_version("1.2.3.4").is_err());
        assert!(parse_version("a.b.c").is_err());
    }

    #[test]
    fn test_bump_version_patch() {
        assert_eq!(bump_version("1.2.3", BumpType::Patch).unwrap(), "1.2.4");
        assert_eq!(bump_version("0.0.0", BumpType::Patch).unwrap(), "0.0.1");
    }

    #[test]
    fn test_bump_version_minor() {
        assert_eq!(bump_version("1.2.3", BumpType::Minor).unwrap(), "1.3.0");
        assert_eq!(bump_version("0.0.5", BumpType::Minor).unwrap(), "0.1.0");
    }

    #[test]
    fn test_bump_version_major() {
        assert_eq!(bump_version("1.2.3", BumpType::Major).unwrap(), "2.0.0");
        assert_eq!(bump_version("0.5.3", BumpType::Major).unwrap(), "1.0.0");
    }

    #[test]
    fn test_determine_bump_type_breaking() {
        let commits = vec![
            ParsedCommit {
                commit_type: CommitType::Fix,
                scope: None,
                description: "normal fix".to_string(),
                hash: "aaa".to_string(),
                breaking: false,
            },
            ParsedCommit {
                commit_type: CommitType::Feat,
                scope: None,
                description: "breaking feature".to_string(),
                hash: "bbb".to_string(),
                breaking: true,
            },
        ];
        assert_eq!(determine_bump_type(&commits), BumpType::Major);
    }

    #[test]
    fn test_determine_bump_type_feat() {
        let commits = vec![
            ParsedCommit {
                commit_type: CommitType::Fix,
                scope: None,
                description: "a fix".to_string(),
                hash: "aaa".to_string(),
                breaking: false,
            },
            ParsedCommit {
                commit_type: CommitType::Feat,
                scope: None,
                description: "new feature".to_string(),
                hash: "bbb".to_string(),
                breaking: false,
            },
        ];
        assert_eq!(determine_bump_type(&commits), BumpType::Minor);
    }

    #[test]
    fn test_determine_bump_type_fix_only() {
        let commits = vec![
            ParsedCommit {
                commit_type: CommitType::Fix,
                scope: None,
                description: "bug fix".to_string(),
                hash: "aaa".to_string(),
                breaking: false,
            },
            ParsedCommit {
                commit_type: CommitType::Docs,
                scope: None,
                description: "update docs".to_string(),
                hash: "bbb".to_string(),
                breaking: false,
            },
        ];
        assert_eq!(determine_bump_type(&commits), BumpType::Patch);
    }
}
