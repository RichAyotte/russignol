//! Changelog generation from Conventional Commits

use anyhow::{Context, Result, bail};
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
            Self::Feat => "Features",
            Self::Fix => "Bug Fixes",
            Self::Docs => "Documentation",
            Self::Refactor => "Refactoring",
            Self::Test => "Tests",
            Self::Chore => "Chores",
            Self::Perf => "Performance",
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

    /// Whether this commit type should appear in user-facing changelogs
    fn is_user_facing(self) -> bool {
        matches!(self, Self::Feat | Self::Fix | Self::Perf)
    }
}

/// A parsed conventional commit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommit {
    pub commit_type: CommitType,
    pub scope: Option<String>,
    pub description: String,
    pub hash: String,
    pub breaking: bool,
}

/// Parse a commit line in format "hash|subject"
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
pub fn get_previous_tag() -> Result<Option<String>> {
    get_tag_before("HEAD")
}

/// Get the tag before a given reference (tag or commit)
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

/// Fetch tags from remote to ensure we have all tags for changelog generation
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

/// Get commits since a tag (or all commits if no tag), optionally filtered by scope
pub fn get_commits_since(tag: Option<&str>, scope_filter: Option<&str>) -> Result<Vec<String>> {
    let range = match tag {
        Some(t) => format!("{t}..HEAD"),
        None => "HEAD".to_string(),
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

    let commit_lines = get_commits_since(tag.as_deref(), scope_filter)?;

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
pub fn parse_version(version: &str) -> Result<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();
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
pub fn bump_version(version: &str, bump_type: BumpType) -> Result<String> {
    let (major, minor, patch) = parse_version(version)?;

    let (new_major, new_minor, new_patch) = match bump_type {
        BumpType::Major => (major + 1, 0, 0),
        BumpType::Minor => (major, minor + 1, 0),
        BumpType::Patch => (major, minor, patch + 1),
    };

    Ok(format!("{new_major}.{new_minor}.{new_patch}"))
}

/// Generate changelog markdown from parsed commits
pub fn generate_changelog(version: &str, commits: &[ParsedCommit]) -> String {
    let mut output = String::new();
    output.push_str("## What's Changed\n");

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

    let _ = write!(
        output,
        "\n**Full Changelog**: https://github.com/RichAyotte/russignol/compare/v{version}...HEAD\n"
    );

    output
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

/// Create changelog file for a release (full release, all commits)
pub fn create_changelog_file(version: &str) -> Result<String> {
    create_changelog_file_for_component(version, None, None)
}

/// Create changelog file for a component release
///
/// - `component_prefix`: The tag prefix (e.g., "signer") for finding previous tag
/// - `scope_filter`: The commit scope to filter by (e.g., "signer")
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
    let tag = if tag_exists(&current_tag)? {
        // Current tag exists - find the tag before it
        get_tag_before(&current_tag)?
    } else if let Some(prefix) = component_prefix {
        // Current tag doesn't exist yet - use component tag or fall back to release tag
        get_previous_component_tag(prefix)?.or(get_previous_tag()?)
    } else {
        get_previous_tag()?
    };

    let commit_lines = get_commits_since(tag.as_deref(), scope_filter)?;

    // Only include user-facing commits (feat, fix, perf) and breaking changes
    let commits: Vec<ParsedCommit> = commit_lines
        .iter()
        .filter_map(|line| parse_commit(line))
        .filter(|c| c.breaking || c.commit_type.is_user_facing())
        .collect();

    let changelog = generate_changelog(version, &commits);

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
    fn test_generate_changelog_groups_by_type() {
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

        let changelog = generate_changelog("1.0.0", &commits);

        // Features should come before Bug Fixes, which should come before Documentation
        let feat_pos = changelog.find("### Features").unwrap();
        let fix_pos = changelog.find("### Bug Fixes").unwrap();
        let docs_pos = changelog.find("### Documentation").unwrap();

        assert!(feat_pos < fix_pos, "Features should come before Bug Fixes");
        assert!(
            fix_pos < docs_pos,
            "Bug Fixes should come before Documentation"
        );
    }

    #[test]
    fn test_generate_changelog_breaking_changes_first() {
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

        let changelog = generate_changelog("1.0.0", &commits);

        let breaking_pos = changelog.find("### Breaking Changes").unwrap();
        let feat_pos = changelog.find("### Features").unwrap();

        assert!(
            breaking_pos < feat_pos,
            "Breaking Changes should come before Features"
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
