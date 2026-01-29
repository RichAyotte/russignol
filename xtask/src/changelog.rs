//! Changelog generation from Conventional Commits

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::{Command, Stdio};

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

/// Get the previous tag from git history
pub fn get_previous_tag() -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0", "HEAD^"])
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

/// Get commits since a tag (or all commits if no tag)
pub fn get_commits_since(tag: Option<&str>) -> Result<Vec<String>> {
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
    Ok(stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect())
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

/// Create changelog file for a release
pub fn create_changelog_file(version: &str) -> Result<String> {
    fetch_remote_tags()?;
    let tag = get_previous_tag()?;
    let commit_lines = get_commits_since(tag.as_deref())?;

    let commits: Vec<ParsedCommit> = commit_lines
        .iter()
        .filter_map(|line| parse_commit(line))
        .collect();

    let changelog = generate_changelog(version, &commits);

    let path = format!("target/CHANGELOG-{version}.md");
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
}
