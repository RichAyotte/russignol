// Configuration management for Russignol host utility
//
// This module provides persistent configuration storage using XDG standards,
// with intelligent auto-detection of Octez directories and user-friendly prompts.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CONFIG_VERSION: u32 = 2;
const DEFAULT_RPC_ENDPOINT: &str = "http://localhost:8732";
const DEFAULT_DAL_ENDPOINT: &str = "http://localhost:10732";

/// Minimal structure to extract RPC config from octez-node config.json
#[derive(Debug, Deserialize)]
struct OctezNodeConfig {
    #[serde(default)]
    rpc: Option<OctezNodeRpcConfig>,
}

#[derive(Debug, Deserialize)]
struct OctezNodeRpcConfig {
    #[serde(rename = "listen-addrs")]
    listen_addrs: Vec<String>,
}

/// Russignol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RussignolConfig {
    /// Configuration schema version for future migrations
    pub version: u32,

    /// Path to octez-client directory (e.g., ~/.tezos-client)
    pub octez_client_dir: PathBuf,

    /// Optional path to octez-node directory
    pub octez_node_dir: Option<PathBuf>,

    /// RPC endpoint URL for octez-client
    pub rpc_endpoint: String,

    /// DAL node RPC endpoint URL (optional, for bakers participating in DAL)
    #[serde(default)]
    pub dal_node_endpoint: Option<String>,
}

impl RussignolConfig {
    /// Load configuration from file, or create with auto-detection if missing
    ///
    /// This is the main entry point for configuration loading. It will:
    /// 1. Try to load existing config file
    /// 2. If missing, auto-detect directories
    /// 3. If auto-detection fails or finds multiple, prompt user
    /// 4. Save the configuration for future use
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        // Try to load existing config
        if config_path.exists() {
            match Self::load_from_file(&config_path) {
                Ok(config) => {
                    // Validate the loaded config
                    if let Err(e) = config.validate() {
                        eprintln!(
                            "{} Configuration validation failed: {}",
                            "Warning:".yellow().bold(),
                            e
                        );
                        eprintln!("  Run 'russignol config reset' to reconfigure.");
                        eprintln!();

                        // Return the invalid config anyway - let the caller decide what to do
                        // (they might be running config commands to fix it)
                        return Ok(config);
                    }
                    return Ok(config);
                }
                Err(e) => {
                    eprintln!(
                        "{} Failed to load config file: {}",
                        "Warning:".yellow().bold(),
                        e
                    );
                    eprintln!("  Will attempt auto-detection...");
                    eprintln!();
                }
            }
        }

        // No config file or failed to load - run auto-detection
        println!("{}", "Auto-detecting Octez configuration...".bold());

        let config = Self::auto_detect()?;

        // Save the detected/configured settings
        config.save()?;

        println!(
            "{} Configuration saved to {}",
            "✓".green(),
            config_path.display()
        );
        println!();

        Ok(config)
    }

    /// Create a minimal configuration with just an RPC endpoint
    ///
    /// Used when no config file exists but user provides --endpoint flag.
    /// Uses default octez-client directory (~/.tezos-client).
    pub fn minimal_with_endpoint(endpoint: &str) -> Self {
        Self {
            version: CONFIG_VERSION,
            octez_client_dir: dirs::home_dir().map_or_else(
                || PathBuf::from(".tezos-client"),
                |h| h.join(".tezos-client"),
            ),
            octez_node_dir: None,
            rpc_endpoint: endpoint.to_string(),
            dal_node_endpoint: None,
        }
    }

    /// Load configuration from a specific file path
    fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Save configuration to the XDG config directory
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        // Ensure config directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        // Serialize to JSON with pretty formatting
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize configuration")?;

        std::fs::write(&config_path, content)
            .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;

        Ok(())
    }

    /// Get the XDG-compliant configuration file path
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Failed to determine config directory (XDG_CONFIG_HOME or ~/.config)")?;

        Ok(config_dir.join("russignol").join("config.json"))
    }

    /// Validate configuration
    ///
    /// Checks that directories exist and have the expected structure
    pub fn validate(&self) -> Result<()> {
        // Validate client directory
        Self::validate_client_dir(&self.octez_client_dir)?;

        // Validate node directory if specified
        if let Some(ref node_dir) = self.octez_node_dir {
            Self::validate_node_dir(node_dir)?;
        }

        // Validate RPC endpoint format
        if !self.rpc_endpoint.starts_with("http://") && !self.rpc_endpoint.starts_with("https://") {
            anyhow::bail!(
                "Invalid RPC endpoint '{}': must start with http:// or https://",
                self.rpc_endpoint
            );
        }

        Ok(())
    }

    /// Validate that a directory is a valid octez-client directory
    ///
    /// Checks for presence of required files: `public_keys`, `secret_keys`, `public_key_hashs`
    fn validate_client_dir(dir: &Path) -> Result<()> {
        if !dir.exists() {
            anyhow::bail!("Octez client directory does not exist: {}", dir.display());
        }

        if !dir.is_dir() {
            anyhow::bail!("Octez client path is not a directory: {}", dir.display());
        }

        // Check for required files
        let required_files = ["public_keys", "secret_keys", "public_key_hashs"];
        for file_name in &required_files {
            let file_path = dir.join(file_name);
            if !file_path.exists() {
                anyhow::bail!(
                    "Octez client directory missing required file '{}': {}",
                    file_name,
                    dir.display()
                );
            }
        }

        Ok(())
    }

    /// Validate that a directory is a valid octez-node directory
    ///
    /// Checks for presence of config.json or identity.json
    fn validate_node_dir(dir: &Path) -> Result<()> {
        if !dir.exists() {
            anyhow::bail!("Octez node directory does not exist: {}", dir.display());
        }

        if !dir.is_dir() {
            anyhow::bail!("Octez node path is not a directory: {}", dir.display());
        }

        // Check for at least one expected file
        let config_file = dir.join("config.json");
        let identity_file = dir.join("identity.json");

        if !config_file.exists() && !identity_file.exists() {
            anyhow::bail!(
                "Octez node directory missing expected files (config.json or identity.json): {}",
                dir.display()
            );
        }

        Ok(())
    }

    /// Auto-detect Octez directories
    ///
    /// Searches for valid octez-client directories and prompts user if multiple found
    fn auto_detect() -> Result<Self> {
        // Search for valid client directories
        let client_dirs = Self::search_for_client_dirs()?;

        let client_dir = match client_dirs.len() {
            0 => {
                // No directories found - prompt user
                println!("  {} No Octez client directories found", "×".red());
                println!();
                Self::prompt_for_client_dir()?
            }
            1 => {
                // Exactly one directory found - use it
                let dir = client_dirs[0].clone();
                println!(
                    "  {} Found client directory: {}",
                    "✓".green(),
                    dir.display()
                );
                dir
            }
            _ => {
                // Multiple directories found - let user choose
                println!(
                    "  {} Found {} Octez client directories",
                    "!".yellow(),
                    client_dirs.len()
                );
                println!();
                Self::prompt_directory_selection(&client_dirs)?
            }
        };

        // For now, don't auto-detect node directory (optional field)
        let node_dir = None;

        // Try to detect RPC endpoint from node config, or prompt if not found
        let rpc_endpoint = if let Some(detected) = Self::detect_rpc_endpoint_from_node() {
            println!("  {} Detected RPC endpoint: {}", "✓".green(), detected);
            detected
        } else {
            Self::prompt_for_rpc_endpoint()?
        };

        // Try to detect DAL node endpoint
        let dal_node_endpoint = Self::detect_dal_node_endpoint();
        if let Some(ref endpoint) = dal_node_endpoint {
            println!("  {} Detected DAL node endpoint: {}", "✓".green(), endpoint);
        }

        Ok(Self {
            version: CONFIG_VERSION,
            octez_client_dir: client_dir,
            octez_node_dir: node_dir,
            rpc_endpoint,
            dal_node_endpoint,
        })
    }

    /// Search for valid octez-client directories in common locations
    fn search_for_client_dirs() -> Result<Vec<PathBuf>> {
        let home = std::env::var("HOME").context("Failed to get HOME environment variable")?;
        let home_path = Path::new(&home);

        let mut valid_dirs = Vec::new();

        // Try default first
        let default_client = home_path.join(".tezos-client");
        if Self::validate_client_dir(&default_client).is_ok() {
            valid_dirs.push(default_client);
        }

        // Search for pattern matches
        let patterns = vec![".octez-client*", ".tezos-client*"];

        for pattern in patterns {
            if let Ok(entries) = std::fs::read_dir(home_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        // Simple pattern matching
                        let pattern_prefix = pattern.trim_end_matches('*');
                        if name.starts_with(pattern_prefix) {
                            // Skip if already in list (from default check)
                            if !valid_dirs.contains(&path)
                                && Self::validate_client_dir(&path).is_ok()
                            {
                                valid_dirs.push(path);
                            }
                        }
                    }
                }
            }
        }

        Ok(valid_dirs)
    }

    /// Prompt user to select from multiple directories
    fn prompt_directory_selection(dirs: &[PathBuf]) -> Result<PathBuf> {
        let options: Vec<String> = dirs.iter().map(|p| p.display().to_string()).collect();

        let selection = inquire::Select::new("Select Octez client directory:", options.clone())
            .prompt()
            .context("Failed to get user selection")?;

        // Find the selected path
        for (i, option) in options.iter().enumerate() {
            if option == &selection {
                return Ok(dirs[i].clone());
            }
        }

        anyhow::bail!("Failed to find selected directory")
    }

    /// Prompt user for octez-client directory path
    fn prompt_for_client_dir() -> Result<PathBuf> {
        loop {
            let input = inquire::Text::new("Enter Octez client directory path:")
                .with_help_message("Example: ~/.tezos-client or ~/.octez-client-shadownet")
                .prompt()
                .context("Failed to get user input")?;

            // Expand ~ and environment variables
            let expanded = shellexpand::full(&input).context("Failed to expand path")?;
            let path = PathBuf::from(expanded.as_ref());

            // Validate
            match Self::validate_client_dir(&path) {
                Ok(()) => return Ok(path),
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    eprintln!("  Please try again.");
                    eprintln!();
                }
            }
        }
    }

    /// Try to detect RPC endpoint from octez-node config.json
    ///
    /// Searches for octez-node directories and reads the RPC listen address
    /// from config.json if available.
    fn detect_rpc_endpoint_from_node() -> Option<String> {
        let home = std::env::var("HOME").ok()?;
        let home_path = Path::new(&home);

        // Search patterns for node directories
        let patterns = [
            ".tezos-node",
            ".octez-node",
            ".tezos-node-*",
            ".octez-node-*",
        ];

        let mut node_dirs = Vec::new();

        // Check exact matches first
        for pattern in &patterns[..2] {
            let path = home_path.join(pattern);
            if path.exists() && path.is_dir() {
                node_dirs.push(path);
            }
        }

        // Then check wildcard patterns
        if let Ok(entries) = std::fs::read_dir(home_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    for pattern in &patterns[2..] {
                        let pattern_prefix = pattern.trim_end_matches('*');
                        if name.starts_with(pattern_prefix) && !node_dirs.contains(&path) {
                            node_dirs.push(path.clone());
                            break; // Only add once, don't check remaining patterns
                        }
                    }
                }
            }
        }

        // Try to read RPC config from each node directory
        for node_dir in node_dirs {
            let config_path = node_dir.join("config.json");
            if let Ok(config_content) = std::fs::read_to_string(&config_path)
                && let Ok(node_config) = serde_json::from_str::<OctezNodeConfig>(&config_content)
                && let Some(rpc_config) = node_config.rpc
                && let Some(listen_addr) = rpc_config.listen_addrs.first()
            {
                // Convert listen address to RPC endpoint
                // Format is typically "127.0.0.1:8732" or "127.0.0.1:8733"
                let endpoint = if listen_addr.starts_with("http") {
                    listen_addr.clone()
                } else {
                    format!("http://{listen_addr}")
                };
                log::debug!(
                    "Detected RPC endpoint from {}: {}",
                    config_path.display(),
                    endpoint
                );
                return Some(endpoint);
            }
        }

        None
    }

    /// Try to detect DAL node RPC endpoint
    ///
    /// Searches for octez-dal-node directories and reads the RPC listen address
    /// from config.json if available. Falls back to checking if default port responds.
    fn detect_dal_node_endpoint() -> Option<String> {
        let home = std::env::var("HOME").ok()?;
        let home_path = Path::new(&home);

        // Search patterns for DAL node directories
        let patterns = [
            ".tezos-dal-node",
            ".octez-dal-node",
            ".tezos-dal-node-*",
            ".octez-dal-node-*",
        ];

        let mut dal_dirs = Vec::new();

        // Check exact matches first
        for pattern in &patterns[..2] {
            let path = home_path.join(pattern);
            if path.exists() && path.is_dir() {
                dal_dirs.push(path);
            }
        }

        // Then check wildcard patterns
        if let Ok(entries) = std::fs::read_dir(home_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    for pattern in &patterns[2..] {
                        let pattern_prefix = pattern.trim_end_matches('*');
                        if name.starts_with(pattern_prefix) && !dal_dirs.contains(&path) {
                            dal_dirs.push(path.clone());
                            break;
                        }
                    }
                }
            }
        }

        // If we found a DAL node directory, assume default endpoint
        // (DAL node config.json doesn't store RPC address the same way as octez-node)
        if !dal_dirs.is_empty() {
            log::debug!(
                "Found DAL node directory: {}, assuming default endpoint",
                dal_dirs[0].display()
            );
            return Some(DEFAULT_DAL_ENDPOINT.to_string());
        }

        None
    }

    /// Prompt user for RPC endpoint with auto-detected or default value
    fn prompt_for_rpc_endpoint() -> Result<String> {
        // Try to detect RPC endpoint from node config
        let detected = Self::detect_rpc_endpoint_from_node();
        let default_endpoint = detected.as_deref().unwrap_or(DEFAULT_RPC_ENDPOINT);

        if detected.is_some() {
            println!(
                "  {} Detected RPC endpoint: {}",
                "✓".green(),
                default_endpoint
            );
        }

        let endpoint = inquire::Text::new("Enter Octez node RPC endpoint:")
            .with_default(default_endpoint)
            .with_help_message("The URL where your octez-node RPC is accessible")
            .prompt()
            .context("Failed to get user input")?;

        // Basic validation
        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            anyhow::bail!("RPC endpoint must start with http:// or https://");
        }

        Ok(endpoint)
    }

    /// Reset configuration - delete config file and re-run auto-detection
    pub fn reset(skip_confirm: bool) -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() && !skip_confirm {
            let confirm = inquire::Confirm::new("Delete existing configuration and re-detect?")
                .with_default(false)
                .prompt()
                .context("Failed to get confirmation")?;

            if !confirm {
                anyhow::bail!("Configuration reset cancelled");
            }
        }

        // Delete config file if it exists
        if config_path.exists() {
            std::fs::remove_file(&config_path).with_context(|| {
                format!("Failed to delete config file: {}", config_path.display())
            })?;
            println!("{} Deleted configuration file", "✓".green());
        }

        // Re-detect
        println!();
        Self::load()
    }
}

/// CLI command handlers
pub fn run_config_command(command: crate::ConfigCommands) -> Result<()> {
    use crate::ConfigCommands;

    match command {
        ConfigCommands::Show => cmd_config_show(),
        ConfigCommands::Set { key, value } => cmd_config_set(&key, &value),
        ConfigCommands::Reset { yes } => cmd_config_reset(yes),
        ConfigCommands::Path => cmd_config_path(),
    }
}

/// Show current configuration
fn cmd_config_show() -> Result<()> {
    let config = RussignolConfig::load()?;
    let config_path = RussignolConfig::config_path()?;

    println!();
    println!("{}", "Current configuration:".bold());
    println!(
        "  Octez Client Directory: {}",
        config.octez_client_dir.display()
    );
    if let Some(ref node_dir) = config.octez_node_dir {
        println!("  Octez Node Directory:   {}", node_dir.display());
    } else {
        println!("  Octez Node Directory:   {}", "(not set)".dimmed());
    }
    println!("  RPC Endpoint:           {}", config.rpc_endpoint);
    if let Some(ref dal_endpoint) = config.dal_node_endpoint {
        println!("  DAL Node Endpoint:      {dal_endpoint}");
    } else {
        println!("  DAL Node Endpoint:      {}", "(not set)".dimmed());
    }
    println!();
    println!(
        "Config file: {}",
        config_path.display().to_string().dimmed()
    );
    println!();

    Ok(())
}

/// Set a configuration value
fn cmd_config_set(key: &str, value: &str) -> Result<()> {
    let mut config = RussignolConfig::load()?;

    match key {
        "octez-client-dir" => {
            let expanded = shellexpand::full(value).context("Failed to expand path")?;
            let path = PathBuf::from(expanded.as_ref());
            RussignolConfig::validate_client_dir(&path)?;
            config.octez_client_dir = path;
        }
        "octez-node-dir" => {
            let expanded = shellexpand::full(value).context("Failed to expand path")?;
            let path = PathBuf::from(expanded.as_ref());
            RussignolConfig::validate_node_dir(&path)?;
            config.octez_node_dir = Some(path);
        }
        "rpc-endpoint" => {
            if !value.starts_with("http://") && !value.starts_with("https://") {
                anyhow::bail!("RPC endpoint must start with http:// or https://");
            }
            config.rpc_endpoint = value.to_string();
        }
        "dal-node-endpoint" => {
            if !value.starts_with("http://") && !value.starts_with("https://") {
                anyhow::bail!("DAL node endpoint must start with http:// or https://");
            }
            config.dal_node_endpoint = Some(value.to_string());
        }
        _ => {
            anyhow::bail!(
                "Unknown configuration key: {key}\nValid keys: octez-client-dir, octez-node-dir, rpc-endpoint, dal-node-endpoint"
            );
        }
    }

    config.save()?;

    println!("{} Configuration updated", "✓".green());
    println!();

    Ok(())
}

/// Reset configuration
fn cmd_config_reset(yes: bool) -> Result<()> {
    RussignolConfig::reset(yes)?;
    println!();
    println!("{} Configuration reset complete", "✓".green());
    println!();
    Ok(())
}

/// Show configuration file path
fn cmd_config_path() -> Result<()> {
    let config_path = RussignolConfig::config_path()?;
    println!("{}", config_path.display());
    Ok(())
}
