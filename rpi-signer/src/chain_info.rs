//! Chain info reader
//!
//! Reads chain configuration from /`keys/chain_info.json` which is
//! created during first-boot setup and stored on the read-only keys partition.

use crate::constants::CHAIN_INFO_FILE;
use serde::Deserialize;
use std::fs;
use std::io;

/// Chain information
#[derive(Debug, Clone, Deserialize)]
pub struct ChainInfo {
    /// Chain ID in base58check format (e.g., "`NetXdQprcVkpaWU`")
    pub id: String,
    /// Human-friendly chain name (e.g., "Mainnet", "Ghostnet")
    pub name: String,
    /// Number of blocks per cycle (chain-specific, used for level gap threshold)
    #[serde(default)]
    pub blocks_per_cycle: Option<u32>,
}

/// Read chain info from /`keys/chain_info.json`
///
/// # Errors
/// Returns error if file doesn't exist or contains invalid JSON.
pub fn read_chain_info() -> io::Result<ChainInfo> {
    let content = fs::read_to_string(CHAIN_INFO_FILE)?;
    serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
