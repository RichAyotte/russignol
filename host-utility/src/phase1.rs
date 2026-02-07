use crate::config::RussignolConfig;
use crate::system;
use anyhow::Result;

pub fn run(_dry_run: bool, _verbose: bool, config: &RussignolConfig) -> Result<()> {
    // Run all validation checks (silent - progress shown in main)
    let deps_result = system::verify_dependencies();
    let node_result = system::verify_octez_node(config);
    let client_result = system::verify_octez_client_directory(config);

    // Check all results - report first error encountered
    deps_result?;
    node_result?;
    client_result?;

    Ok(())
}
