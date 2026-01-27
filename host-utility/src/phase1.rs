use crate::config::RussignolConfig;
use crate::system;
use anyhow::Result;

pub fn run(_dry_run: bool, _verbose: bool, config: &RussignolConfig) -> Result<()> {
    // Run all validation checks in parallel (silent - progress shown in main)
    let (deps_result, node_result, client_result) = std::thread::scope(|s| {
        let config_ref = config;

        let deps_handle = s.spawn(system::verify_dependencies);
        let node_handle = s.spawn(move || system::verify_octez_node(config_ref));
        let client_handle = s.spawn(move || system::verify_octez_client_directory(config_ref));

        (
            deps_handle.join().unwrap(),
            node_handle.join().unwrap(),
            client_handle.join().unwrap(),
        )
    });

    // Check all results - report first error encountered
    deps_result?;
    node_result?;
    client_result?;

    Ok(())
}
