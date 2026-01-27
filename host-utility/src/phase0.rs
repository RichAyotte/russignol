use crate::hardware;
use anyhow::Result;

pub fn run(skip_hardware_check: bool, _dry_run: bool, _verbose: bool) -> Result<()> {
    // USB Device Detection (silent - progress shown in main)
    if !skip_hardware_check {
        hardware::detect_hardware_device()?;
    }
    // Note: Skipping hardware check doesn't produce output anymore

    Ok(())
}
