use crate::hardware;
use crate::utils;
use anyhow::Result;

pub fn run(skip_hardware_check: bool, _dry_run: bool, _verbose: bool) -> Result<()> {
    // USB Device Detection (silent - progress shown in main)
    if !skip_hardware_check {
        hardware::detect_hardware_device()?;

        // Check USB power situation and warn if needed
        if let Ok(Some(power_info)) = hardware::get_usb_power_info()
            && let Some(warning_msg) = hardware::check_power_warning(&power_info)
        {
            println!();
            utils::warning(&warning_msg);
            println!();
        }
    }

    Ok(())
}
