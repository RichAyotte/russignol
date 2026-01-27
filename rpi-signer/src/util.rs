//! Shared utility functions

use std::process::Command;

/// Run a command and return Ok(()) on success, or error with stderr on failure
pub fn run_command(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {cmd}: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_command_success() {
        assert!(run_command("/bin/true", &[]).is_ok());
    }

    #[test]
    fn test_run_command_failure() {
        let result = run_command("/bin/false", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed"));
    }

    #[test]
    fn test_run_command_not_found() {
        let result = run_command("/nonexistent/command", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to run"));
    }
}
