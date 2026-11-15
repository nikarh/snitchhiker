//! Helpers for scenarios.

use std::process::Command;

/// Runs a command, failing with its output if it fails; returns its standard output.
pub fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "{program} {}: {}\n{stdout}{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Fails with `message` and what was found unless `condition` holds.
pub fn check(condition: bool, message: &str, found: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("{message}; found:\n{found}"))
    }
}
