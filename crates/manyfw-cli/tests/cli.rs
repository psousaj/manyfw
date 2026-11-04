use std::process::Command;

#[test]
fn check_reports_valid_policy_and_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args(["check", "--file", "../../examples/manyfw.toml"])
        .output()
        .expect("run manyfw check");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Valid schema v1: 2 zones, 3 rules"));
}

#[test]
fn check_reports_invalid_policy_and_exits_nonzero() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "check",
            "--file",
            "../../examples/invalid/unknown-zone.toml",
        ])
        .output()
        .expect("run manyfw check");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("InvalidSelector"));
    assert!(stderr.contains("unknown zone"));
}
