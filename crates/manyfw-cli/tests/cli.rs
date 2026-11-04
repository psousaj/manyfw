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

#[test]
fn check_reports_warnings_and_still_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "check",
            "--file",
            "../../examples/warnings/broad-ports.toml",
        ])
        .output()
        .expect("run manyfw check");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Warning BroadPortScope"));
    assert!(stdout.contains("[rules: admin-vpn]"));
}

#[test]
fn plan_prints_normalized_rules_in_priority_order() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args(["plan", "--file", "../../examples/manyfw.toml"])
        .output()
        .expect("run manyfw plan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lan = stdout.find("rule postgres-lan").expect("lan rule");
    let tailscale = stdout
        .find("rule postgres-tailscale")
        .expect("tailscale rule");
    assert!(lan < tailscale);
    assert!(stdout.contains("PREVIEW ONLY"));
    assert!(stdout.contains("priority=100"));
    assert!(stdout.contains("ports=Specific"));
}

#[test]
fn check_reports_legacy_migration_requirements() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "check",
            "--file",
            "../../examples/invalid/migration-required.toml",
        ])
        .output()
        .expect("run manyfw check");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("LegacyMigrationRequired"));
    assert!(stderr.contains("suggested equivalent"));
}

#[test]
fn check_reports_missing_default_unknown_fields_and_conflicts() {
    for (file, code) in [
        (
            "../../examples/invalid/missing-default.toml",
            "MissingField",
        ),
        ("../../examples/invalid/unknown-field.toml", "InvalidToml"),
        ("../../examples/invalid/conflict.toml", "Conflict"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
            .args(["check", "--file", file])
            .output()
            .expect("run manyfw check");
        assert!(!output.status.success(), "{file} unexpectedly succeeded");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(code), "{file}: {stderr}");
    }
}

#[test]
fn audit_emits_a_valid_report_and_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "audit",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
            "../../examples/empty-snapshot.json",
            "--format",
            "json",
        ])
        .output()
        .expect("run manyfw audit");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"version\": 1"));
    assert!(!stdout.contains("Safe"));
}

#[test]
fn audit_snapshot_failure_is_a_command_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "audit",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
            "../../examples/does-not-exist.json",
        ])
        .output()
        .expect("run manyfw audit");
    assert!(!output.status.success());
}
