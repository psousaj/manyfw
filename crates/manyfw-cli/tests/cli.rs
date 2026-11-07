use std::process::Command;

#[test]
fn apply_requires_explicit_experimental_opt_in_before_reading_plan() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args(["apply", "--file", "/not-read-before-opt-in.json"])
        .output()
        .expect("run manyfw apply");
    assert!(!output.status.success());
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["status"], "error");
    assert!(
        diagnostic["diagnostic"]
            .as_str()
            .unwrap()
            .contains("--experimental")
    );
}

#[test]
fn check_reports_valid_policy_and_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args(["check", "--file", "../../examples/manyfw.toml"])
        .output()
        .expect("run manyfw check");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Valid schema v1 — 2 zones, 3 rules"));
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
    assert!(stdout.contains("rules[id=\"admin-vpn\"].port_scope"));
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
    assert!(stdout.contains("ports=5432"));
    assert!(stdout.contains("action=allow"));
    assert!(!stdout.contains("Zone("));
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
fn audit_partial_report_is_successful_and_human_output_is_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "audit",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
            "../../examples/partial-snapshot.json",
            "--format",
            "human",
        ])
        .output()
        .expect("run manyfw audit");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ManyFW audit report v1"));
    assert!(stdout.contains("READ-ONLY"));
    assert!(stdout.contains("IncompleteObservation"));
    assert!(stdout.contains("Unknown"));
    assert!(stdout.contains("unavailable"));
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

#[test]
fn explain_unresolved_service_is_explicit_and_versioned() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "explain",
            "missing",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
            "../../examples/empty-snapshot.json",
            "--format",
            "json",
        ])
        .output()
        .expect("run manyfw explain");
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"version\": 3"));
    assert!(stdout.contains("\"outcome\": \"unresolved_identity\""));
    assert!(stdout.contains("external reachability"));
    assert!(!stdout.contains("SAFE"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("did not resolve"));
}

#[test]
fn explain_ambiguous_selector_emits_candidates_and_fails() {
    let mut snapshot: serde_json::Value =
        serde_json::from_str(include_str!("../../../examples/empty-snapshot.json")).unwrap();
    snapshot["docker"]["containers"] = serde_json::json!([
        {"logical_identity":{"value":"docker:team-a/api","source":"ComposeLabels"},"instance":{"id":"instance-a","replica_key":"api-a"},"lifecycle":"Running","operational_status":"Running","network_mode":"Bridge","configured_publications":[],"observed_endpoints":[]},
        {"logical_identity":{"value":"docker:team-b/api","source":"ComposeLabels"},"instance":{"id":"instance-b","replica_key":"api-b"},"lifecycle":"Running","operational_status":"Running","network_mode":"Bridge","configured_publications":[],"observed_endpoints":[]}
    ]);
    let snapshot_path =
        std::env::temp_dir().join(format!("manyfw-ambiguous-{}.json", std::process::id()));
    std::fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "explain",
            "api",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
        ])
        .arg(&snapshot_path)
        .args(["--format", "json"])
        .output()
        .expect("run manyfw explain");
    let _ = std::fs::remove_file(snapshot_path);
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ambiguous_identity"));
    assert!(stdout.contains("docker:team-a/api"));
    assert!(stdout.contains("docker:team-b/api"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ambiguous service selector"));
}

#[test]
fn explain_rejects_unknown_format() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "explain",
            "missing",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
            "../../examples/empty-snapshot.json",
            "--format",
            "yaml",
        ])
        .output()
        .expect("run manyfw explain");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported explain format"));
}

#[test]
#[cfg(target_os = "linux")]
fn discover_writes_a_versioned_snapshot_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args(["discover", "--output", "-", "--color", "always"])
        .output()
        .expect("run manyfw discover");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: manyfw_core::snapshot::ObservationSnapshot =
        serde_json::from_slice(&output.stdout).expect("valid observation snapshot JSON");
    assert_eq!(
        snapshot.version(),
        manyfw_core::snapshot::OBSERVATION_SNAPSHOT_VERSION
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Safe"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("\u{1b}["));
}

#[test]
#[cfg(target_os = "linux")]
fn discover_supports_a_human_report_for_terminal_use() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "discover", "--output", "-", "--format", "human", "--color", "never",
        ])
        .output()
        .expect("run manyfw discover");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ManyFW discovery snapshot v1"));
    assert!(stdout.contains("Docker"));
    assert!(stdout.contains("Host network"));
    assert!(!stdout.trim_start().starts_with('{'));
    assert!(!stdout.contains("\u{1b}["));
}

#[test]
#[cfg(target_os = "linux")]
fn discover_can_force_color_in_captured_terminal_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "discover", "--output", "-", "--format", "human", "--color", "always",
        ])
        .output()
        .expect("run manyfw discover");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("\u{1b}["));
}

#[test]
#[cfg(target_os = "linux")]
fn discover_human_output_is_concise_by_default_and_verbose_on_request() {
    let summary = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "discover", "--output", "-", "--format", "human", "--color", "never",
        ])
        .output()
        .expect("run summary discovery");
    let summary = String::from_utf8_lossy(&summary.stdout);
    assert!(summary.contains("interfaces:"));
    assert!(!summary.contains("    route "));

    let details = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "discover",
            "--output",
            "-",
            "--format",
            "human",
            "--color",
            "never",
            "--verbose",
        ])
        .output()
        .expect("run detailed discovery");
    assert!(
        details.status.success(),
        "{}",
        String::from_utf8_lossy(&details.stderr)
    );
    let details = String::from_utf8_lossy(&details.stdout);
    assert!(details.contains("ManyFW discovery snapshot v1"));
}

#[test]
#[cfg(target_os = "linux")]
fn discover_keeps_json_as_the_non_terminal_default() {
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args(["discover", "--output", "-", "--color", "always"])
        .output()
        .expect("run manyfw discover");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("discovery JSON for non-terminal output");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("\u{1b}["));
    assert_eq!(snapshot["version"], 1);
    assert!(snapshot.get("docker").is_some());
    assert!(snapshot.get("host").is_some());
}

#[test]
fn discover_rejects_human_format_for_snapshot_files() {
    let target = std::env::temp_dir().join(format!("manyfw-human-{}.json", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args(["discover", "--output"])
        .arg(&target)
        .args(["--format", "human"])
        .output()
        .expect("run manyfw discover");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("only supported on stdout"));
    assert!(!target.exists());
}

#[test]
fn global_color_option_styles_check_and_plan_output() {
    for args in [
        vec![
            "check",
            "--file",
            "../../examples/manyfw.toml",
            "--color",
            "always",
        ],
        vec![
            "plan",
            "--file",
            "../../examples/manyfw.toml",
            "--color",
            "always",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_manyfw"))
            .args(args)
            .output()
            .expect("run human-readable command");
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("\u{1b}["),
            "command output was not colorized"
        );
    }
}

#[test]
fn global_color_option_styles_audit_and_explain_human_output() {
    let audit = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "audit",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
            "../../examples/partial-snapshot.json",
            "--format",
            "human",
            "--color",
            "always",
        ])
        .output()
        .expect("run manyfw audit");
    assert!(audit.status.success());
    let audit_stdout = String::from_utf8_lossy(&audit.stdout);
    assert!(audit_stdout.contains("\u{1b}["));
    assert!(audit_stdout.contains("Summary:"));
    assert!(audit_stdout.contains("\u{1b}[33mUnknown\u{1b}[0m: 1"));
    assert!(!audit_stdout.contains("ObservedExposure"));
    assert!(!audit_stdout.contains("Critical"));

    let explain = Command::new(env!("CARGO_BIN_EXE_manyfw"))
        .args([
            "explain",
            "missing",
            "--file",
            "../../examples/manyfw.toml",
            "--snapshot",
            "../../examples/empty-snapshot.json",
            "--format",
            "human",
            "--color",
            "always",
        ])
        .output()
        .expect("run manyfw explain");
    assert!(!explain.status.success());
    let explain_stdout = String::from_utf8_lossy(&explain.stdout);
    assert!(explain_stdout.contains("\u{1b}["));
    assert!(explain_stdout.contains("Summary:"));
    assert!(explain_stdout.contains("runtime unknown"));
}
