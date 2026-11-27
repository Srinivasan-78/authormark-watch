use authormark_watch::auditor::{audit_repository, detect_stack};
use authormark_watch::config::{apply_repo_overrides, load_config, BotConfig};
use authormark_watch::github::{sanitize, RepoInfo, RepoOwner, RepoPosture};
use authormark_watch::report::{
    build_markdown_report, diff_snapshots, extract_snapshot_from_text, RepoSnapshot, Snapshot,
    SummaryTotals, WatchSummary,
};
use authormark_watch::scanner::{audit_workflow, scan_repository, ScanFindings};
use authormark_watch::templates::generate_repo_patches;
use authormark_watch::transformer::transform_repository;
use authormark_watch::vulns::parse_dependencies;
use authormark_watch::webhook::verify_github_signature;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

#[test]
fn sanitize_redacts_tokens_and_git_credentials() {
    let tok = format!("using ghp_{} now", "A".repeat(36));
    assert_eq!(sanitize(&tok), "using *** now");
    let pat = format!("github_pat_{}", "B".repeat(82));
    assert_eq!(sanitize(&pat), "***");
    assert_eq!(
        sanitize("https://x-access-token:secret123@github.com/a/b.git"),
        "https://x-access-token:***@github.com/a/b.git"
    );
}

#[test]
fn config_loads_and_applies_repo_overrides() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("bot.config.json");
    fs::write(&cfg_path, r#"{"owner":"ada"}"#).unwrap();
    let base = load_config(&cfg_path);
    assert_eq!(base.owner, "ada");
    assert!(base.checks.vulnerabilities);

    fs::write(
        dir.path().join(".masterbot.json"),
        r#"{"checks":{"workflows":false},"ignoreSecrets":["fixtures/"],"ignoreVulns":["GHSA-1"]}"#,
    )
    .unwrap();
    let merged = apply_repo_overrides(&base, dir.path());
    assert!(!merged.checks.workflows);
    assert_eq!(merged.allowlist.ignore_secrets, vec!["fixtures/"]);
    assert_eq!(merged.allowlist.ignore_vulns, vec!["GHSA-1"]);
}

#[test]
fn parse_dependencies_supports_all_lockfiles() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("requirements.txt"),
        "requests[security]==2.31.0 ; python_version >= '3.8'\nflask>=2.0\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("go.mod"),
        "module x\nrequire (\n  github.com/gin-gonic/gin v1.9.0\n)\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();

    let deps = parse_dependencies(dir.path());
    assert!(deps
        .iter()
        .any(|d| d.ecosystem == "npm" && d.name == "lodash" && d.version == "4.17.20"));
    assert!(deps
        .iter()
        .any(|d| d.ecosystem == "PyPI" && d.name == "requests" && d.version == "2.31.0"));
    assert!(!deps.iter().any(|d| d.name == "flask"));
    assert!(deps
        .iter()
        .any(|d| d.ecosystem == "Go" && d.name == "github.com/gin-gonic/gin"));
    assert!(deps
        .iter()
        .any(|d| d.ecosystem == "crates.io" && d.name == "serde"));
}

#[test]
fn audit_workflow_flags_risks_and_allows_safe_env() {
    let risky = "name: x\non:\n  pull_request_target:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: some/thing@main\n      - run: echo ${{ github.event.issue.title }}\n      - run: curl http://x/i.sh | bash\n";
    let risks = audit_workflow(risky, "wf.yml").join(" || ");
    assert!(risks.contains("pull_request_target"));
    assert!(risks.contains("unpinned action"));
    assert!(risks.contains("no top-level `permissions:`"));
    assert!(risks.contains("pass via `env:` instead"));
    assert!(risks.contains("straight into a shell"));

    let safe = "name: safe\non: [issues]\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"$TITLE\"\n        env:\n          TITLE: ${{ github.event.issue.title }}\n";
    assert!(audit_workflow(safe, "safe.yml").is_empty());
}

#[test]
fn auditor_and_templates_generate_clean_workflows_without_license() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(dir.path().join("README.md"), "# Demo\n").unwrap();
    let meta = RepoInfo {
        name: "demo".into(),
        owner: Some(RepoOwner {
            login: "Srinivasan-78".into(),
        }),
        ..Default::default()
    };
    let stack = detect_stack(dir.path(), &meta);
    assert!(stack.languages.contains(&"rust".to_string()));

    let posture = RepoPosture {
        branch_protected: Some(false),
        ..Default::default()
    };
    let audit = audit_repository(
        dir.path(),
        &meta,
        0,
        &ScanFindings::default(),
        Some(&posture),
    );
    assert_eq!(audit.scorecard.len(), 15);
    assert!(audit
        .todos
        .iter()
        .any(|t| t.id == "LEG-01" && !t.auto_fixable));

    let patches = generate_repo_patches(&audit, "Srinivasan-78", "main", |rel| {
        dir.path().join(rel).exists()
    });
    assert!(!patches.iter().any(|p| p.path == "LICENSE"));
    for p in &patches {
        if p.path.starts_with(".github/workflows/") {
            assert!(
                audit_workflow(&p.content, &p.path).is_empty(),
                "workflow {} failed audit",
                p.path
            );
        }
    }

    let res = transform_repository(
        "Srinivasan-78",
        dir.path(),
        &meta,
        0,
        &ScanFindings::default(),
        Some(&posture),
        None,
        None,
        true,
        false,
    );
    assert_eq!(res.pr_action, "dry-run");
    assert!(res.patches_count > 0);
}

#[test]
fn scan_repository_detects_secrets_and_respects_allowlist() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("fixtures")).unwrap();
    let pem_hdr = format!("{}RSA PRIVATE KEY-----", "-----BEGIN ");
    fs::write(
        dir.path().join("fixtures").join("sample.key"),
        format!("{pem_hdr}\nTEST\n"),
    )
    .unwrap();
    fs::write(dir.path().join("id_rsa"), format!("{pem_hdr}\nMIIabc\n")).unwrap();
    fs::write(dir.path().join(".env"), "API_TOKEN=hunter2\n").unwrap();

    let cfg = BotConfig::default();
    let mut al = cfg.allowlist.clone();
    al.ignore_secrets.push("fixtures/".into());

    let (_meta, findings) = scan_repository(dir.path(), &RepoInfo::default(), &cfg.checks, &al);
    assert!(!findings
        .secrets
        .iter()
        .any(|s| s.contains("fixtures/sample.key")));
    assert!(findings.secrets.iter().any(|s| s.contains("id_rsa")));
    assert!(findings
        .secrets
        .iter()
        .any(|s| s.contains("Committed env file")));
}

#[test]
fn webhook_signature_verifies_hmac_sha256() {
    let secret = "my-secret";
    let payload = br#"{"action":"created"}"#;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload);
    let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    assert!(verify_github_signature(payload, Some(&sig), secret));
    assert!(!verify_github_signature(
        payload,
        Some("sha256=deadbeef"),
        secret
    ));
}

#[test]
fn snapshot_diff_and_markdown_embedding_roundtrip() {
    let mut prev_repos = BTreeMap::new();
    prev_repos.insert(
        "r1".into(),
        RepoSnapshot {
            sha: Some("aaa".into()),
            cves: vec!["a@1:CVE-1".into()],
            sec: 0,
            wf: 0,
            alerts: 0,
        },
    );
    let prev = Snapshot {
        time: "2026-01-01".into(),
        repos: prev_repos,
    };

    let mut curr_repos = BTreeMap::new();
    curr_repos.insert(
        "r1".into(),
        RepoSnapshot {
            sha: Some("bbb".into()),
            cves: vec!["b@2:CVE-2".into()],
            sec: 1,
            wf: 0,
            alerts: 0,
        },
    );
    let curr = Snapshot {
        time: "2026-01-02".into(),
        repos: curr_repos,
    };

    let changes = diff_snapshots(Some(&prev), &curr).join(" | ");
    assert!(changes.contains("aaa"));
    assert!(changes.contains("+1 new CVE"));
    assert!(changes.contains("resolved 1 CVE"));

    let summary = WatchSummary {
        owner: "ada".into(),
        total: 1,
        scanned_time: "2026-01-02".into(),
        repos: vec![],
        failed_repos: vec![],
        changes: vec![],
        transform_results: vec![],
        totals: SummaryTotals::default(),
        snapshot: Some(curr.clone()),
    };
    let md = build_markdown_report(&BotConfig::default(), &summary, true);
    let parsed = extract_snapshot_from_text(&md).expect("snapshot parsed");
    assert_eq!(parsed.time, curr.time);
}
