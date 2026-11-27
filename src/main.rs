use authormark_watch::config::{apply_repo_overrides, load_config};
use authormark_watch::dependabot::process_dependabot_prs;
use authormark_watch::github::{
    clone_repo, notify, resolve_issue_token, resolve_token, sanitize, GitHubClient, RepoInfo,
};
use authormark_watch::report::{
    build_markdown_report, build_portfolio_audit_report, build_snapshot, diff_snapshots,
    extract_snapshot_from_text, write_portfolio_reports, FailedRepo, RepoReportEntry,
    SummaryTotals, WatchSummary,
};
use authormark_watch::scanner::scan_repository;
use authormark_watch::transformer::transform_repository;
use authormark_watch::vulns::{parse_dependencies, query_osv_vulnerabilities, OsvResult};
use authormark_watch::webhook::run_webhook_server;
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "authormark-watch",
    version,
    about = "Cross-repo security scanner, DevSecOps auditor & PR transformer"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, env = "TARGET_REPO")]
    repo: Option<String>,

    #[arg(long)]
    public_only: bool,

    #[arg(long)]
    audit: bool,

    #[arg(long)]
    transform: bool,

    #[arg(long)]
    dependabot: bool,

    #[arg(long)]
    ai: bool,

    #[arg(long)]
    write_reports: bool,

    #[arg(long, env = "SNAPSHOT_PATH")]
    snapshot: Option<PathBuf>,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    no_osv: bool,

    #[arg(long)]
    dry_run: bool,

    #[arg(long, default_value = "squash")]
    merge_method: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the HMAC-SHA256 verified GitHub webhook server
    Webhook {
        #[arg(long, env = "WEBHOOK_PORT", default_value_t = 8787)]
        port: u16,
    },
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn main() {
    let cli = Cli::parse();

    if let Some(Commands::Webhook { port }) = cli.command {
        let secret = env::var("WEBHOOK_SECRET").unwrap_or_default();
        if let Err(e) = run_webhook_server(port, &secret) {
            eprintln!("::error::{e}");
            process::exit(1);
        }
        return;
    }

    let exe_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = load_config(&exe_dir.join("bot.config.json"));
    let token = resolve_token();
    let issue_token = resolve_issue_token();

    let is_dry_run = cli.dry_run || env_flag("DRY_RUN");
    let do_transform = cli.transform || env_flag("TRANSFORM");
    let do_audit = do_transform || cli.audit || env_flag("AUDIT");
    let do_dependabot = cli.dependabot || env_flag("DEPENDABOT_AUTOMERGE");
    let use_ai = cli.ai || env_flag("USE_AI");
    let write_reports = cli.write_reports || env_flag("WRITE_REPORTS");
    let public_only = cli.public_only || env_flag("PUBLIC_ONLY");
    let skip_osv = cli.no_osv || env_flag("SKIP_OSV");

    let client = GitHubClient::new(token.clone());
    let issue_client = GitHubClient::new(issue_token.or_else(|| token.clone()));

    let existing_issue = if issue_client.token.is_some() {
        issue_client.find_tracking_issue(
            &config.owner,
            "authormark-watch",
            &["watch:", "authormark:"],
        )
    } else {
        None
    };

    let prev_snapshot = cli
        .snapshot
        .as_ref()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .or_else(|| {
            existing_issue
                .as_ref()
                .and_then(|i| i.body.as_deref())
                .and_then(extract_snapshot_from_text)
        });

    let mut repos: Vec<RepoInfo> = if let Some(ref target) = cli.repo {
        let meta = if token.is_some() {
            client.get_repo(&config.owner, target).ok().flatten()
        } else {
            None
        };
        vec![meta.unwrap_or_else(|| RepoInfo {
            name: target.clone(),
            ..Default::default()
        })]
    } else if token.is_some() {
        match client.list_repos(&config.owner) {
            Ok(list) => list,
            Err(e) => {
                eprintln!(
                    "::error::Could not retrieve repository list: {}",
                    sanitize(&e)
                );
                config
                    .repos
                    .include
                    .iter()
                    .map(|n| RepoInfo {
                        name: n.clone(),
                        ..Default::default()
                    })
                    .collect()
            }
        }
    } else {
        vec![]
    };

    let mut seen: HashSet<String> = repos.iter().map(|r| r.name.to_lowercase()).collect();
    for inc in &config.repos.include {
        if seen.insert(inc.to_lowercase()) {
            repos.push(RepoInfo {
                name: inc.clone(),
                ..Default::default()
            });
        }
    }

    let exclude_set: HashSet<String> = config
        .repos
        .exclude
        .iter()
        .chain(config.repos.skip.iter())
        .map(|s| s.to_lowercase())
        .collect();

    let filtered: Vec<RepoInfo> = repos
        .into_iter()
        .filter(|r| {
            let n = r.name.to_lowercase();
            !exclude_set.contains(&n)
                && (config.repos.include_archived || !r.archived)
                && (config.repos.include_forks || !r.fork)
                && (!public_only || !r.private)
        })
        .collect();

    if do_dependabot {
        let dep_results = process_dependabot_prs(
            &config.owner,
            &filtered,
            &client,
            is_dry_run,
            use_ai,
            &cli.merge_method,
        );
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&dep_results).unwrap_or_default()
            );
        } else if dep_results.is_empty() {
            println!(
                "No open Dependabot PRs found across {} repo(s).",
                filtered.len()
            );
        } else {
            println!("# Dependabot PR Automation Summary\n\n| Repository | PR | Title | Status | Reason |\n|---|---|---|---|---|");
            for d in &dep_results {
                println!(
                    "| `{}` | [#{}]({}) | {} | {} | {} |",
                    d.repo, d.number, d.url, d.title, d.status, d.reason
                );
            }
        }
        return;
    }

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut summary = WatchSummary {
        owner: config.owner.clone(),
        total: filtered.len(),
        scanned_time: chrono::Utc::now().to_rfc3339(),
        repos: vec![],
        failed_repos: vec![],
        changes: vec![],
        transform_results: vec![],
        totals: SummaryTotals::default(),
        snapshot: None,
    };

    for repo_info in &filtered {
        let name = &repo_info.name;
        let dest = temp_dir.path().join(name);
        if token.is_some() {
            let depth = if do_transform && !is_dry_run { 20 } else { 1 };
            if let Err(err) = clone_repo(&config.owner, name, &dest, token.as_deref(), depth) {
                eprintln!("::warning::Could not clone {name}: {}", sanitize(&err));
                summary.failed_repos.push(FailedRepo {
                    name: name.clone(),
                    reason: "Clone failed or repository inaccessible".into(),
                });
                continue;
            }
        } else {
            summary.failed_repos.push(FailedRepo {
                name: name.clone(),
                reason: "No GitHub token available".into(),
            });
            continue;
        }

        let repo_cfg = apply_repo_overrides(&config, &dest);
        if !repo_cfg.enabled {
            continue;
        }

        let (metadata, findings) =
            scan_repository(&dest, repo_info, &repo_cfg.checks, &repo_cfg.allowlist);
        let deps = parse_dependencies(&dest);

        let mut osv = if repo_cfg.checks.vulnerabilities && !skip_osv && !deps.is_empty() {
            query_osv_vulnerabilities(&deps)
        } else {
            OsvResult {
                status: "skipped".into(),
                checked: deps.len(),
                findings: vec![],
            }
        };

        if !repo_cfg.allowlist.ignore_vulns.is_empty() && !osv.findings.is_empty() {
            let ignored: HashSet<String> = repo_cfg
                .allowlist
                .ignore_vulns
                .iter()
                .map(|v| v.to_uppercase())
                .collect();
            for p in &mut osv.findings {
                p.vulns.retain(|v| {
                    !ignored.contains(&v.id.to_uppercase())
                        && !v
                            .cve
                            .as_ref()
                            .is_some_and(|c| ignored.contains(&c.to_uppercase()))
                });
            }
            osv.findings.retain(|p| !p.vulns.is_empty());
        }

        let github_alerts = if token.is_some() && repo_cfg.checks.github_alerts {
            client.count_open_alerts(&repo_cfg.owner, name)
        } else {
            Default::default()
        };
        let posture = if token.is_some() && repo_cfg.checks.posture {
            Some(client.get_repo_posture(&repo_cfg.owner, name, repo_info))
        } else {
            None
        };

        let cve_count: usize = osv.findings.iter().map(|f| f.vulns.len()).sum();
        let gh_alerts_count =
            github_alerts.dependabot + github_alerts.code_scanning + github_alerts.secret_scanning;
        let vuln_disabled = github_alerts.vulnerability_alerts_disabled;

        if do_audit {
            let t_res = transform_repository(
                &repo_cfg.owner,
                &dest,
                repo_info,
                cve_count,
                &findings,
                posture.as_ref(),
                Some(&client),
                token.as_deref(),
                is_dry_run || !do_transform,
                use_ai,
            );
            summary.transform_results.push(t_res);
        }

        summary.totals.vulns += cve_count;
        summary.totals.secrets += findings.secrets.len();
        summary.totals.history_secrets += findings.history_secrets.len();
        summary.totals.workflow_risks += findings.workflow_risks.len();
        summary.totals.integrity += findings.integrity.len();
        summary.totals.github_alerts += gh_alerts_count;

        summary.repos.push(RepoReportEntry {
            name: name.clone(),
            metadata,
            posture,
            dep_count: deps.len(),
            osv_status: osv.status,
            vulns: osv.findings,
            cve_count,
            github_alerts,
            github_alerts_count: gh_alerts_count,
            vulnerability_alerts_disabled: vuln_disabled,
            findings,
        });
    }

    let snap = build_snapshot(&summary);
    summary.changes = diff_snapshots(prev_snapshot.as_ref(), &snap);
    summary.snapshot = Some(snap);

    if let Some(ref snap_path) = cli.snapshot {
        if !is_dry_run {
            if let Some(ref s) = summary.snapshot {
                let _ = fs::write(
                    snap_path,
                    format!("{}\n", serde_json::to_string_pretty(s).unwrap_or_default()),
                );
            }
        }
    }

    if do_audit && write_reports && !is_dry_run {
        let _ = write_portfolio_reports(
            &exe_dir.join("reports"),
            &config.owner,
            &summary.scanned_time,
            &summary.transform_results,
        );
    }

    let console_report = if do_audit {
        build_portfolio_audit_report(
            &config.owner,
            &summary.scanned_time,
            &summary.transform_results,
        )
    } else {
        build_markdown_report(&config, &summary, false)
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        );
    } else {
        println!("{console_report}");
    }

    let has_issues = summary.totals.vulns > 0
        || summary.totals.secrets > 0
        || summary.totals.history_secrets > 0
        || summary.totals.workflow_risks > 0
        || summary.totals.integrity > 0
        || summary.totals.github_alerts > 0
        || !summary.failed_repos.is_empty()
        || summary
            .repos
            .iter()
            .any(|r| r.vulnerability_alerts_disabled);

    if let Ok(step_summary) = env::var("GITHUB_STEP_SUMMARY") {
        let _ = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(step_summary)
            .and_then(|mut f| {
                std::io::Write::write_all(&mut f, format!("{console_report}\n").as_bytes())
            });
    }

    let slack = config
        .notify
        .slack
        .as_deref()
        .or_else(|| env::var("SLACK_WEBHOOK").ok().as_deref().map(|_| ""));
    let _ = slack;
    let slack_url = config
        .notify
        .slack
        .clone()
        .or_else(|| env::var("SLACK_WEBHOOK").ok());
    let discord_url = config
        .notify
        .discord
        .clone()
        .or_else(|| env::var("DISCORD_WEBHOOK").ok());
    if has_issues {
        let msg = format!(
            "*Repo Watch* (@{}) — {} CVE(s), {} secret(s), {} workflow risk(s) across {} repo(s).",
            config.owner,
            summary.totals.vulns,
            summary.totals.secrets + summary.totals.history_secrets,
            summary.totals.workflow_risks,
            summary.total
        );
        notify(
            slack_url.as_deref(),
            discord_url.as_deref(),
            &msg,
            is_dry_run,
        );
    }

    if env::var("REPORT").ok().as_deref() != Some("0")
        && !is_dry_run
        && issue_client.token.is_some()
    {
        let dashboard_title = "watch: Security & Repo Monitor Dashboard";
        let issue_body = build_markdown_report(&config, &summary, true);
        if let Some(ref existing) = existing_issue {
            let state = if has_issues { "open" } else { "closed" };
            let _ = issue_client.update_issue(
                &config.owner,
                "authormark-watch",
                existing.number,
                dashboard_title,
                &issue_body,
                state,
            );
            let _ = issue_client.add_comment(
                &config.owner,
                "authormark-watch",
                existing.number,
                &format!(
                    "Scan completed at `{}`. Status: **{}**.",
                    summary.scanned_time,
                    if has_issues {
                        "Findings require attention"
                    } else {
                        "All Clear"
                    }
                ),
            );
        } else if has_issues {
            let _ = issue_client.create_issue(
                &config.owner,
                "authormark-watch",
                dashboard_title,
                &issue_body,
                &["security"],
            );
        }
    }
}
