use crate::config::BotConfig;
use crate::github::{GithubAlerts, RepoPosture};
use crate::scanner::{RepoMetadata, ScanFindings};
use crate::transformer::TransformResult;
use crate::vulns::PackageVulnFinding;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSnapshot {
    pub sha: Option<String>,
    pub cves: Vec<String>,
    pub sec: usize,
    pub wf: usize,
    pub alerts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub time: String,
    pub repos: BTreeMap<String, RepoSnapshot>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SummaryTotals {
    pub vulns: usize,
    pub secrets: usize,
    pub history_secrets: usize,
    pub workflow_risks: usize,
    pub integrity: usize,
    pub github_alerts: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoReportEntry {
    pub name: String,
    pub metadata: RepoMetadata,
    pub posture: Option<RepoPosture>,
    pub dep_count: usize,
    pub osv_status: String,
    pub vulns: Vec<PackageVulnFinding>,
    pub cve_count: usize,
    pub github_alerts: GithubAlerts,
    pub github_alerts_count: usize,
    pub vulnerability_alerts_disabled: bool,
    pub findings: ScanFindings,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailedRepo {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchSummary {
    pub owner: String,
    pub total: usize,
    pub scanned_time: String,
    pub repos: Vec<RepoReportEntry>,
    pub failed_repos: Vec<FailedRepo>,
    pub changes: Vec<String>,
    pub transform_results: Vec<TransformResult>,
    pub totals: SummaryTotals,
    pub snapshot: Option<Snapshot>,
}

pub fn build_snapshot(summary: &WatchSummary) -> Snapshot {
    let mut repos = BTreeMap::new();
    for r in &summary.repos {
        let mut cves = Vec::new();
        for p in &r.vulns {
            for v in &p.vulns {
                cves.push(format!(
                    "{}@{}:{}",
                    p.name,
                    p.version,
                    v.cve.as_deref().unwrap_or(&v.id)
                ));
            }
        }
        cves.sort();
        repos.insert(
            r.name.clone(),
            RepoSnapshot {
                sha: r.metadata.head_sha.clone(),
                cves,
                sec: r.findings.secrets.len() + r.findings.history_secrets.len(),
                wf: r.findings.workflow_risks.len(),
                alerts: r.github_alerts_count,
            },
        );
    }
    Snapshot {
        time: summary.scanned_time.clone(),
        repos,
    }
}

pub fn extract_snapshot_from_text(text: &str) -> Option<Snapshot> {
    let mut idx = text.find("<!--")?;
    loop {
        let end = text[idx + 4..].find("-->").map(|o| idx + 4 + o)?;
        let inner = text[idx + 4..end].trim();
        if let Some(rest) = inner.strip_prefix("watch-snapshot:") {
            return serde_json::from_str::<Snapshot>(rest.trim()).ok();
        }
        idx = text[end + 3..].find("<!--").map(|o| end + 3 + o)?;
    }
}

pub fn diff_snapshots(prev: Option<&Snapshot>, curr: &Snapshot) -> Vec<String> {
    let Some(p) = prev else { return vec![] };
    let mut changes = Vec::new();
    for (name, cur) in &curr.repos {
        let Some(old) = p.repos.get(name) else {
            changes.push(format!("Added repo `{name}`"));
            continue;
        };
        if let (Some(o_sha), Some(c_sha)) = (&old.sha, &cur.sha) {
            if o_sha != c_sha {
                changes.push(format!("`{name}`: commit `{o_sha}` -> `{c_sha}`"));
            }
        }
        let old_set: BTreeSet<&str> = old.cves.iter().map(String::as_str).collect();
        let cur_set: BTreeSet<&str> = cur.cves.iter().map(String::as_str).collect();
        let new_cves: Vec<&str> = cur_set.difference(&old_set).copied().collect();
        let fixed_cves: Vec<&str> = old_set.difference(&cur_set).copied().collect();
        if !new_cves.is_empty() {
            changes.push(format!(
                "`{name}`: **+{} new CVE(s)** ({})",
                new_cves.len(),
                new_cves[..new_cves.len().min(4)].join(", ")
            ));
        }
        if !fixed_cves.is_empty() {
            changes.push(format!("`{name}`: resolved {} CVE(s)", fixed_cves.len()));
        }
        if cur.sec > old.sec {
            changes.push(format!(
                "`{name}`: **+{} secret finding(s)**",
                cur.sec - old.sec
            ));
        }
        if cur.wf > old.wf {
            changes.push(format!(
                "`{name}`: **+{} workflow risk(s)**",
                cur.wf - old.wf
            ));
        }
        if cur.alerts > old.alerts {
            changes.push(format!(
                "`{name}`: **+{} GitHub alert(s)**",
                cur.alerts - old.alerts
            ));
        }
    }
    for old_name in p.repos.keys() {
        if !curr.repos.contains_key(old_name) {
            changes.push(format!("Removed/excluded repo `{old_name}`"));
        }
    }
    changes
}

pub fn build_markdown_report(
    config: &BotConfig,
    summary: &WatchSummary,
    embed_snapshot: bool,
) -> String {
    let mut lines = Vec::new();
    let t = &summary.totals;
    let problem_count = t.vulns
        + t.secrets
        + t.history_secrets
        + t.workflow_risks
        + t.integrity
        + t.github_alerts
        + summary.failed_repos.len();

    lines.push(format!(
        "# Repository Security & Status Monitor (@{})",
        config.owner
    ));
    lines.push(format!(
        "\nScanned **{}** repository(ies) at `{}`.\n",
        summary.total, summary.scanned_time
    ));
    if problem_count == 0 {
        lines.push(format!("> **All Clear**: No vulnerabilities, leaked secrets, workflow risks, or GitHub alerts detected across **{}** repo(s).\n", summary.total));
    } else {
        lines.push(format!("> **Attention Needed**: **{}** CVE(s), **{}** secret finding(s), **{}** workflow risk(s), **{}** GitHub alert(s), **{}** config/hygiene note(s).\n", t.vulns, t.secrets + t.history_secrets, t.workflow_risks, t.github_alerts, t.integrity));
    }

    if !summary.changes.is_empty() {
        lines.push("## Changes Since Last Scan\n".into());
        for c in &summary.changes {
            lines.push(format!("- {c}"));
        }
        lines.push(String::new());
    }

    if !summary.repos.is_empty() {
        lines.push("## Repository Inventory\n".into());
        lines.push("| Repository | Visibility | Language | Last Push | HEAD | Files | Deps | CVEs | PRs (Dep) | Protected | Alerts | Status |".into());
        lines.push("|------------|------------|----------|-----------|------|------:|-----:|-----:|----------:|-----------|-------:|--------|".into());
        for r in &summary.repos {
            let m = &r.metadata;
            let push_col = m
                .pushed_at
                .as_deref()
                .map(|d| {
                    if m.stale {
                        format!("{d} (stale)")
                    } else {
                        d.to_string()
                    }
                })
                .unwrap_or_else(|| "-".into());
            let pr_col = r
                .posture
                .as_ref()
                .map(|p| {
                    if p.dependabot_prs > 0 {
                        format!("{} ({})", p.open_prs, p.dependabot_prs)
                    } else {
                        p.open_prs.to_string()
                    }
                })
                .unwrap_or_else(|| "-".into());
            let prot_col = r
                .posture
                .as_ref()
                .and_then(|p| p.branch_protected)
                .map(|b| if b { "yes" } else { "no" })
                .unwrap_or("-");
            let issue_sum = r.cve_count
                + r.findings.secrets.len()
                + r.findings.history_secrets.len()
                + r.findings.workflow_risks.len()
                + r.findings.integrity.len()
                + r.github_alerts_count;
            let status = if issue_sum == 0 && !r.vulnerability_alerts_disabled {
                "OK"
            } else {
                "WARN"
            };
            lines.push(format!(
                "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                r.name,
                m.visibility,
                m.language.as_deref().unwrap_or("-"),
                push_col,
                m.head_sha
                    .as_deref()
                    .map(|s| format!("`{s}`"))
                    .unwrap_or_else(|| "-".into()),
                m.file_count,
                r.dep_count,
                r.cve_count,
                pr_col,
                prot_col,
                r.github_alerts_count,
                status
            ));
        }
        lines.push(String::new());
    }

    lines.push(
        "---\n*Generated by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*"
            .into(),
    );
    if embed_snapshot {
        if let Some(ref snap) = summary.snapshot {
            if let Ok(json) = serde_json::to_string(snap) {
                lines.push(format!("<!-- watch-snapshot:{json} -->"));
            }
        }
    }
    lines.join("\n")
}

pub fn build_portfolio_audit_report(
    owner: &str,
    scanned_time: &str,
    results: &[TransformResult],
) -> String {
    let mut lines = vec![
        format!("# Portfolio Engineering & DevSecOps Health Report (@{owner})"),
        String::new(),
        format!(
            "Generated at `{scanned_time}` across **{}** repository(ies).",
            results.len()
        ),
        String::new(),
        "| Repository | Stack | Pass | Needs Work | Blocked | Patches | PR Status |".to_string(),
        "|---|---|---:|---:|---:|---:|---|".to_string(),
    ];
    for r in results {
        let pass = r
            .audit
            .scorecard
            .iter()
            .filter(|s| s.status == "Pass")
            .count();
        let nw = r
            .audit
            .scorecard
            .iter()
            .filter(|s| s.status == "Needs Work")
            .count();
        let blk = r
            .audit
            .scorecard
            .iter()
            .filter(|s| s.status == "Blocked")
            .count();
        let stack = if r.audit.stack.languages.is_empty() {
            "docs".into()
        } else {
            r.audit.stack.languages.join(", ")
        };
        let pr_cell = r
            .pr_url
            .as_deref()
            .map(|u| format!("[{}]({u})", r.pr_action))
            .unwrap_or_else(|| r.pr_action.clone());
        lines.push(format!(
            "| `{}` | {stack} | {pass} | {nw} | {blk} | {} | {pr_cell} |",
            r.repo, r.patches_count
        ));
    }
    lines.push(String::new());
    lines.push(
        "---\n*Generated by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*"
            .into(),
    );
    lines.join("\n")
}

pub fn write_portfolio_reports(
    reports_dir: &Path,
    owner: &str,
    scanned_time: &str,
    results: &[TransformResult],
) -> Result<PathBuf, String> {
    fs::create_dir_all(reports_dir).map_err(|e| e.to_string())?;
    let portfolio_path = reports_dir.join("PORTFOLIO_REPORT.md");
    let md = build_portfolio_audit_report(owner, scanned_time, results);
    fs::write(&portfolio_path, format!("{md}\n")).map_err(|e| e.to_string())?;
    for r in results {
        fs::write(
            reports_dir.join(format!("{}.md", r.repo)),
            format!("{}\n", r.report_markdown),
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(portfolio_path)
}
