use crate::ai::analyze_with_gemini;
use crate::auditor::{audit_repository, AuditResult, STANDARD_LABELS};
use crate::github::{apply_git_auth, sanitize, GitHubClient, RepoInfo, RepoPosture};
use crate::scanner::ScanFindings;
use crate::templates::{generate_repo_patches, RepoPatch};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

pub const DEFAULT_BRANCH_NAME: &str = "chore/authormark-engineering-standards";

#[derive(Debug, Clone, Serialize)]
pub struct TransformResult {
    pub repo: String,
    pub audit: AuditResult,
    pub patches_count: usize,
    pub patched_files: Vec<String>,
    pub pr_url: Option<String>,
    pub pr_action: String,
    pub labels_synced: usize,
    pub ai_status: String,
    pub report_markdown: String,
}

pub fn build_pr_body(
    audit: &AuditResult,
    patches: &[RepoPatch],
    ai_insights: Option<&str>,
    posture: Option<&RepoPosture>,
) -> String {
    let mut lines = vec![
        format!(
            "# Automated DevSecOps, Quality & Governance Audit for `{}`",
            audit.repo
        ),
        String::new(),
        format!(
            "**Detected Stack:** {} (Package manager: `{}`)",
            if audit.stack.languages.is_empty() {
                "docs/static".into()
            } else {
                audit.stack.languages.join(", ")
            },
            audit.stack.package_manager.as_deref().unwrap_or("none")
        ),
        String::new(),
    ];

    if !patches.is_empty() {
        lines.push("## Changes Included in This PR\n".into());
        for p in patches {
            lines.push(format!("- `{}` — {}", p.path, p.reason));
        }
        lines.push(String::new());
    }

    lines.push("## Repository Health Scorecard (Baseline)\n".into());
    lines.push("| Category | Status | Evidence |".into());
    lines.push("|---|---|---|".into());
    for s in &audit.scorecard {
        lines.push(format!(
            "| {} | {} | {} |",
            s.category, s.status, s.evidence
        ));
    }
    lines.push(String::new());

    if !audit.todos.is_empty() {
        lines.push("## Remaining TODOs & Manual Admin Checklist\n".into());
        for t in &audit.todos {
            let tag = if t.auto_fixable {
                "Auto-addressed in PR"
            } else {
                "Manual Action Required"
            };
            lines.push(format!(
                "- **[{}] {}: {}** ({tag}) — {} *Resolution:* {}",
                t.priority, t.id, t.title, t.reason, t.resolution
            ));
        }
        lines.push(String::new());
    }

    if posture.is_some_and(|p| p.branch_protected == Some(false)) {
        lines.push("> [!IMPORTANT]\n> Default branch protection is currently disabled. Enable PR reviews and status checks in **Settings -> Branches**.\n".into());
    }

    if let Some(ins) = ai_insights {
        lines.push("## AI Architecture & QA Recommendations\n".into());
        lines.push(ins.to_string());
        lines.push(String::new());
    }

    lines.push("---\n*Generated automatically by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*".into());
    lines.join("\n")
}

pub fn apply_patches_to_disk(repo_dir: &Path, patches: &[RepoPatch]) -> Result<(), String> {
    for p in patches {
        let dest = repo_dir.join(&p.path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&dest, &p.content).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run_git(repo_dir: &Path, token: Option<&str>, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("git");
    cmd.args(args)
        .current_dir(repo_dir)
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    apply_git_auth(&mut cmd, token);
    let out = cmd.output().map_err(|e| sanitize(&e.to_string()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(sanitize(&String::from_utf8_lossy(&out.stderr)))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn transform_repository(
    owner: &str,
    repo_dir: &Path,
    repo_meta: &RepoInfo,
    cve_count: usize,
    findings: &ScanFindings,
    posture: Option<&RepoPosture>,
    client: Option<&GitHubClient>,
    token: Option<&str>,
    dry_run: bool,
    use_ai: bool,
) -> TransformResult {
    let repo_name = if repo_meta.name.is_empty() {
        repo_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("repo")
            .to_string()
    } else {
        repo_meta.name.clone()
    };
    let default_branch = repo_meta.default_branch.as_deref().unwrap_or("main");
    let audit = audit_repository(repo_dir, repo_meta, cve_count, findings, posture);
    let patches = generate_repo_patches(&audit, owner, default_branch, |rel| {
        repo_dir.join(rel).exists()
    });

    let ai_res = if use_ai {
        analyze_with_gemini(
            &repo_name,
            &audit.stack,
            &audit.scorecard,
            &audit.todos,
            None,
        )
    } else {
        crate::ai::AiResult {
            status: "skipped".into(),
            insights: None,
        }
    };

    let pr_body = build_pr_body(&audit, &patches, ai_res.insights.as_deref(), posture);
    let mut res = TransformResult {
        repo: repo_name.clone(),
        audit,
        patches_count: patches.len(),
        patched_files: patches.iter().map(|p| p.path.clone()).collect(),
        pr_url: None,
        pr_action: if dry_run {
            "dry-run".into()
        } else {
            "none".into()
        },
        labels_synced: 0,
        ai_status: ai_res.status,
        report_markdown: pr_body.clone(),
    };

    if dry_run {
        return res;
    }

    let Some(gh) = client.filter(|c| c.token.is_some()) else {
        return res;
    };
    res.labels_synced = gh.sync_labels(owner, &repo_name, STANDARD_LABELS);

    if patches.is_empty() || token.is_none() {
        return res;
    }

    let branch = DEFAULT_BRANCH_NAME;
    let push_res = (|| -> Result<(), String> {
        run_git(repo_dir, token, &["checkout", "-B", branch])?;
        apply_patches_to_disk(repo_dir, &patches)?;
        run_git(repo_dir, token, &["add", "-A"])?;
        if run_git(repo_dir, token, &["status", "--porcelain"])?
            .trim()
            .is_empty()
        {
            res.pr_action = "up-to-date".into();
            return Ok(());
        }
        run_git(
            repo_dir,
            token,
            &["config", "user.name", "authormark-watch[bot]"],
        )?;
        run_git(
            repo_dir,
            token,
            &[
                "config",
                "user.email",
                "authormark-watch[bot]@users.noreply.github.com",
            ],
        )?;
        run_git(
            repo_dir,
            token,
            &[
                "commit",
                "-m",
                "chore: apply DevSecOps, CI, security, and governance standards",
            ],
        )?;
        let refspec = format!("refs/heads/{branch}");
        run_git(repo_dir, token, &["push", "--force", "origin", &refspec])?;

        let title = "chore: apply DevSecOps, CI, security & governance standards";
        if let Some(existing) = gh.find_open_pr_by_branch(owner, &repo_name, branch) {
            let updated = gh.update_pull(owner, &repo_name, existing.number, title, &pr_body)?;
            res.pr_url = updated.map(|u| u.html_url).or(Some(existing.html_url));
            res.pr_action = "updated".into();
        } else {
            let created =
                gh.create_pull(owner, &repo_name, title, &pr_body, branch, default_branch)?;
            res.pr_url = created.map(|c| c.html_url);
            res.pr_action = "created".into();
        }
        Ok(())
    })();

    if let Err(err) = push_res {
        res.pr_action = "error".into();
        eprintln!(
            "::warning::Transform failed for {repo_name}: {}",
            sanitize(&err)
        );
    }
    res
}
