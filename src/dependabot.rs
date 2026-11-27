use crate::ai::analyze_with_gemini;
use crate::auditor::{StackInfo, TodoItem};
use crate::github::{sanitize, GitHubClient, PullRequestSummary, RepoInfo};
use serde::Serialize;

const PASSING_CONCLUSIONS: &[&str] = &["success", "neutral", "skipped"];

#[derive(Debug, Clone, Serialize)]
pub struct FailedCheck {
    pub name: String,
    pub conclusion: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependabotEntry {
    pub repo: String,
    pub number: u64,
    pub title: String,
    pub url: String,
    pub status: String,
    pub reason: String,
    pub failed_checks: Vec<FailedCheck>,
    pub ai_diagnosis: Option<String>,
}

pub fn evaluate_dependabot_pr(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    pr: &PullRequestSummary,
) -> (String, String, Vec<FailedCheck>) {
    let details = client
        .get_pull(owner, repo, pr.number)
        .unwrap_or_else(|_| pr.clone());
    let sha = details
        .head
        .as_ref()
        .or(pr.head.as_ref())
        .map(|h| h.sha.as_str())
        .unwrap_or("");
    let mergeable_state = details.mergeable_state.as_deref().unwrap_or("unknown");

    let runs = if sha.is_empty() {
        vec![]
    } else {
        client
            .get_check_runs(owner, repo, sha)
            .map(|r| r.check_runs)
            .unwrap_or_default()
    };

    let pending: Vec<_> = runs.iter().filter(|r| r.status != "completed").collect();
    let failed: Vec<FailedCheck> = runs
        .iter()
        .filter(|r| {
            r.status == "completed"
                && !r
                    .conclusion
                    .as_deref()
                    .is_some_and(|c| PASSING_CONCLUSIONS.contains(&c))
        })
        .map(|r| FailedCheck {
            name: r.name.clone(),
            conclusion: r.conclusion.clone().unwrap_or_else(|| "unknown".into()),
            url: r.html_url.clone(),
        })
        .collect();

    if !failed.is_empty() {
        let names: Vec<_> = failed.iter().map(|f| f.name.as_str()).collect();
        return (
            "failed".into(),
            format!("{} CI check(s) failed: {}", failed.len(), names.join(", ")),
            failed,
        );
    }
    if mergeable_state == "dirty" || mergeable_state == "behind" {
        return (
            "rebase".into(),
            format!("PR mergeable_state is \"{mergeable_state}\""),
            vec![],
        );
    }
    if !pending.is_empty() {
        return (
            "pending".into(),
            format!("{} CI check(s) still running", pending.len()),
            vec![],
        );
    }
    if mergeable_state == "clean"
        || mergeable_state == "has_hooks"
        || (!runs.is_empty() && details.mergeable != Some(false))
    {
        let reason = if runs.is_empty() {
            "No blocking checks and mergeable".into()
        } else {
            format!("All {} CI check(s) passed", runs.len())
        };
        return ("merge".into(), reason, vec![]);
    }
    (
        "blocked".into(),
        format!("PR not ready (mergeable_state={mergeable_state})"),
        vec![],
    )
}

pub fn process_dependabot_prs(
    owner: &str,
    repos: &[RepoInfo],
    client: &GitHubClient,
    dry_run: bool,
    use_ai: bool,
    merge_method: &str,
) -> Vec<DependabotEntry> {
    let mut results = Vec::new();
    if client.token.is_none() {
        return results;
    }

    for repo_info in repos {
        let repo = &repo_info.name;
        let prs = match client.list_open_pulls(owner, repo) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("::warning::Could not list PRs for {repo}: {}", sanitize(&e));
                continue;
            }
        };

        for pr in prs.into_iter().filter(|p| {
            p.user
                .as_ref()
                .is_some_and(|u| u.login == "dependabot[bot]")
        }) {
            let (action, reason, failed_checks) = evaluate_dependabot_pr(client, owner, repo, &pr);
            let mut entry = DependabotEntry {
                repo: repo.clone(),
                number: pr.number,
                title: pr.title.clone(),
                url: pr.html_url.clone(),
                status: action.clone(),
                reason,
                failed_checks: failed_checks.clone(),
                ai_diagnosis: None,
            };

            if action == "failed" && use_ai {
                let stack = StackInfo {
                    languages: repo_info.language.clone().into_iter().collect(),
                    codeql_languages: vec![],
                    ecosystems: vec![],
                    package_manager: None,
                    has_tests: true,
                    test_files_count: 0,
                    linters: vec![],
                    has_dockerfile: false,
                    is_profile_repo: false,
                    is_publishable: false,
                    targets_windows_or_mac: false,
                    has_node_lockfile: false,
                    file_count: 0,
                };
                let todos: Vec<TodoItem> = failed_checks
                    .iter()
                    .map(|c| TodoItem {
                        id: "CI-FAIL",
                        title: "Dependabot PR CI failure",
                        priority: "High",
                        category: "CI/CD",
                        auto_fixable: false,
                        reason: format!("Check {} concluded with {}", c.name, c.conclusion),
                        resolution: "Inspect failing check logs".into(),
                    })
                    .collect();
                let ai = analyze_with_gemini(
                    &format!("{repo}#{}", pr.number),
                    &stack,
                    &[],
                    &todos,
                    None,
                );
                if ai.status == "ok" {
                    entry.ai_diagnosis = ai.insights;
                }
            }

            if !dry_run {
                if action == "merge" {
                    match client.merge_pull(owner, repo, pr.number, merge_method) {
                        Ok(()) => {
                            entry.status = "merged".into();
                            println!("Merged Dependabot PR {repo}#{}: {}", pr.number, pr.title);
                        }
                        Err(e) => {
                            entry.status = "error".into();
                            entry.reason = sanitize(&e);
                        }
                    }
                } else if action == "rebase" {
                    match client.add_comment(owner, repo, pr.number, "@dependabot rebase") {
                        Ok(()) => {
                            entry.status = "rebased".into();
                            println!("Requested @dependabot rebase on {repo}#{}", pr.number);
                        }
                        Err(e) => {
                            entry.status = "error".into();
                            entry.reason = sanitize(&e);
                        }
                    }
                }
            }

            results.push(entry);
        }
    }
    results
}
