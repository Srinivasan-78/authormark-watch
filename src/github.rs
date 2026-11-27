use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoOwner {
    pub login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityStatus {
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityAndAnalysis {
    pub secret_scanning_push_protection: Option<SecurityStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoInfo {
    pub name: String,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub archived: bool,
    pub language: Option<String>,
    pub default_branch: Option<String>,
    pub pushed_at: Option<String>,
    pub owner: Option<RepoOwner>,
    pub security_and_analysis: Option<SecurityAndAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GithubAlerts {
    pub dependabot: usize,
    pub code_scanning: usize,
    pub secret_scanning: usize,
    pub vulnerability_alerts_disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoPosture {
    pub branch_protected: Option<bool>,
    pub codeql_default_setup: bool,
    pub push_protection: Option<bool>,
    pub open_prs: usize,
    pub dependabot_prs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestSummary {
    pub number: u64,
    pub title: String,
    pub html_url: String,
    pub user: Option<RepoOwner>,
    pub head: Option<PullHead>,
    pub mergeable: Option<bool>,
    pub mergeable_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullHead {
    pub sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRun {
    pub name: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub html_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRunsResponse {
    #[serde(default)]
    pub check_runs: Vec<CheckRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueSummary {
    pub number: u64,
    pub title: String,
    pub body: Option<String>,
    pub pull_request: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LabelSpec {
    pub name: &'static str,
    pub color: &'static str,
    pub description: &'static str,
}

pub fn sanitize(text: &str) -> String {
    static PAT_RE: OnceLock<Regex> = OnceLock::new();
    static GIT_RE: OnceLock<Regex> = OnceLock::new();
    let pat_re = PAT_RE
        .get_or_init(|| Regex::new(r"(gh[pousr]_|github_pat_)[A-Za-z0-9_]+").expect("valid regex"));
    let git_re =
        GIT_RE.get_or_init(|| Regex::new(r"x-access-token:[^@\s]+@").expect("valid regex"));
    let step1 = pat_re.replace_all(text, "***");
    git_re
        .replace_all(&step1, "x-access-token:***@")
        .into_owned()
}

pub fn resolve_token() -> Option<String> {
    for name in ["BOT_TOKEN", "WATCH_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(val) = env::var(name) {
            if !val.trim().is_empty() {
                return Some(val);
            }
        }
    }
    if let Ok(out) = Command::new("gh")
        .args(["auth", "token"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        if out.status.success() {
            let tok = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !tok.is_empty() {
                return Some(tok);
            }
        }
    }
    None
}

pub fn resolve_issue_token() -> Option<String> {
    env::var("ISSUE_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(resolve_token)
}

pub fn apply_git_auth(cmd: &mut Command, token: Option<&str>) {
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    if let Some(tok) = token {
        let raw = format!("x-access-token:{tok}");
        let encoded = base64_encode(raw.as_bytes());
        cmd.env("GIT_CONFIG_COUNT", "1");
        cmd.env("GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader");
        cmd.env(
            "GIT_CONFIG_VALUE_0",
            format!("AUTHORIZATION: basic {encoded}"),
        );
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn clone_repo(
    owner: &str,
    repo: &str,
    dest: &Path,
    token: Option<&str>,
    depth: u32,
) -> Result<(), String> {
    let url = format!("https://github.com/{owner}/{repo}.git");
    let mut cmd = Command::new("git");
    cmd.args(["clone", "--depth", &depth.to_string(), &url])
        .arg(dest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    apply_git_auth(&mut cmd, token);
    let out = cmd.output().map_err(|e| sanitize(&e.to_string()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(sanitize(&String::from_utf8_lossy(&out.stderr)))
    }
}

pub struct GitHubClient {
    pub token: Option<String>,
    http: Client,
    base_url: String,
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("reqwest client");
        Self {
            token,
            http,
            base_url: "https://api.github.com".to_string(),
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        h.insert(
            "X-GitHub-Api-Version",
            HeaderValue::from_static("2022-11-28"),
        );
        h.insert(
            USER_AGENT,
            HeaderValue::from_static(
                "authormark-watch/3.0 (+https://github.com/Srinivasan-78/authormark-watch)",
            ),
        );
        if let Some(ref tok) = self.token {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {tok}")) {
                h.insert(AUTHORIZATION, v);
            }
        }
        h
    }

    pub fn request_json<T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        endpoint: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Option<T>, String> {
        let url = if endpoint.starts_with("http") {
            endpoint.to_string()
        } else {
            format!("{}{}", self.base_url, endpoint)
        };
        let mut req = self
            .http
            .request(method.clone(), &url)
            .headers(self.headers());
        if let Some(b) = body {
            req = req.json(b);
        }
        let res = req.send().map_err(|e| sanitize(&e.to_string()))?;
        let status = res.status();
        if status.as_u16() == 204 {
            return Ok(None);
        }
        let text = res.text().unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "{} {} failed ({}): {}",
                method,
                endpoint,
                status.as_u16(),
                sanitize(&text)
            ));
        }
        if text.trim().is_empty() {
            return Ok(None);
        }
        serde_json::from_str::<T>(&text)
            .map(Some)
            .map_err(|e| format!("JSON parse error on {endpoint}: {e}"))
    }

    pub fn list_repos(&self, owner: &str) -> Result<Vec<RepoInfo>, String> {
        let mut repos = Vec::new();
        let base = if self.token.is_some() {
            "/user/repos?affiliation=owner&per_page=100&sort=pushed".to_string()
        } else {
            format!("/users/{owner}/repos?per_page=100&sort=pushed")
        };
        for page in 1..=20 {
            let ep = format!("{base}&page={page}");
            let batch: Vec<RepoInfo> = self
                .request_json(reqwest::Method::GET, &ep, None)?
                .unwrap_or_default();
            let count = batch.len();
            for r in batch {
                let matches = r
                    .owner
                    .as_ref()
                    .map(|o| o.login.eq_ignore_ascii_case(owner))
                    .unwrap_or(true);
                if matches {
                    repos.push(r);
                }
            }
            if count < 100 {
                break;
            }
        }
        Ok(repos)
    }

    pub fn get_repo(&self, owner: &str, repo: &str) -> Result<Option<RepoInfo>, String> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/repos/{owner}/{repo}"),
            None,
        )
    }

    pub fn count_open_alerts(&self, owner: &str, repo: &str) -> GithubAlerts {
        let fetch_len = |ep: &str| -> usize {
            self.request_json::<Vec<serde_json::Value>>(reqwest::Method::GET, ep, None)
                .ok()
                .flatten()
                .map(|v| v.len())
                .unwrap_or(0)
        };
        let dependabot = fetch_len(&format!(
            "/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100"
        ));
        let code_scanning = fetch_len(&format!(
            "/repos/{owner}/{repo}/code-scanning/alerts?state=open&per_page=100"
        ));
        let secret_scanning = fetch_len(&format!(
            "/repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100"
        ));
        let vuln_disabled = matches!(
            self.request_json::<serde_json::Value>(
                reqwest::Method::GET,
                &format!("/repos/{owner}/{repo}/vulnerability-alerts"),
                None,
            ),
            Err(e) if e.contains("(404)")
        );
        GithubAlerts {
            dependabot,
            code_scanning,
            secret_scanning,
            vulnerability_alerts_disabled: vuln_disabled,
        }
    }

    pub fn get_repo_posture(&self, owner: &str, repo: &str, repo_info: &RepoInfo) -> RepoPosture {
        let branch = repo_info.default_branch.as_deref().unwrap_or("main");
        let branch_protected = match self.request_json::<serde_json::Value>(
            reqwest::Method::GET,
            &format!("/repos/{owner}/{repo}/branches/{branch}/protection"),
            None,
        ) {
            Ok(_) => Some(true),
            Err(e) if e.contains("(404)") => Some(false),
            Err(_) => None,
        };

        let codeql_default_setup = self
            .request_json::<serde_json::Value>(
                reqwest::Method::GET,
                &format!("/repos/{owner}/{repo}/code-scanning/default-setup"),
                None,
            )
            .ok()
            .flatten()
            .and_then(|v| {
                v.get("state")
                    .and_then(|s| s.as_str())
                    .map(|s| s == "configured")
            })
            .unwrap_or(false);

        let prs = self.list_open_pulls(owner, repo).unwrap_or_default();
        let open_prs = prs.len();
        let dependabot_prs = prs
            .iter()
            .filter(|p| {
                p.user
                    .as_ref()
                    .map(|u| u.login == "dependabot[bot]")
                    .unwrap_or(false)
            })
            .count();

        let push_protection = repo_info
            .security_and_analysis
            .as_ref()
            .and_then(|s| s.secret_scanning_push_protection.as_ref())
            .and_then(|s| s.status.as_deref())
            .and_then(|s| match s {
                "enabled" => Some(true),
                "disabled" => Some(false),
                _ => None,
            });

        RepoPosture {
            branch_protected,
            codeql_default_setup,
            push_protection,
            open_prs,
            dependabot_prs,
        }
    }

    pub fn list_open_pulls(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<PullRequestSummary>, String> {
        Ok(self
            .request_json::<Vec<PullRequestSummary>>(
                reqwest::Method::GET,
                &format!("/repos/{owner}/{repo}/pulls?state=open&per_page=100"),
                None,
            )?
            .unwrap_or_default())
    }

    pub fn get_pull(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<PullRequestSummary, String> {
        self.request_json(
            reqwest::Method::GET,
            &format!("/repos/{owner}/{repo}/pulls/{number}"),
            None,
        )?
        .ok_or_else(|| "Empty PR response".to_string())
    }

    pub fn get_check_runs(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<CheckRunsResponse, String> {
        Ok(self
            .request_json::<CheckRunsResponse>(
                reqwest::Method::GET,
                &format!("/repos/{owner}/{repo}/commits/{sha}/check-runs?per_page=100"),
                None,
            )?
            .unwrap_or(CheckRunsResponse { check_runs: vec![] }))
    }

    pub fn merge_pull(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        merge_method: &str,
    ) -> Result<(), String> {
        let body = serde_json::json!({ "merge_method": merge_method });
        self.request_json::<serde_json::Value>(
            reqwest::Method::PUT,
            &format!("/repos/{owner}/{repo}/pulls/{number}/merge"),
            Some(&body),
        )?;
        Ok(())
    }

    pub fn find_open_pr_by_branch(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Option<PullRequestSummary> {
        self.request_json::<Vec<PullRequestSummary>>(
            reqwest::Method::GET,
            &format!("/repos/{owner}/{repo}/pulls?state=open&head={owner}:{branch}&per_page=10"),
            None,
        )
        .ok()
        .flatten()
        .and_then(|v| v.into_iter().next())
    }

    pub fn create_pull(
        &self,
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        head: &str,
        base: &str,
    ) -> Result<Option<PullRequestSummary>, String> {
        let payload =
            serde_json::json!({ "title": title, "body": body, "head": head, "base": base });
        self.request_json(
            reqwest::Method::POST,
            &format!("/repos/{owner}/{repo}/pulls"),
            Some(&payload),
        )
    }

    pub fn update_pull(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        title: &str,
        body: &str,
    ) -> Result<Option<PullRequestSummary>, String> {
        let payload = serde_json::json!({ "title": title, "body": body });
        self.request_json(
            reqwest::Method::PATCH,
            &format!("/repos/{owner}/{repo}/pulls/{number}"),
            Some(&payload),
        )
    }

    pub fn sync_labels(&self, owner: &str, repo: &str, labels: &[LabelSpec]) -> usize {
        let existing: HashSet<String> = self
            .request_json::<Vec<serde_json::Value>>(
                reqwest::Method::GET,
                &format!("/repos/{owner}/{repo}/labels?per_page=100"),
                None,
            )
            .ok()
            .flatten()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| {
                v.get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_lowercase())
            })
            .collect();

        let mut added = 0;
        for lbl in labels {
            if existing.contains(&lbl.name.to_lowercase()) {
                continue;
            }
            let payload = serde_json::json!({
                "name": lbl.name,
                "color": lbl.color,
                "description": lbl.description,
            });
            if self
                .request_json::<serde_json::Value>(
                    reqwest::Method::POST,
                    &format!("/repos/{owner}/{repo}/labels"),
                    Some(&payload),
                )
                .is_ok()
            {
                added += 1;
            }
        }
        added
    }

    pub fn find_tracking_issue(
        &self,
        owner: &str,
        repo: &str,
        prefixes: &[&str],
    ) -> Option<IssueSummary> {
        let issues = self
            .request_json::<Vec<IssueSummary>>(
                reqwest::Method::GET,
                &format!("/repos/{owner}/{repo}/issues?state=open&per_page=50"),
                None,
            )
            .ok()
            .flatten()?;
        issues
            .into_iter()
            .find(|i| i.pull_request.is_none() && prefixes.iter().any(|p| i.title.starts_with(p)))
    }

    pub fn create_issue(
        &self,
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
        labels: &[&str],
    ) -> Result<(), String> {
        let payload = serde_json::json!({ "title": title, "body": body, "labels": labels });
        self.request_json::<serde_json::Value>(
            reqwest::Method::POST,
            &format!("/repos/{owner}/{repo}/issues"),
            Some(&payload),
        )?;
        Ok(())
    }

    pub fn update_issue(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        title: &str,
        body: &str,
        state: &str,
    ) -> Result<(), String> {
        let payload = serde_json::json!({ "title": title, "body": body, "state": state });
        self.request_json::<serde_json::Value>(
            reqwest::Method::PATCH,
            &format!("/repos/{owner}/{repo}/issues/{number}"),
            Some(&payload),
        )?;
        Ok(())
    }

    pub fn add_comment(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        body: &str,
    ) -> Result<(), String> {
        let payload = serde_json::json!({ "body": body });
        self.request_json::<serde_json::Value>(
            reqwest::Method::POST,
            &format!("/repos/{owner}/{repo}/issues/{number}/comments"),
            Some(&payload),
        )?;
        Ok(())
    }
}

pub fn notify(slack: Option<&str>, discord: Option<&str>, text: &str, dry_run: bool) {
    if dry_run || (slack.is_none() && discord.is_none()) {
        return;
    }
    let http = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok();
    let Some(client) = http else { return };
    if let Some(url) = slack {
        let _ = client
            .post(url)
            .json(&serde_json::json!({ "text": text }))
            .send();
    }
    if let Some(url) = discord {
        let _ = client
            .post(url)
            .json(&serde_json::json!({ "content": text.replace('*', "**") }))
            .send();
    }
}
