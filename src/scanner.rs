use crate::config::{AllowlistConfig, ChecksConfig};
use crate::github::RepoInfo;
use chrono::NaiveDate;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use walkdir::WalkDir;

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".next",
    "dist",
    "build",
    "out",
    "coverage",
    ".turbo",
    ".vercel",
    "vendor",
    "__pycache__",
    "venv",
    ".venv",
    "site-packages",
    "third_party",
    "target",
    ".mypy_cache",
    ".cache",
];

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScanFindings {
    pub secrets: Vec<String>,
    pub history_secrets: Vec<String>,
    pub workflow_risks: Vec<String>,
    pub integrity: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RepoMetadata {
    pub name: String,
    pub visibility: String,
    pub language: Option<String>,
    pub default_branch: Option<String>,
    pub pushed_at: Option<String>,
    pub stale: bool,
    pub head_sha: Option<String>,
    pub head_subject: Option<String>,
    pub file_count: usize,
    pub size_kb: usize,
    pub ecosystems: Vec<String>,
}

fn secret_patterns() -> &'static [(&'static str, Regex)] {
    static PATS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            (
                "GitHub Personal Access Token",
                Regex::new(r"(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82})").unwrap(),
            ),
            (
                "Google / Firebase API Key",
                Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            ),
            (
                "Google OAuth Client Secret",
                Regex::new(r"GOCSPX-[A-Za-z0-9_-]{28}").unwrap(),
            ),
            (
                "AWS Access Key ID",
                Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
                    .unwrap(),
            ),
            (
                "Private Key",
                Regex::new(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----").unwrap(),
            ),
            (
                "Slack Token",
                Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,}").unwrap(),
            ),
            (
                "Slack Webhook",
                Regex::new(
                    r"https://hooks\.slack\.com/services/T[0-9A-Z_]+/B[0-9A-Z_]+/[0-9A-Za-z]+",
                )
                .unwrap(),
            ),
            (
                "Discord Webhook",
                Regex::new(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+")
                    .unwrap(),
            ),
            (
                "Stripe Secret Key",
                Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            ),
            (
                "npm Access Token",
                Regex::new(r"npm_[A-Za-z0-9]{36}").unwrap(),
            ),
            (
                "Generic JWT Token",
                Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                    .unwrap(),
            ),
        ]
    })
}

pub fn match_pattern(rel_path: &str, patterns: &[String]) -> bool {
    let norm = rel_path.replace('\\', "/");
    patterns.iter().any(|pat| {
        let p = pat.replace('\\', "/");
        let p = p.trim_end_matches('/');
        if p.is_empty() {
            return false;
        }
        norm == p || norm.starts_with(&format!("{p}/"))
    })
}

pub fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut acc = Vec::new();
    let it = WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() {
                if SKIP_DIRS.contains(&name.as_ref()) {
                    return false;
                }
                if name.starts_with('.') && name != ".github" {
                    return false;
                }
            }
            true
        });
    for entry in it.flatten() {
        if entry.file_type().is_file() {
            acc.push(entry.into_path());
        }
    }
    acc
}

fn repo_target_files(repo_dir: &Path) -> Vec<PathBuf> {
    if repo_dir.join(".git").exists() {
        if let Ok(out) = Command::new("git")
            .args(["ls-files", "-z"])
            .current_dir(repo_dir)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            if out.status.success() {
                let mut files = Vec::new();
                for part in out.stdout.split(|&b| b == 0) {
                    if part.is_empty() {
                        continue;
                    }
                    let rel = String::from_utf8_lossy(part);
                    let p = repo_dir.join(rel.as_ref());
                    if p.exists() {
                        files.push(p);
                    }
                }
                return files;
            }
        }
    }
    walk_files(repo_dir)
}

pub fn audit_workflow(text: &str, file: &str) -> Vec<String> {
    static UNTRUSTED_RE: OnceLock<Regex> = OnceLock::new();
    static SHA40_RE: OnceLock<Regex> = OnceLock::new();
    static CURL_SH_RE: OnceLock<Regex> = OnceLock::new();
    let untrusted_re = UNTRUSTED_RE.get_or_init(|| {
        Regex::new(r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|pull_request\.head\.label|comment\.body|review\.body|head_commit\.message|pages|commits)").unwrap()
    });
    let sha40_re = SHA40_RE.get_or_init(|| Regex::new(r"^[0-9a-f]{40}$").unwrap());
    let curl_sh_re =
        CURL_SH_RE.get_or_init(|| Regex::new(r"\|\s*(?:sudo\s+)?(?:ba)?sh\b").unwrap());

    let mut risks = Vec::new();
    let lines: Vec<&str> = text.lines().collect();

    let has_pr_target = lines.iter().any(|l| {
        let t = l.trim_start();
        t.starts_with("pull_request_target")
            && t["pull_request_target".len()..]
                .trim_start()
                .starts_with(':')
    });
    if has_pr_target
        && text.contains("actions/checkout")
        && text.contains("github.event.pull_request.head")
    {
        risks.push(format!("`{file}`: `pull_request_target` checks out PR head code — runs untrusted code with a write token"));
    }

    let mut unpinned = BTreeSet::new();
    for l in &lines {
        let t = l.trim_start().trim_start_matches('-').trim_start();
        if !t.starts_with("uses:") {
            continue;
        }
        let val = t["uses:".len()..]
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches(|c| c == '\'' || c == '"');
        if let Some(at_idx) = val.find('@') {
            let action = &val[..at_idx];
            let r = &val[at_idx + 1..];
            if action.starts_with("./") || action.starts_with("docker://") || sha40_re.is_match(r) {
                continue;
            }
            unpinned.insert(format!("{action}@{r}"));
        }
    }
    if !unpinned.is_empty() {
        let preview: Vec<String> = unpinned.iter().take(6).cloned().collect();
        risks.push(format!(
            "`{file}`: {} unpinned action ref(s): {}",
            unpinned.len(),
            preview.join(", ")
        ));
    }

    let has_write_all = lines
        .iter()
        .any(|l| l.trim().starts_with("permissions:") && l.contains("write-all"));
    let has_permissions = lines
        .iter()
        .any(|l| l.trim_start().starts_with("permissions:"));
    if has_write_all {
        risks.push(format!(
            "`{file}`: `permissions: write-all` — grant least privilege instead"
        ));
    } else if !has_permissions {
        risks.push(format!(
            "`{file}`: no top-level `permissions:` — job inherits broad default token"
        ));
    }

    let mut run_indent: isize = -1;
    for l in &lines {
        let indent = (l.len() - l.trim_start().len()) as isize;
        let trimmed = l.trim_start();
        let after_dash = trimmed
            .strip_prefix("- ")
            .map(str::trim_start)
            .unwrap_or(trimmed);
        if let Some(rest) = after_dash.strip_prefix("run:") {
            let val = rest.trim();
            if untrusted_re.is_match(val) {
                risks.push(format!("`{file}`: untrusted `${{{{ github.event.* }}}}` in `run:` — pass via `env:` instead"));
                break;
            }
            run_indent = if val.is_empty() || val.starts_with('|') || val.starts_with('>') {
                indent + if trimmed.starts_with("- ") { 2 } else { 0 }
            } else {
                -1
            };
            continue;
        }
        if run_indent >= 0 {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if indent <= run_indent {
                run_indent = -1;
                continue;
            }
            if untrusted_re.is_match(l) {
                risks.push(format!("`{file}`: untrusted `${{{{ github.event.* }}}}` in `run:` — pass via `env:` instead"));
                break;
            }
        }
    }

    if lines.iter().any(|l| {
        (l.contains("curl ") || l.contains("wget "))
            && l.find('|')
                .map(|idx| curl_sh_re.is_match(&l[idx..]))
                .unwrap_or(false)
    }) {
        risks.push(format!(
            "`{file}`: pipes a network download straight into a shell"
        ));
    }

    risks
}

pub fn scan_git_history(repo_dir: &Path, ignore_secrets: &[String]) -> Vec<String> {
    const HIST_RE: &str = r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk_live_[0-9a-zA-Z]{24}";
    let Ok(out) = Command::new("git")
        .args([
            "log",
            "--all",
            "--no-merges",
            "-n",
            "400",
            "--format=%H",
            "-G",
            HIST_RE,
        ])
        .current_dir(repo_dir)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }

    let re = Regex::new(HIST_RE).unwrap();
    let mut hits = Vec::new();
    for sha in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|s| !s.is_empty())
        .take(15)
    {
        let Ok(show) = Command::new("git")
            .args(["show", "--no-color", "--format=", sha])
            .current_dir(repo_dir)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            continue;
        };
        let diff = String::from_utf8_lossy(&show.stdout);
        let mut cur_file = String::new();
        for l in diff.lines() {
            if let Some(f) = l.strip_prefix("+++ b/") {
                cur_file = f.to_string();
                continue;
            }
            if l.starts_with('+')
                && !l.starts_with("+++")
                && re.is_match(l)
                && !cur_file.ends_with(".md")
                && !cur_file.contains(".test.")
                && !cur_file.contains(".spec.")
                && !match_pattern(&cur_file, ignore_secrets)
            {
                hits.push(format!(
                    "Secret-shaped string in `{cur_file}` at commit `{}` (in git history)",
                    &sha[..sha.len().min(10)]
                ));
                break;
            }
        }
        if hits.len() >= 10 {
            break;
        }
    }
    hits
}

fn git_head_info(repo_dir: &Path) -> (Option<String>, Option<String>, Option<String>) {
    if !repo_dir.join(".git").exists() {
        return (None, None, None);
    }
    let Ok(out) = Command::new("git")
        .args(["log", "-1", "--format=%h\t%cs\t%s"])
        .current_dir(repo_dir)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return (None, None, None);
    };
    if !out.status.success() {
        return (None, None, None);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let mut parts = s.trim().splitn(3, '\t');
    let sha = parts.next().filter(|v| !v.is_empty()).map(str::to_string);
    let date = parts.next().filter(|v| !v.is_empty()).map(str::to_string);
    let subj = parts
        .next()
        .filter(|v| !v.is_empty())
        .map(|v| v.chars().take(60).collect());
    (sha, date, subj)
}

pub fn scan_repository(
    repo_dir: &Path,
    repo_meta: &RepoInfo,
    checks: &ChecksConfig,
    allowlist: &AllowlistConfig,
) -> (RepoMetadata, ScanFindings) {
    let mut findings = ScanFindings::default();
    let files = repo_target_files(repo_dir);
    let has = |rel: &str| repo_dir.join(rel).exists();

    let mut ecosystems = Vec::new();
    if has("package.json") {
        ecosystems.push("npm".to_string());
    }
    if has("requirements.txt") || has("pyproject.toml") || has("poetry.lock") || has("uv.lock") {
        ecosystems.push("pip".to_string());
    }
    if has("go.mod") {
        ecosystems.push("go".to_string());
    }
    if has("Cargo.toml") {
        ecosystems.push("cargo".to_string());
    }

    if checks.workflows {
        let wf_dir = repo_dir.join(".github").join("workflows");
        if let Ok(entries) = fs::read_dir(wf_dir) {
            for ent in entries.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                if name.ends_with(".yml") || name.ends_with(".yaml") {
                    if let Ok(txt) = fs::read_to_string(ent.path()) {
                        findings
                            .workflow_risks
                            .extend(audit_workflow(&txt, &format!(".github/workflows/{name}")));
                    }
                }
            }
        }
    }

    if checks.git_history_secrets {
        findings
            .history_secrets
            .extend(scan_git_history(repo_dir, &allowlist.ignore_secrets));
    }

    if checks.integrity {
        if !has(".gitignore") {
            findings.integrity.push("Missing `.gitignore`".to_string());
        }
        if !["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]
            .iter()
            .any(|p| has(p))
        {
            findings.integrity.push("Missing `SECURITY.md`".to_string());
        }
        let db_rel = if has(".github/dependabot.yml") {
            Some(".github/dependabot.yml")
        } else if has(".github/dependabot.yaml") {
            Some(".github/dependabot.yaml")
        } else {
            None
        };
        if let Some(rel) = db_rel {
            if let Ok(db) = fs::read_to_string(repo_dir.join(rel)) {
                if db.contains("package-ecosystem") && !db.contains("groups:") {
                    findings.integrity.push(format!("`{rel}` is ungrouped"));
                }
            }
        }
    }

    let mut total_bytes: u64 = 0;
    for file in &files {
        let rel = file
            .strip_prefix(repo_dir)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let base = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let skip_sec = match_pattern(&rel, &allowlist.ignore_secrets);

        if checks.secrets
            && !skip_sec
            && (base == ".env" || base == ".env.local" || base == ".env.production")
        {
            findings
                .secrets
                .push(format!("Committed env file: `{rel}`"));
        }
        if checks.integrity
            && (base.ends_with(".pyc")
                || rel.contains("__pycache__")
                || base == ".DS_Store"
                || base == "Thumbs.db")
        {
            findings
                .integrity
                .push(format!("Tracked artifact: `{rel}`"));
        }

        let Ok(meta) = fs::metadata(file) else {
            continue;
        };
        total_bytes += meta.len();
        if meta.len() > 2 * 1024 * 1024 {
            continue;
        }
        let Ok(content) = fs::read_to_string(file) else {
            continue;
        };

        if checks.secrets
            && !skip_sec
            && !rel.ends_with(".md")
            && !content.contains("AIzaSyDummy")
            && !content.contains("your-api-key")
        {
            for (name, re) in secret_patterns() {
                if re.is_match(&content) {
                    findings.secrets.push(format!("Possible {name} in `{rel}`"));
                }
            }
        }

        if checks.integrity
            && rel.ends_with(".json")
            && !base.contains("package-lock")
            && !base.contains("tsconfig")
        {
            if let Err(err) = serde_json::from_str::<serde_json::Value>(&content) {
                findings
                    .integrity
                    .push(format!("Invalid JSON in `{rel}`: {err}"));
            }
        }
    }

    let (head_sha, head_date, head_subject) = git_head_info(repo_dir);
    let pushed_at = repo_meta
        .pushed_at
        .as_deref()
        .map(|s| s.chars().take(10).collect::<String>())
        .or(head_date);

    let stale = pushed_at
        .as_deref()
        .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        .map(|d| (chrono::Utc::now().date_naive() - d).num_days() >= 90)
        .unwrap_or(false);

    let visibility = if repo_meta.name.is_empty() {
        "local".to_string()
    } else if repo_meta.private {
        "private".to_string()
    } else {
        "public".to_string()
    };

    let metadata = RepoMetadata {
        name: if repo_meta.name.is_empty() {
            repo_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("repo")
                .to_string()
        } else {
            repo_meta.name.clone()
        },
        visibility,
        language: repo_meta.language.clone(),
        default_branch: repo_meta.default_branch.clone(),
        pushed_at,
        stale,
        head_sha,
        head_subject,
        file_count: files.len(),
        size_kb: (total_bytes / 1024) as usize,
        ecosystems,
    };

    (metadata, findings)
}
