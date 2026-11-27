use crate::github::{LabelSpec, RepoInfo, RepoPosture};
use crate::scanner::{walk_files, ScanFindings};
use serde::Serialize;
use std::fs;
use std::path::Path;

pub const STANDARD_LABELS: &[LabelSpec] = &[
    LabelSpec {
        name: "bug",
        color: "d73a4a",
        description: "Something isn't working",
    },
    LabelSpec {
        name: "enhancement",
        color: "a2eeef",
        description: "New feature or request",
    },
    LabelSpec {
        name: "security",
        color: "b60205",
        description: "Security vulnerability or hardening",
    },
    LabelSpec {
        name: "documentation",
        color: "0075ca",
        description: "Improvements or additions to documentation",
    },
    LabelSpec {
        name: "testing",
        color: "1d76db",
        description: "Test coverage and QA improvements",
    },
    LabelSpec {
        name: "performance",
        color: "fbca04",
        description: "Performance and resource efficiency",
    },
    LabelSpec {
        name: "refactoring",
        color: "d4c5f9",
        description: "Code quality and architecture cleanup",
    },
    LabelSpec {
        name: "dependencies",
        color: "0366d6",
        description: "Dependency updates and supply chain",
    },
    LabelSpec {
        name: "good first issue",
        color: "7057ff",
        description: "Good for newcomers",
    },
    LabelSpec {
        name: "help wanted",
        color: "008672",
        description: "Extra attention is needed",
    },
    LabelSpec {
        name: "breaking change",
        color: "e99695",
        description: "Backward-incompatible change",
    },
    LabelSpec {
        name: "technical debt",
        color: "fef2c0",
        description: "Known technical debt to address",
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct StackInfo {
    pub languages: Vec<String>,
    pub codeql_languages: Vec<String>,
    pub ecosystems: Vec<String>,
    pub package_manager: Option<String>,
    pub has_tests: bool,
    pub test_files_count: usize,
    pub linters: Vec<String>,
    pub has_dockerfile: bool,
    pub is_profile_repo: bool,
    pub is_publishable: bool,
    pub targets_windows_or_mac: bool,
    pub has_node_lockfile: bool,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScorecardItem {
    pub category: &'static str,
    pub status: &'static str,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TodoItem {
    pub id: &'static str,
    pub title: &'static str,
    pub priority: &'static str,
    pub category: &'static str,
    pub auto_fixable: bool,
    pub reason: String,
    pub resolution: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFlags {
    pub has_ci_workflow: bool,
    pub has_codeql: bool,
    pub has_dep_review: bool,
    pub has_secret_scan_wf: bool,
    pub has_release_wf: bool,
    pub has_dependabot: bool,
    pub has_security_md: bool,
    pub has_license: bool,
    pub has_readme: bool,
    pub has_contributing: bool,
    pub has_codeowners: bool,
    pub has_pr_template: bool,
    pub has_issue_templates: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditResult {
    pub repo: String,
    pub stack: StackInfo,
    pub scorecard: Vec<ScorecardItem>,
    pub todos: Vec<TodoItem>,
    pub flags: AuditFlags,
}

pub fn detect_stack(repo_dir: &Path, repo_meta: &RepoInfo) -> StackInfo {
    let has = |rel: &str| repo_dir.join(rel).exists();
    let files: Vec<String> = walk_files(repo_dir)
        .into_iter()
        .filter_map(|f| {
            f.strip_prefix(repo_dir)
                .ok()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
        })
        .collect();

    let pkg: Option<serde_json::Value> = fs::read_to_string(repo_dir.join("package.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let pyproject = fs::read_to_string(repo_dir.join("pyproject.toml")).unwrap_or_default();

    let has_ts = has("tsconfig.json")
        || files
            .iter()
            .any(|f| f.ends_with(".ts") || f.ends_with(".tsx") || f.ends_with(".mts"));
    let has_js = pkg.is_some()
        || files.iter().any(|f| {
            f.ends_with(".js") || f.ends_with(".mjs") || f.ends_with(".cjs") || f.ends_with(".jsx")
        });
    let has_py = has("requirements.txt")
        || has("pyproject.toml")
        || has("setup.py")
        || files.iter().any(|f| f.ends_with(".py"));
    let has_go = has("go.mod") || files.iter().any(|f| f.ends_with(".go"));
    let has_rust = has("Cargo.toml") || files.iter().any(|f| f.ends_with(".rs"));
    let has_docker = has("Dockerfile")
        || files.iter().any(|f| {
            let base = f.rsplit('/').next().unwrap_or(f);
            base == "Dockerfile" || base.starts_with("Dockerfile.")
        });
    let has_html = files
        .iter()
        .any(|f| f.ends_with(".html") || f.ends_with(".htm"));

    let mut languages = Vec::new();
    if has_ts {
        languages.push("typescript".into());
    } else if has_js {
        languages.push("javascript".into());
    }
    if has_py {
        languages.push("python".into());
    }
    if has_go {
        languages.push("go".into());
    }
    if has_rust {
        languages.push("rust".into());
    }
    if has_docker {
        languages.push("docker".into());
    }
    if has_html && languages.is_empty() {
        languages.push("html".into());
    }

    let mut codeql_languages = Vec::new();
    if has_ts || has_js {
        codeql_languages.push("javascript-typescript".into());
    }
    if has_py {
        codeql_languages.push("python".into());
    }
    if has_go {
        codeql_languages.push("go".into());
    }
    if has_rust {
        codeql_languages.push("rust".into());
    }

    let mut ecosystems = Vec::new();
    if pkg.is_some() {
        ecosystems.push("npm".into());
    }
    if has_py
        && (has("requirements.txt")
            || has("pyproject.toml")
            || has("poetry.lock")
            || has("uv.lock"))
    {
        ecosystems.push("pip".into());
    }
    if has_go {
        ecosystems.push("gomod".into());
    }
    if has_rust {
        ecosystems.push("cargo".into());
    }
    if has_docker {
        ecosystems.push("docker".into());
    }
    if files.iter().any(|f| {
        f.starts_with(".github/workflows/") && (f.ends_with(".yml") || f.ends_with(".yaml"))
    }) {
        ecosystems.push("github-actions".into());
    }

    let package_manager = if pkg.is_some() {
        if has("pnpm-lock.yaml") {
            Some("pnpm".into())
        } else if has("yarn.lock") {
            Some("yarn".into())
        } else {
            Some("npm".into())
        }
    } else if has_py {
        if has("uv.lock") {
            Some("uv".into())
        } else if has("poetry.lock") {
            Some("poetry".into())
        } else {
            Some("pip".into())
        }
    } else if has_go {
        Some("go".into())
    } else if has_rust {
        Some("cargo".into())
    } else {
        None
    };

    let test_files_count = files
        .iter()
        .filter(|f| {
            f.starts_with("test/")
                || f.starts_with("tests/")
                || f.contains("/tests/")
                || f.contains(".test.")
                || f.contains("_test.")
        })
        .count();
    let has_test_script = pkg
        .as_ref()
        .and_then(|p| p.pointer("/scripts/test"))
        .and_then(|v| v.as_str())
        .map(|s| !s.to_lowercase().contains("no test specified"))
        .unwrap_or(false);
    let has_tests = test_files_count > 0 || has_test_script || has_rust;

    let mut linters = Vec::new();
    if pkg.as_ref().is_some_and(|p| {
        has("eslint.config.js")
            || has("eslint.config.mjs")
            || has(".eslintrc.json")
            || p.pointer("/devDependencies/eslint").is_some()
    }) {
        linters.push("eslint".into());
    }
    if has_py && (has("ruff.toml") || pyproject.contains("[tool.ruff]")) {
        linters.push("ruff".into());
    }
    if has_rust {
        linters.push("clippy".into());
    }

    let is_profile_repo = repo_meta.owner.as_ref().is_some_and(|o| {
        !repo_meta.name.is_empty() && o.login.eq_ignore_ascii_case(&repo_meta.name)
    });

    let is_publishable = pkg.as_ref().is_some_and(|p| {
        p.get("private").and_then(|v| v.as_bool()) != Some(true)
            && (p.get("bin").is_some() || p.get("main").is_some() || p.get("exports").is_some())
    }) || (pyproject.contains("[project]") && pyproject.contains("name"))
        || has_docker;

    let targets_windows_or_mac = files
        .iter()
        .any(|f| f.ends_with(".ps1") || f.ends_with(".bat") || f.ends_with(".cmd"));
    let has_node_lockfile = has("package-lock.json") || has("pnpm-lock.yaml") || has("yarn.lock");

    StackInfo {
        languages,
        codeql_languages,
        ecosystems,
        package_manager,
        has_tests,
        test_files_count,
        linters,
        has_dockerfile: has_docker,
        is_profile_repo,
        is_publishable,
        targets_windows_or_mac,
        has_node_lockfile,
        file_count: files.len(),
    }
}

pub fn audit_repository(
    repo_dir: &Path,
    repo_meta: &RepoInfo,
    cve_count: usize,
    findings: &ScanFindings,
    posture: Option<&RepoPosture>,
) -> AuditResult {
    let stack = detect_stack(repo_dir, repo_meta);
    let has = |rel: &str| repo_dir.join(rel).exists();

    let mut wf_contents = Vec::new();
    let mut wf_names = Vec::new();
    if let Ok(entries) = fs::read_dir(repo_dir.join(".github").join("workflows")) {
        for ent in entries.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if name.ends_with(".yml") || name.ends_with(".yaml") {
                wf_names.push(name);
                if let Ok(c) = fs::read_to_string(ent.path()) {
                    wf_contents.push(c);
                }
            }
        }
    }
    let all_wf = wf_contents.join("\n");

    let has_ci_workflow = wf_names.iter().any(|n| {
        let l = n.to_lowercase();
        l.contains("ci") || l.contains("test") || l.contains("build") || l.contains("lint")
    }) || all_wf.contains("pull_request");
    let has_codeql = posture.is_some_and(|p| p.codeql_default_setup)
        || wf_names.iter().any(|n| n.to_lowercase().contains("codeql"))
        || all_wf.contains("github/codeql-action");
    let has_dep_review = wf_names
        .iter()
        .any(|n| n.to_lowercase().contains("dependency-review"))
        || all_wf.contains("actions/dependency-review-action");
    let has_secret_scan_wf = wf_names.iter().any(|n| {
        let l = n.to_lowercase();
        l.contains("gitleaks") || l.contains("secret")
    }) || all_wf.contains("gitleaks/gitleaks-action");
    let has_release_wf = wf_names
        .iter()
        .any(|n| n.to_lowercase().contains("release"))
        || all_wf.contains("release-please");
    let has_coverage_in_ci =
        all_wf.contains("coverage") || all_wf.contains("tarpaulin") || all_wf.contains("llvm-cov");

    let has_dependabot = has(".github/dependabot.yml") || has(".github/dependabot.yaml");
    let has_security_md = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]
        .iter()
        .any(|p| has(p));
    let has_license = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]
        .iter()
        .any(|p| has(p));
    let has_readme = ["README.md", "readme.md"].iter().any(|p| has(p));
    let has_contributing = ["CONTRIBUTING.md", ".github/CONTRIBUTING.md"]
        .iter()
        .any(|p| has(p));
    let has_codeowners = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]
        .iter()
        .any(|p| has(p));
    let has_pr_template = [
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/pull_request_template.md",
    ]
    .iter()
    .any(|p| has(p));
    let has_issue_templates = fs::read_dir(repo_dir.join(".github").join("ISSUE_TEMPLATE"))
        .map(|it| it.count() > 0)
        .unwrap_or(false);

    let secret_count = findings.secrets.len() + findings.history_secrets.len();
    let wf_risk_count = findings.workflow_risks.len();
    let integrity_count = findings.integrity.len();

    let mut todos = Vec::new();
    if secret_count > 0 {
        todos.push(TodoItem {
            id: "SEC-01",
            title: "Remediate detected secrets or git history leaks",
            priority: "Critical",
            category: "Secret Scanning",
            auto_fixable: false,
            reason: format!("{secret_count} secret finding(s) detected."),
            resolution: "Rotate exposed credentials and clean git history.".into(),
        });
    }
    if cve_count > 0 {
        todos.push(TodoItem {
            id: "SEC-02",
            title: "Upgrade dependencies with known CVEs",
            priority: "High",
            category: "Dependency Security",
            auto_fixable: false,
            reason: format!("{cve_count} OSV CVE(s) detected."),
            resolution: "Update lockfiles and merge Dependabot PRs.".into(),
        });
    }
    if !has_ci_workflow && !stack.is_profile_repo {
        todos.push(TodoItem {
            id: "CI-01",
            title: "Add core CI workflow",
            priority: "High",
            category: "CI/CD",
            auto_fixable: true,
            reason: "No CI workflow found.".into(),
            resolution: "Add .github/workflows/ci.yml.".into(),
        });
    }
    if !stack.codeql_languages.is_empty() && !has_codeql {
        todos.push(TodoItem {
            id: "SEC-03",
            title: "Enable GitHub CodeQL SAST workflow",
            priority: "High",
            category: "CodeQL",
            auto_fixable: true,
            reason: format!(
                "CodeQL supports {:?} but is not configured.",
                stack.codeql_languages
            ),
            resolution: "Add .github/workflows/codeql.yml.".into(),
        });
    }
    if !has_license && !stack.is_profile_repo {
        todos.push(TodoItem {
            id: "LEG-01",
            title: "Choose and add a repository LICENSE",
            priority: "High",
            category: "Documentation",
            auto_fixable: false,
            reason: "No LICENSE file found (auto-generation intentionally skipped).".into(),
            resolution: "Select a license and add LICENSE.".into(),
        });
    }
    if posture.is_some_and(|p| p.branch_protected == Some(false)) {
        todos.push(TodoItem {
            id: "GOV-03",
            title: "Enable branch protection on default branch",
            priority: "High",
            category: "Repository Governance",
            auto_fixable: false,
            reason: "Default branch protection is disabled.".into(),
            resolution: "Enable PR & status check requirements in GitHub Settings -> Branches."
                .into(),
        });
    }

    let scorecard = vec![
        ScorecardItem {
            category: "Architecture",
            status: if has_readme && stack.file_count > 0 { "Pass" } else { "Needs Work" },
            evidence: format!("{} files across [{}]", stack.file_count, stack.languages.join(", ")),
        },
        ScorecardItem {
            category: "Code Quality",
            status: if stack.is_profile_repo || !stack.linters.is_empty() || all_wf.contains("clippy") || all_wf.contains("lint") { "Pass" } else { "Needs Work" },
            evidence: if stack.linters.is_empty() { "No linter detected".into() } else { format!("Configured: {}", stack.linters.join(", ")) },
        },
        ScorecardItem {
            category: "CI/CD",
            status: if stack.is_profile_repo || has_ci_workflow { "Pass" } else { "Needs Work" },
            evidence: format!("{} workflow(s)", wf_names.len()),
        },
        ScorecardItem {
            category: "CodeQL",
            status: if stack.codeql_languages.is_empty() || has_codeql { "Pass" } else { "Needs Work" },
            evidence: if has_codeql { "CodeQL active".into() } else { "Not configured".into() },
        },
        ScorecardItem {
            category: "SAST",
            status: if stack.codeql_languages.is_empty() || has_codeql { "Pass" } else { "Needs Work" },
            evidence: if has_codeql { "Covered by CodeQL".into() } else { "Missing SAST".into() },
        },
        ScorecardItem {
            category: "Secret Scanning",
            status: if secret_count > 0 { "Needs Work" } else if has_secret_scan_wf || posture.is_some_and(|p| p.push_protection == Some(true)) { "Pass" } else { "Needs Work" },
            evidence: if secret_count > 0 { format!("{secret_count} finding(s)") } else if has_secret_scan_wf { "Gitleaks workflow active".into() } else { "Missing CI secret scan".into() },
        },
        ScorecardItem {
            category: "Dependency Security",
            status: if cve_count > 0 { "Needs Work" } else if stack.ecosystems.is_empty() || has_dependabot { "Pass" } else { "Needs Work" },
            evidence: if cve_count > 0 { format!("{cve_count} CVE(s)") } else if has_dependabot { "Dependabot configured".into() } else { "Missing Dependabot".into() },
        },
        ScorecardItem {
            category: "Supply Chain Security",
            status: if wf_risk_count == 0 && (!wf_names.is_empty() || stack.is_profile_repo) { "Pass" } else { "Needs Work" },
            evidence: format!("{wf_risk_count} workflow risk(s)"),
        },
        ScorecardItem {
            category: "Testing",
            status: if stack.is_profile_repo || stack.has_tests { "Pass" } else { "Needs Work" },
            evidence: if stack.has_tests { format!("{} test file(s)", stack.test_files_count) } else { "No tests detected".into() },
        },
        ScorecardItem {
            category: "Test Coverage",
            status: if stack.is_profile_repo || !stack.has_tests || has_coverage_in_ci { "Pass" } else { "Needs Work" },
            evidence: if has_coverage_in_ci { "Coverage enabled in CI".into() } else { "Not configured in CI".into() },
        },
        ScorecardItem {
            category: "Performance",
            status: if stack.is_profile_repo || !stack.is_publishable || all_wf.contains("timeout-minutes") { "Pass" } else { "Needs Work" },
            evidence: if all_wf.contains("timeout-minutes") { "CI timeouts enforced".into() } else { "No CI timeouts".into() },
        },
        ScorecardItem {
            category: "Documentation",
            status: if has_readme && has_security_md && (has_license || stack.is_profile_repo) { "Pass" } else { "Needs Work" },
            evidence: format!("README:{has_readme}, SECURITY:{has_security_md}, LICENSE:{has_license}"),
        },
        ScorecardItem {
            category: "Repository Governance",
            status: if has_codeowners && has_pr_template && has_issue_templates && posture.is_none_or(|p| p.branch_protected != Some(false)) { "Pass" } else { "Needs Work" },
            evidence: format!("CODEOWNERS:{has_codeowners}, PR-tpl:{has_pr_template}, Issues-tpl:{has_issue_templates}"),
        },
        ScorecardItem {
            category: "Release Engineering",
            status: if !stack.is_publishable || has_release_wf { "Pass" } else { "Needs Work" },
            evidence: if has_release_wf { "Release automation present".into() } else { "Not configured".into() },
        },
        ScorecardItem {
            category: "Maintainability",
            status: if integrity_count == 0 && has(".gitignore") && has(".editorconfig") { "Pass" } else { "Needs Work" },
            evidence: format!("Integrity:{integrity_count}, .gitignore:{}, .editorconfig:{}", has(".gitignore"), has(".editorconfig")),
        },
    ];

    AuditResult {
        repo: if repo_meta.name.is_empty() {
            repo_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("repo")
                .to_string()
        } else {
            repo_meta.name.clone()
        },
        stack,
        scorecard,
        todos,
        flags: AuditFlags {
            has_ci_workflow,
            has_codeql,
            has_dep_review,
            has_secret_scan_wf,
            has_release_wf,
            has_dependabot,
            has_security_md,
            has_license,
            has_readme,
            has_contributing,
            has_codeowners,
            has_pr_template,
            has_issue_templates,
        },
    }
}
