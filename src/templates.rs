use crate::auditor::AuditResult;
use std::collections::BTreeSet;

pub const SHA_CHECKOUT: &str =
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1";
pub const SHA_SETUP_NODE: &str =
    "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1  # v7.1.0";
pub const SHA_SETUP_PYTHON: &str =
    "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0  # v7.1.0";
pub const SHA_SETUP_GO: &str =
    "actions/setup-go@d8cbb8045d7f43706b9177cceb36c1f91a6644d5  # v7.1.0";
pub const SHA_DEP_REVIEW: &str =
    "actions/dependency-review-action@bbc44d14a204704ccc493733616cd1e93a0321ec  # v5.0.1";
pub const SHA_CODEQL_INIT: &str =
    "github/codeql-action/init@38112626f97ac1fd7acf3df7ebca51f4677c1b38  # codeql-bundle-v2.27.6";
pub const SHA_CODEQL_ANALYZE: &str = "github/codeql-action/analyze@38112626f97ac1fd7acf3df7ebca51f4677c1b38  # codeql-bundle-v2.27.6";
pub const SHA_GITLEAKS: &str =
    "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e  # v3.0.0";
pub const SHA_RELEASE_PLEASE: &str =
    "googleapis/release-please-action@45996ed1f6d02564a971a2fa1b5860e934307cf7  # v5.0.0";

#[derive(Debug, Clone)]
pub struct RepoPatch {
    pub path: String,
    pub content: String,
    pub reason: String,
}

pub fn render_ci_workflow(audit: &AuditResult, default_branch: &str) -> String {
    let stack = &audit.stack;
    let mut lines = vec![
        "name: CI".to_string(),
        String::new(),
        "on:".into(),
        "  pull_request:".into(),
        "  push:".into(),
        format!("    branches: [{default_branch}]"),
        "  workflow_dispatch:".into(),
        String::new(),
        "concurrency:".into(),
        "  group: ci-${{ github.ref }}".into(),
        "  cancel-in-progress: true".into(),
        String::new(),
        "permissions:".into(),
        "  contents: read".into(),
        String::new(),
        "jobs:".into(),
    ];

    if stack.languages.iter().any(|l| l == "rust") {
        lines.extend([
            "  rust:".into(),
            "    runs-on: ubuntu-latest".into(),
            "    timeout-minutes: 20".into(),
            "    steps:".into(),
            format!("      - uses: {SHA_CHECKOUT}"),
            "      - name: Check formatting, clippy, and tests".into(),
            "        run: cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test".into(),
        ]);
    } else if stack
        .languages
        .iter()
        .any(|l| l == "javascript" || l == "typescript")
    {
        let pm = stack
            .package_manager
            .as_deref()
            .filter(|m| matches!(*m, "npm" | "pnpm" | "yarn"))
            .unwrap_or("npm");
        let install_cmd = match pm {
            "pnpm" => "pnpm install --frozen-lockfile",
            "yarn" => "yarn install --frozen-lockfile",
            _ => "if [ -f package-lock.json ]; then npm ci; elif [ -f package.json ]; then npm install; fi",
        };
        lines.extend([
            "  node:".into(),
            format!(
                "    runs-on: {}",
                if stack.targets_windows_or_mac {
                    "${{ matrix.os }}"
                } else {
                    "ubuntu-latest"
                }
            ),
            "    timeout-minutes: 15".into(),
        ]);
        if stack.targets_windows_or_mac {
            lines.extend([
                "    defaults:".into(),
                "      run:".into(),
                "        shell: bash".into(),
                "    strategy:".into(),
                "      fail-fast: false".into(),
                "      matrix:".into(),
                "        os: ['ubuntu-latest', 'windows-latest']".into(),
            ]);
        }
        lines.extend([
            "    steps:".into(),
            format!("      - uses: {SHA_CHECKOUT}"),
            format!("      - uses: {SHA_SETUP_NODE}"),
            "        with:".into(),
            "          node-version: '22'".into(),
        ]);
        if stack.has_node_lockfile {
            lines.push(format!("          cache: '{pm}'"));
        }
        lines.extend([
            "      - name: Install dependencies".into(),
            format!("        run: {install_cmd}"),
            "      - name: Lint (if configured)".into(),
            "        run: if [ -f package.json ]; then npm run lint --if-present; fi".into(),
            "      - name: Typecheck (if configured)".into(),
            "        run: if [ -f package.json ]; then npm run typecheck --if-present; fi".into(),
            "      - name: Build (if configured)".into(),
            "        run: if [ -f package.json ]; then npm run build --if-present; fi".into(),
            "      - name: Run tests".into(),
            "        run: if [ -f package.json ]; then npm test --if-present; fi".into(),
        ]);
    } else if stack.languages.iter().any(|l| l == "python") {
        lines.extend([
            "  python:".into(),
            "    runs-on: ubuntu-latest".into(),
            "    timeout-minutes: 15".into(),
            "    steps:".into(),
            format!("      - uses: {SHA_CHECKOUT}"),
            format!("      - uses: {SHA_SETUP_PYTHON}"),
            "        with:".into(),
            "          python-version: '3.12'".into(),
            "          cache: 'pip'".into(),
            "      - name: Install and test".into(),
            "        run: |".into(),
            "          python -m pip install --upgrade pip ruff pytest".into(),
            "          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi".into(),
            "          ruff check .".into(),
            "          pytest || python -m unittest discover".into(),
        ]);
    } else if stack.languages.iter().any(|l| l == "go") {
        lines.extend([
            "  go:".into(),
            "    runs-on: ubuntu-latest".into(),
            "    timeout-minutes: 15".into(),
            "    steps:".into(),
            format!("      - uses: {SHA_CHECKOUT}"),
            format!("      - uses: {SHA_SETUP_GO}"),
            "        with:".into(),
            "          go-version-file: 'go.mod'".into(),
            "          cache: true".into(),
            "      - name: Vet and test".into(),
            "        run: go vet ./... && go test -race ./...".into(),
        ]);
    } else {
        lines.extend([
            "  verify:".into(),
            "    runs-on: ubuntu-latest".into(),
            "    timeout-minutes: 10".into(),
            "    steps:".into(),
            format!("      - uses: {SHA_CHECKOUT}"),
            "      - name: Verify README".into(),
            "        run: test -f README.md".into(),
        ]);
    }

    lines.join("\n") + "\n"
}

pub fn generate_repo_patches<F>(
    audit: &AuditResult,
    owner: &str,
    default_branch: &str,
    existing_check: F,
) -> Vec<RepoPatch>
where
    F: Fn(&str) -> bool,
{
    let mut patches = Vec::new();
    let mut add_if_missing = |path: &str, content: String, reason: &str| {
        if !existing_check(path) {
            patches.push(RepoPatch {
                path: path.to_string(),
                content,
                reason: reason.to_string(),
            });
        }
    };

    let f = &audit.flags;
    let s = &audit.stack;

    if !s.is_profile_repo {
        if !f.has_ci_workflow {
            add_if_missing(
                ".github/workflows/ci.yml",
                render_ci_workflow(audit, default_branch),
                "Add core CI workflow",
            );
        }
        if !s.codeql_languages.is_empty() && !f.has_codeql {
            let langs = serde_json::to_string(&s.codeql_languages).unwrap_or_else(|_| "[]".into());
            let wf = format!(
                "name: CodeQL\n\non:\n  push:\n    branches: [{default_branch}]\n  pull_request:\n    branches: [{default_branch}]\n  schedule:\n    - cron: '23 4 * * 1'\n  workflow_dispatch:\n\npermissions:\n  contents: read\n  security-events: write\n  actions: read\n\njobs:\n  analyze:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n    strategy:\n      fail-fast: false\n      matrix:\n        language: {langs}\n    steps:\n      - uses: {SHA_CHECKOUT}\n      - uses: {SHA_CODEQL_INIT}\n        with:\n          languages: ${{{{ matrix.language }}}}\n          queries: security-extended\n      - uses: {SHA_CODEQL_ANALYZE}\n        with:\n          category: \"/language:${{{{ matrix.language }}}}\"\n"
            );
            add_if_missing(
                ".github/workflows/codeql.yml",
                wf,
                "Add CodeQL SAST workflow",
            );
        }
        if !f.has_secret_scan_wf {
            let wf = format!(
                "name: Secret Scan\n\non:\n  pull_request:\n  push:\n    branches: [{default_branch}]\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\njobs:\n  gitleaks:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: {SHA_CHECKOUT}\n        with:\n          fetch-depth: 0\n      - uses: {SHA_GITLEAKS}\n        env:\n          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}\n"
            );
            add_if_missing(
                ".github/workflows/secret-scan.yml",
                wf,
                "Add Gitleaks secret-scan workflow",
            );
        }
        if !f.has_dep_review && s.ecosystems.iter().any(|e| e != "github-actions") {
            let wf = format!(
                "name: Dependency Review\n\non:\n  pull_request:\n\npermissions:\n  contents: read\n\njobs:\n  dependency-review:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: {SHA_CHECKOUT}\n      - uses: {SHA_DEP_REVIEW}\n        with:\n          fail-on-severity: high\n"
            );
            add_if_missing(
                ".github/workflows/dependency-review.yml",
                wf,
                "Add Dependency Review PR gate",
            );
        }
        if !f.has_dependabot && !s.ecosystems.is_empty() {
            let mut unique = BTreeSet::new();
            for e in &s.ecosystems {
                unique.insert(e.as_str());
            }
            unique.insert("github-actions");
            let mut lines = vec!["version: 2".to_string(), "updates:".to_string()];
            for eco in unique {
                let grp = format!(
                    "{}-dependencies",
                    eco.replace(|c: char| !c.is_ascii_alphanumeric(), "-")
                );
                lines.extend([
                    format!("  - package-ecosystem: \"{eco}\""),
                    "    directory: \"/\"".into(),
                    "    schedule:".into(),
                    "      interval: \"weekly\"".into(),
                    "    open-pull-requests-limit: 10".into(),
                    "    groups:".into(),
                    format!("      {grp}:"),
                    "        patterns: [\"*\"]".into(),
                    "        update-types: [\"minor\", \"patch\"]".into(),
                ]);
            }
            add_if_missing(
                ".github/dependabot.yml",
                lines.join("\n") + "\n",
                "Add grouped Dependabot config",
            );
        }
        if s.is_publishable && !f.has_release_wf {
            let wf = format!(
                "name: Release Please\n\non:\n  push:\n    branches: [{default_branch}]\n\npermissions:\n  contents: write\n  pull-requests: write\n\njobs:\n  release-please:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: {SHA_RELEASE_PLEASE}\n        with:\n          token: ${{{{ secrets.GITHUB_TOKEN }}}}\n"
            );
            add_if_missing(
                ".github/workflows/release-please.yml",
                wf,
                "Add Release Please automation",
            );
        }
    }

    if !f.has_security_md {
        let sec = format!(
            "# Security Policy\n\n## Supported Versions\n\nSecurity updates are applied to the latest release and default branch of `{owner}/{}`.\n\n## Reporting a Vulnerability\n\nPlease do **not** open a public issue. Use GitHub Private Vulnerability Reporting at `https://github.com/{owner}/{}/security/advisories/new`.\n",
            audit.repo, audit.repo
        );
        add_if_missing("SECURITY.md", sec, "Add security policy");
    }
    if !f.has_codeowners {
        add_if_missing(
            ".github/CODEOWNERS",
            format!("* @{owner}\n"),
            "Add CODEOWNERS",
        );
    }
    if !f.has_pr_template {
        add_if_missing(".github/PULL_REQUEST_TEMPLATE.md", "## Summary\n\n## Related Issues\n\n## Checklist\n\n- [ ] Tests passing locally\n- [ ] No secrets or unrelated files\n".into(), "Add PR template");
    }
    add_if_missing(".editorconfig", "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\ninsert_final_newline = true\ntrim_trailing_whitespace = true\nindent_style = space\nindent_size = 2\n".into(), "Add EditorConfig");
    add_if_missing(
        ".gitattributes",
        "* text=auto eol=lf\n".into(),
        "Add GitAttributes",
    );

    patches
}
