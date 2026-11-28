# authormark-watch

[![CI](https://github.com/Srinivasan-78/authormark-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/Srinivasan-78/authormark-watch/actions/workflows/ci.yml)

Fast Rust CLI (`authormark-watch`) for GitHub account monitoring, DevSecOps auditing, and automated PR transformation. Tracks repository state across `@Srinivasan-78`, runs vulnerability and secret checks, audits repos against a 15-category engineering scorecard, and opens/updates Pull Requests with missing CI, CodeQL, Dependabot, secret-scanning, and governance baselines.

## What It Checks & Automates

- **Dependency Vulnerabilities (`src/vulns.rs`)**: Statically parses `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `package.json`, `requirements*.txt`, `poetry.lock`, `uv.lock`, `go.mod`, and `Cargo.lock`, then queries `api.osv.dev/v1/querybatch` for CVEs/advisories.
- **GitHub Security Alerts & Posture (`src/github.rs`)**: Collects open Dependabot, code-scanning, and secret-scanning alerts, open PR counts, and default-branch protection status.
- **Secrets & Git History (`src/scanner.rs`)**: Scans tracked files, `.env*` files, and `git log` history for leaked tokens, API keys, webhooks, JWTs, and PEM private keys.
- **GitHub Actions Security (`src/scanner.rs`)**: Audits workflows for `pull_request_target` + head checkout, unpinned action refs, missing/`write-all` `permissions:`, `${{ github.event.* }}` script injection in `run:`, and `curl | sh`.
- **15-Category Engineering Auditor (`src/auditor.rs`)**: Evaluates Architecture, Code Quality, CI/CD, CodeQL, SAST, Secret Scanning, Dependency Security, Supply Chain Security, Testing, Test Coverage, Performance, Documentation, Repository Governance, Release Engineering, and Maintainability.
- **Stack-Aware PR Transformer (`src/templates.rs`, `src/transformer.rs`)**: Non-destructively generates missing workflows (with SHA-pinned actions), grouped `dependabot.yml`, `SECURITY.md`, `CODEOWNERS`, issue/PR templates, syncs standard labels, and opens/updates PRs.
- **Optional Gemini AI Insights (`src/ai.rs`)**: When `--ai` and `GEMINI_API_KEY` are set, adds repo-specific architecture and QA recommendations.
- **Webhook Listener (`src/webhook.rs`)**: HMAC-SHA256 verified GitHub webhook server (`authormark-watch webhook`).
- **Central Portfolio Reports (`src/report.rs`)**: Writes `reports/PORTFOLIO_REPORT.md` and per-repo reports alongside dashboard issue tracking.

## Usage

```sh
cargo run --                               # Scan all owned repos, update dashboard issue
cargo run -- --audit --dry-run             # Run 15-category DevSecOps audit (dry-run)
cargo run -- --audit --write-reports       # Audit and write central ./reports/ markdown files
cargo run -- --transform --dry-run         # Preview PR patches without pushing
cargo run -- --transform                   # Open/update PRs & sync labels on target repos
cargo run -- --transform --ai              # Include Gemini API recommendations in PRs
cargo run -- --repo my-repo                # Target one repository
cargo run -- webhook                       # Start GitHub webhook server on :8787
```

Environment variables:
- `BOT_TOKEN` / `WATCH_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN`: GitHub PAT (`repo` + `workflow` scopes for PR automation; falls back to `gh auth token`).
- `ISSUE_TOKEN`: Token used to update `watch: Security & Repo Monitor Dashboard` in `authormark-watch`.
- `GEMINI_API_KEY`: Optional Gemini API key for `--ai` insights.
- `WEBHOOK_SECRET` / `WEBHOOK_PORT`: Required secret and port for `authormark-watch webhook`.
- `SLACK_WEBHOOK` / `DISCORD_WEBHOOK`: Optional alerts when findings exist.

## Configuration

- `bot.config.json`: Configure `owner`, `repos` (`include`, `exclude`, `skip`, `includeForks`, `includeArchived`), `checks`, `allowlist` (`ignoreSecrets`, `ignoreVulns`), and `notify`.
- Per-repo `.masterbot.json`: Set `{ "enabled": false }`, toggle `checks`, or add `ignoreSecrets` / `ignoreVulns` allowlist entries.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Runs twice weekly (`17 6 * * 1,4`) via `.github/workflows/watch.yml` and tests on every push/PR via `.github/workflows/ci.yml`.
