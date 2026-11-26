# authormark-watch

[![CI](https://github.com/Srinivasan-78/authormark-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/Srinivasan-78/authormark-watch/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Srinivasan-78/authormark-watch/actions/workflows/codeql.yml/badge.svg)](https://github.com/Srinivasan-78/authormark-watch/actions/workflows/codeql.yml)

Zero-dependency GitHub account monitor, DevSecOps auditor, and automated PR transformer (`Node >= 18`, zero npm dependencies). Tracks repository state across `@Srinivasan-78`, runs vulnerability and secret checks, audits all repos against a 15-category engineering scorecard, and opens/updates Pull Requests with missing CI, CodeQL, Dependabot, secret-scanning, and governance baselines.

## What It Checks & Automates

- **Dependency Vulnerabilities (`lib/vulns.mjs`)**: Statically parses `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, exact `package.json` pins, `requirements*.txt`, `poetry.lock`, `uv.lock`, `go.mod`, and `Cargo.lock`, then queries `api.osv.dev/v1/querybatch` for CVEs/advisories.
- **GitHub Security Alerts & Posture (`lib/github.mjs`)**: Collects open Dependabot, code-scanning, and secret-scanning alerts, open PR counts, and default-branch protection status.
- **Secrets & Git History (`lib/scanner.mjs`)**: Scans tracked files, `.env*` files, and `git log` history for leaked tokens, API keys, webhooks, JWTs, and PEM private keys.
- **GitHub Actions Security (`lib/scanner.mjs`)**: Audits workflows for `pull_request_target` + head checkout, unpinned action refs, missing/`write-all` `permissions:`, `${{ github.event.* }}` script injection in `run:`, and `curl | sh`.
- **15-Category Engineering Auditor (`lib/auditor.mjs`)**: Evaluates Architecture, Code Quality, CI/CD, CodeQL, SAST, Secret Scanning, Dependency Security, Supply Chain Security, Testing, Test Coverage, Performance, Documentation, Repository Governance, Release Engineering, and Maintainability.
- **Stack-Aware PR Transformer (`lib/templates.mjs`, `lib/transformer.mjs`)**: Non-destructively generates missing workflows (with SHA-pinned actions), grouped `dependabot.yml`, `SECURITY.md`, `CODEOWNERS`, issue/PR templates, syncs standard labels, and opens/updates PRs.
- **Optional Gemini AI Insights (`lib/ai.mjs`)**: When `--ai` and `GEMINI_API_KEY` are set, adds repo-specific architecture and QA recommendations.
- **Webhook Listener (`lib/webhook.mjs`)**: HMAC-SHA256 verified GitHub webhook server (`node bot.mjs webhook`).
- **Central Portfolio Reports (`lib/report.mjs`)**: Writes `reports/PORTFOLIO_REPORT.md` and per-repo reports alongside dashboard issue tracking.

## Usage

```sh
node bot.mjs                               # Scan all owned repos, update dashboard issue
node bot.mjs --audit --dry-run             # Run 15-category DevSecOps audit (dry-run)
node bot.mjs --audit --write-reports       # Audit and write central ./reports/ markdown files
node bot.mjs --transform --dry-run         # Preview PR patches without pushing
node bot.mjs --transform                   # Open/update PRs & sync labels on target repos
node bot.mjs --transform --ai              # Include Gemini API recommendations in PRs
node bot.mjs --repo my-repo                # Target one repository
node bot.mjs webhook                       # Start GitHub webhook server on :8787
```

Environment variables:
- `BOT_TOKEN` / `WATCH_TOKEN` / `GH_TOKEN`: GitHub PAT (`repo` + `workflow` scopes for PR automation; falls back to `gh auth token`).
- `ISSUE_TOKEN`: Token used to update `watch: Security & Repo Monitor Dashboard` in `authormark-watch`.
- `GEMINI_API_KEY`: Optional Gemini API key for `--ai` insights.
- `WEBHOOK_SECRET` / `WEBHOOK_PORT`: Secret and port for `node bot.mjs webhook`.
- `SLACK_WEBHOOK` / `DISCORD_WEBHOOK`: Optional alerts when findings exist.

## Configuration

- `bot.config.json`: Configure `owner`, `repos` (`include`, `exclude`, `skip`, `includeForks`, `includeArchived`), `checks`, `allowlist` (`ignoreSecrets`, `ignoreVulns`), and `notify`.
- Per-repo `.masterbot.json`: Set `{ "enabled": false }`, toggle `checks`, or add `ignoreSecrets` / `ignoreVulns` allowlist entries.

## Development

```sh
npm test
```

Runs daily via `.github/workflows/watch.yml` and tests on Node 18/20/24 via `.github/workflows/ci.yml`.
