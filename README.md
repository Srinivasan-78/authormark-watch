# authormark-watch

Lightweight, read-only GitHub account monitor (`Node >= 18`, zero npm dependencies). Tracks repository state across `@Srinivasan-78`, runs vulnerability and secret checks, and maintains a single status dashboard.

## What It Checks

- **Dependency Vulnerabilities (`lib/vulns.mjs`)**: Statically parses `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, exact `package.json` pins, `requirements*.txt`, `poetry.lock`, `uv.lock`, `go.mod`, and `Cargo.lock` without executing untrusted repo code, then queries `api.osv.dev/v1/querybatch` for CVEs/advisories.
- **GitHub Security Alerts & Posture (`lib/github.mjs`)**: Collects open Dependabot, code-scanning, and secret-scanning alerts, open PR / Dependabot PR counts, and default-branch protection status.
- **Secrets & Git History (`lib/scanner.mjs`)**: Scans tracked files, `.env*` files, and `git log` history for leaked tokens, API keys, webhooks, JWTs, and PEM private keys.
- **GitHub Actions Security (`lib/scanner.mjs`)**: Audits workflows for `pull_request_target` + head checkout, unpinned action refs, missing/`write-all` `permissions:`, `${{ github.event.* }}` script injection in `run:`, and `curl | sh`.
- **Change Tracking & Repo Inventory (`lib/report.mjs`)**: Tracks commit/CVE/alert deltas between runs (embedded in the dashboard issue or via `--snapshot`), plus visibility, language, push date / staleness, `HEAD` commit, file count, dependency count, CVE count, PRs, and protection status.

## Usage

```sh
node bot.mjs                               # Scan all owned repos, update dashboard issue
node bot.mjs --dry-run                     # Scan and print report without updating issues/webhooks
node bot.mjs --snapshot .watch-snapshot.json
node bot.mjs --json                        # Print structured JSON report
node bot.mjs --repo my-repo                # Target one repository
node bot.mjs --no-osv                      # Skip live OSV CVE lookup
```

Environment variables:
- `BOT_TOKEN` / `WATCH_TOKEN` / `GH_TOKEN`: GitHub PAT to list private+public repos, clone, and read security alerts / branch protection (falls back to `gh auth token`, or local sibling repos when run offline).
- `ISSUE_TOKEN`: Token used to update `watch: Security & Repo Monitor Dashboard` in `authormark-watch` (`REPORT=0` skips updating the issue).
- `SLACK_WEBHOOK` / `DISCORD_WEBHOOK`: Optional alerts when findings exist.

## Configuration

- `bot.config.json`: Configure `owner`, `repos` (`include`, `exclude`, `skip`, `includeForks`, `includeArchived`), `checks`, `allowlist` (`ignoreSecrets`, `ignoreVulns`), and `notify`.
- Per-repo `.masterbot.json`: Set `{ "enabled": false }`, toggle `checks`, or add `ignoreSecrets` / `ignoreVulns` allowlist entries.

## Development

```sh
npm test
```

Runs daily via `.github/workflows/watch.yml` and tests on Node 18/20/24 via `.github/workflows/ci.yml`.
