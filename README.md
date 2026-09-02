<!--
  @authormark v1 -- do not remove (authorship watermark)
  Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
  Author: https://github.com/Srinivasan-78
  SPDX-License-Identifier: MIT
  Fingerprint: AMK1.AMIvOkGddvUkwHUm8CXnDd
-->
# authormark-watch (Master Bot & Repository Supervisor)

A centralized **Master Bot** that supervises, maintains, and secures **every repository** in your GitHub account (`@Srinivasan-78`), including active repositories, new repositories, and legacy projects.

Operates autonomously on a daily schedule via GitHub Actions, or manually via CLI.

---

## Capabilities

### 1. 🔏 AuthorMark Code Watermarking & Signing
- Scans every repository for intact `@authormark v1` headers, keyed HMAC fingerprints, invisible zero-width copy-paste marks, image watermarks, and sealed `AUTHORSHIP.json` manifests.
- In **Fix Mode** (`--fix` / `FIX=1`), checks out an `authormark` branch, stamps unmarked or drifted files, commits as a bot, pushes, and opens/updates a clean Pull Request.

### 2. 🧹 Multi-Language Code Linting & Hygiene Scan
- **Secret & Token Scanning**: Detects committed GitHub PATs, Firebase/Google API keys, AWS credentials, private keys, Slack/Discord webhooks, JWT tokens, and committed `.env` files.
- **Syntax & Manifest Validation**: Validates `.json` and manifest structure across projects.
- **Hygiene & Cache Protection**: Detects and flags tracked `.pyc`, `__pycache__`, OS metadata (`.DS_Store`, `Thumbs.db`), and uncommitted build artifacts.
- **Repository Health Standards**: Verifies presence and contents of `LICENSE`, `README.md`, `.gitignore`, `AGENTS.md` / `CLAUDE.md`, and `SECURITY.md`.

### 3. 🏷️ Automated PR Tagging & Labeling
- Analyzes all open pull requests across all monitored repositories.
- Automatically calculates and applies:
  - **Size Tags**: `size/XS` (<10 lines), `size/S` (10-49), `size/M` (50-249), `size/L` (250-999), `size/XL` (1000+).
  - **Type Tags**: `type/feat`, `type/fix`, `type/docs`, `type/chore`, `type/refactor`, `type/test`, `type/ci`, `type/authormark`, `type/dependencies`.
  - **Language Tags**: `lang/typescript`, `lang/javascript`, `lang/python`, `lang/rust`, `lang/go`, `lang/web`, `lang/shell`, `lang/c-cpp`.
  - **Workflow Tags**: `needs-review`, `automated-pr`, `bot`, `work-in-progress`.
- Automatically provisions missing labels on repositories with standard color palettes and descriptions.

### 4. 📋 Automated Issue Tagging & Triage
- Analyzes all open issues across repositories for keywords, scope, and urgency.
- Automatically assigns:
  - **Category Tags**: `bug`, `enhancement`, `documentation`, `question`, `security`, `performance`.
  - **Priority & Triage**: `triage`, `needs-info`, `good first issue`, `priority/high`, `priority/medium`, `priority/low`.
- Ensures issue labels exist with proper colors.

### 5. 📊 Consolidated Master Dashboard
- Posts and maintains a single, non-spamming tracking issue on `authormark-watch` (`authormark: Master Bot Status Dashboard`), closing automatically once all repositories are clean.

---

## Configuration (`bot.config.json`)

Configure repository rules, features, and labeling in `bot.config.json`:

```json
{
  "owner": "Srinivasan-78",
  "repos": {
    "include": [],
    "exclude": [
      "wix-installer-template",
      "ubisoft-game-notes",
      "github-actions-snippets",
      "study-brainrot-generator"
    ],
    "skip": ["authormark-watch"],
    "includeForks": false,
    "includeArchived": false
  },
  "features": {
    "authormark": { "enabled": true, "autoFix": false, "branch": "authormark" },
    "lint": { "enabled": true, "scanSecrets": true, "scanHygiene": true, "scanRepoHealth": true },
    "prTagger": { "enabled": true, "sizeLabels": true, "typeLabels": true, "langLabels": true, "autoCreateLabels": true },
    "issueTagger": { "enabled": true, "categoryLabels": true, "priorityLabels": true, "triageLabel": true, "autoCreateLabels": true }
  }
}
```

---

## One-Time Setup

The workflow requires a token with permissions to supervise your repositories.

1. Create a **Fine-Grained Personal Access Token** at <https://github.com/settings/personal-access-tokens/new>:
   - Resource owner: `Srinivasan-78`
   - Repository access: **All repositories**
   - Permissions:
     - **Contents**: Read and Write (for creating AuthorMark fix branches & PRs)
     - **Pull requests**: Read and Write (for creating PRs and applying PR labels)
     - **Issues**: Read and Write (for triaging issues and updating the dashboard)
     - **Workflows**: Read and Write (for stamping workflow files under `.github/workflows/`)
     - **Metadata**: Read-only

2. Add it as a secret named `BOT_TOKEN` (or `WATCH_TOKEN`):
   ```sh
   gh secret set BOT_TOKEN --repo Srinivasan-78/authormark-watch
   ```

3. (Optional for CI Fix Mode) Add your HMAC key as `AUTHORMARK_KEY`:
   ```sh
   gh secret set AUTHORMARK_KEY --repo Srinivasan-78/authormark-watch < ~/.authormark.key
   ```

4. Trigger a workflow run:
   ```sh
   gh workflow run watch.yml --repo Srinivasan-78/authormark-watch
   gh workflow run watch.yml --repo Srinivasan-78/authormark-watch -f fix=true
   ```

---

## Local CLI Usage

Run the master bot locally using Node.js (Node ≥ 18, zero npm dependencies):

```sh
# Supervise all repositories (dry-run mode)
node bot.mjs --dry-run

# Run full scan across all repos and update status dashboard
node bot.mjs --all

# Run AuthorMark fix pass (opens PRs on unmarked/drifted repos)
node bot.mjs --fix

# Target a specific repository (e.g. my-repo)
node bot.mjs --repo my-repo

# Run individual subsystems
node bot.mjs --lint
node bot.mjs --tag-prs
node bot.mjs --tag-issues

# Or use the bash wrapper
./watch.sh
FIX=1 ./watch.sh
```

---

## AuthorMark CLI (`authormark.mjs`)

The watermarking engine the bot drives. Zero dependencies, Node ≥ 18.

```sh
# One command for a fresh repo: config + key + CI + agent rules + LICENSE
# + stamp every source file + mark images + seal manifest + pre-commit hook
node authormark.mjs setup --author "Your Name" --email you@example.com --github https://github.com/you

# Insert or refresh the header + keyed fingerprint (‑‑zw adds an invisible mark)
node authormark.mjs stamp src lib --zw

# CI / hook gate: exit 1 on any unmarked file or stale fingerprint
node authormark.mjs check .
node authormark.mjs check --staged           # pre-commit
node authormark.mjs check --json .            # machine-readable report

# Deliberate removal (licence change, upstreaming) — dry unless --force
node authormark.mjs unstamp path/to/file.js --force

# Hunt for stolen code: your fingerprints/signatures in repos you don't own
GITHUB_TOKEN=ghp_… node authormark.mjs crawl --json

# Tamper-evident manifest of per-file hashes + keyed proof
node authormark.mjs seal
node authormark.mjs verify

# Images: PNG text chunks + optional visible mark + hidden LSB payload;
# JPEG EXIF/XMP/COM metadata
node authormark.mjs image logo.png --visible "© 2026 You" --inplace
node authormark.mjs scan logo.png            # show every mark found
```

Layers, weakest to strongest: visible header comment → keyed HMAC `Fingerprint:`
(survives whitespace/CRLF drift) → invisible zero-width mark (survives copy-paste)
→ image metadata + LSB steganography → sealed `AUTHORSHIP.json` manifest.

`image` also writes metadata-level marks for **GIF** (comment extension), **SVG**
(`<metadata>` Dublin Core), **WebP** (`XMP ` chunk), **MP3** (ID3v2.4), **MP4/MOV**
(`moov/udta` ©-atoms) and **PDF** (incremental-update `/Info` + XMP). These are
metadata only — a re-encode can strip them. `authormark attack <image>` runs a
battery of ImageMagick transforms and reports which marks survive which
(re-encode, resize, crop, rotate, grayscale, `-strip`).

Recognises ~90 source extensions across C-family, hash, `--`, `(* *)`, `//`, `;`
and `%` comment syntaxes, plus named files (`Dockerfile`, `Rakefile`, …).
`.v` and `.m` are excluded as ambiguous — add them via config `ext` if needed.

### `.authormark.json` keys

| key | meaning |
|-----|---------|
| `algo` | `hmac` (default) or `ed25519` — see below |
| `publicKey` | base64 SPKI of the ed25519 public key (written by `init --ed25519`) |
| `ignore` | array of paths / dir-prefixes / globs (`*`, `**`, `?`) never stamped |
| `include` | if non-empty, an allowlist of globs — only matching files are stamped |
| `reuse` | `true` adds a REUSE-spec `SPDX-FileCopyrightText:` line to each header |
| `maxBytes` | files larger than this (default 2 MiB) are skipped by stamp/check |

A `.authormarkignore` file (gitignore-style, one pattern per line) is merged into `ignore`.

### HMAC vs ed25519

- **`hmac`** (default): the `Fingerprint:` line is a keyed HMAC. Only the holder of
  `~/.authormark.key` can verify authenticity; CI without the key does a
  presence-only check.
- **`ed25519`** (`authormark init --ed25519`): the header also carries a
  `Signature:` line. The **public** key lives in `.authormark.json`, so CI and any
  third party can cryptographically verify authorship with **no secret** —
  `authormark check .` verifies signatures in the workflow. `seal`, the
  `AUTHORSHIP.log` chain, and `verify` all use ed25519 proofs in this mode.
  `rotate` mints a new keypair and keeps the retired public key so old
  signatures still verify.

---

## Architecture & Security

- **Independent Checker**: `bot.mjs` runs from *this* repository and never trusts or executes foreign code inside target repositories.
- **Zero Dependencies**: Pure Node.js standard library (`fs`, `path`, `crypto`, `child_process`, native `fetch`).
- **Safe Push Mode**: Never pushes directly to default branches (`main`/`master`); all fixes are submitted via isolated branches and pull requests.

---

## Development

```sh
npm test                      # node:test unit suite (authormark + bot classifiers)
node scripts/sync-vendor.mjs  # copy authormark.mjs -> .authormark/authormark.mjs
node scripts/sync-vendor.mjs --check   # CI guard: fail if the two have drifted
```

`.github/workflows/ci.yml` runs the suite on Node 18/20/24, checks vendored-engine
parity, and runs `authormark check --presence` on every push and PR.
`.github/workflows/watch.yml` is the scheduled account-wide supervisor.
