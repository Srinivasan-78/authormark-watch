#!/usr/bin/env bash
# @authormark v1 -- do not remove (authorship watermark)⁠​‌‌​‌​‌‌​‌​‌​​‌‌​​‌‌​​‌​​​‌​‌‌​‌​‌‌​‌​​​​‌‌‌‌​‌​​‌‌​‌‌​‌​‌​‌‌‌‌‌​‌​‌​‌‌​​‌‌​​​‌​​​‌‌​​​​​‌‌‌​‌‌​​‌​‌​‌‌‌​‌​‌​‌‌​​‌​​‌‌‌​​‌‌‌​​​‌​‌‌‌​‌‌‌​‌‌‌​​​​​​‌‌​​‌‌​​‌‌​‌‌​​‌‌​​‌​‌​‌‌‌‌​​​⁠
# Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
# Author: https://github.com/Srinivasan-78
# SPDX-License-Identifier: MIT
# Fingerprint: AMK1.kS2-hzm_Vb0vWVNqwp36ex
# Scan every repo this account owns and report any that is unmarked, has drifted,
# or has had watermarks stripped. Runs on a schedule from authormark-watch.
#
# Deliberately uses ITS OWN copy of authormark.mjs, never the one vendored inside
# the repo being checked -- otherwise stripping the marks and neutering that repo's
# vendored checker would pass silently.
set -uo pipefail

OWNER="${OWNER:-Srinivasan-78}"
# Repos that may hold work that isn't mine to claim, plus this repo itself.
SKIP=" WixTemplate Ubisoft_spool Simple-Actions Brainrot_Study authormark-watch "

# FIX=1 does not just report -- it applies the marks and opens a PR per repo.
FIX="${FIX:-0}"
BRANCH="${BRANCH:-authormark}"
# The PR is authored by whichever account owns GH_TOKEN; these name the commits
# so they read as the bot's work rather than a human's.
BOT_NAME="${BOT_NAME:-github-actions[bot]}"
BOT_EMAIL="${BOT_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
AUTHOR="${AUTHOR:-Srinivasan Vijayaraghavan}"
EMAIL="${EMAIL:-srinivasan.shyam2000@gmail.com}"
GHURL="${GHURL:-https://github.com/$OWNER}"
KEY_FILE="${KEY_FILE:-$HOME/.authormark.key}"

AM="$(dirname "$(readlink -f "$0")")/authormark.mjs"
[ -f "$AM" ] || { echo "authormark.mjs not found at $AM" >&2; exit 1; }

# In CI the built-in GITHUB_TOKEN cannot see other repos, so a PAT is required.
# Fail with the actual reason rather than a confusing clone error.
if [ -n "${CI:-}" ] && [ -z "${GH_TOKEN:-}" ]; then
  echo "::error::WATCH_TOKEN secret is not set -- this job cannot read your other repos yet. See README steps 1-2."
  exit 1
fi

# Fingerprints are HMACs: without the signing key nothing can be stamped, so fail
# up front rather than after cloning half the account.
if [ "$FIX" = "1" ]; then
  if [ ! -f "$KEY_FILE" ] && [ -n "${AUTHORMARK_KEY:-}" ]; then
    ( umask 077; printf '%s\n' "$AUTHORMARK_KEY" > "$KEY_FILE" )
  fi
  if [ ! -f "$KEY_FILE" ]; then
    echo "FIX=1 needs the signing key at $KEY_FILE (or an AUTHORMARK_KEY secret) -- fingerprints cannot be computed without it." >&2
    exit 1
  fi
fi

# Apply the marks on a branch and open a PR. Runs inside an already-cloned repo.
# Echoes the PR url on success; the caller decides how to report it.
fix_repo() {
  local repo="$1" url existing
  # No commit to branch from means an empty repo, or a clone that never checked
  # anything out. Branching there would commit a tree that DELETES every file.
  git rev-parse --verify -q HEAD >/dev/null || return 1
  git fetch -q --unshallow origin 2>/dev/null || git fetch -q origin 2>/dev/null || true
  git checkout -q -B "$BRANCH" || return 1

  # Same hazard from the other direction: a branch point with no files is never
  # something we should be opening a PR against.
  [ -n "$(git ls-files)" ] || return 1

  # setup is idempotent: it tops up config, CI, agent rules, LICENSE, stamps every
  # source file and image, and seals the manifest.
  node "$AM" setup --author "$AUTHOR" --email "$EMAIL" --github "$GHURL" \
    --license MIT --no-hook >/dev/null 2>&1 || return 1

  # Never commit bytecode a local tool run may have produced.
  git status --porcelain | awk '/^\?\?/{print $2}' | grep -E '__pycache__|\.pyc$' | xargs -r rm -rf

  if [ -n "$(git status --porcelain)" ]; then
    git add -A
    git -c "user.name=$BOT_NAME" -c "user.email=$BOT_EMAIL" commit -q -F - <<EOF
Add authorship watermarks

Stamp source files with a keyed authorship header, watermark images with
metadata plus an invisible pixel mark, and seal a hash manifest. CI verifies
the marks survive every PR.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
  fi

  git push -q -u origin "$BRANCH" --force-with-lease 2>/dev/null || return 1

  # One PR per repo, updated by later pushes -- never a second one.
  existing=$(gh pr list --repo "$OWNER/$repo" --head "$BRANCH" --state open \
    --json url --jq '.[0].url' 2>/dev/null)
  if [ -n "$existing" ]; then printf '%s' "$existing"; return 0; fi

  url=$(gh pr create --repo "$OWNER/$repo" --head "$BRANCH" \
    --title "Add authorship watermarks" --body "$(cat <<'BODY'
Opened automatically by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch) after this repo was found unmarked or drifted.

- **Source headers** — copyright, author URL, SPDX line, and an HMAC fingerprint that only my key can generate
- **Invisible zero-width mark** inside each header, which survives copy-paste
- **Images** — PNG/EXIF metadata plus an invisible pixel watermark repeated across the image
- **`AUTHORSHIP.json`** — SHA-256 of every file with a keyed proof, as a prior-art record
- **CI** — `authormark check` fails any PR that strips a watermark
- **`AGENTS.md` / `CLAUDE.md`** — tells AI tools never to remove the header block

The tool is vendored at `.authormark/authormark.mjs` (zero dependencies, Node ≥ 18), so the repo verifies itself.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
BODY
)" 2>/dev/null | grep -oE 'https://github.com/\S+' | head -1)
  [ -n "$url" ] || return 1
  printf '%s' "$url"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

unmarked=(); drifted=(); clean=(); failed=(); fixed=(); fixfailed=()

# $1 repo. Only called in FIX mode, with cwd inside that repo's clone.
try_fix() {
  local url
  url=$(fix_repo "$1") && [ -n "$url" ] && { fixed+=("$1 — $url"); return 0; }
  fixfailed+=("$1")
}

while IFS= read -r name; do
  [ -z "$name" ] && continue
  case "$SKIP" in *" $name "*) continue ;; esac

  dir="$WORK/$name"
  if ! gh repo clone "$OWNER/$name" "$dir" -- --depth 1 --quiet >/dev/null 2>&1; then
    failed+=("$name"); continue
  fi
  cd "$dir" || { failed+=("$name"); continue; }

  if [ ! -f .authormark.json ]; then
    unmarked+=("$name")
    [ "$FIX" = "1" ] && try_fix "$name"
    continue
  fi

  if out=$(node "$AM" check --presence . 2>&1); then
    clean+=("$name")
  else
    n=$(printf '%s' "$out" | grep -cE '^  (MISSING|STALE)')
    drifted+=("$name ($n file(s))")
    [ "$FIX" = "1" ] && try_fix "$name"
  fi
done < <(gh repo list "$OWNER" --limit 200 --no-archived --json name,isFork --jq '.[] | select(.isFork | not) | .name')

total=$(( ${#unmarked[@]} + ${#drifted[@]} + ${#clean[@]} + ${#failed[@]} ))
problems=$(( ${#unmarked[@]} + ${#drifted[@]} ))

{
  echo "Scanned **$total** repos on $(date -u '+%Y-%m-%d %H:%M UTC')."
  echo
  if [ "$problems" -eq 0 ] && [ ${#failed[@]} -eq 0 ]; then
    echo "✅ Every repo carries intact authorship watermarks."
  fi
  if [ ${#drifted[@]} -gt 0 ]; then
    echo "### ⚠️ Watermarks missing or stripped"
    echo "Files in these repos lost their header, or new files were added unstamped."
    for r in "${drifted[@]}"; do echo "- \`${r%% *}\` — ${r#* }"; done
    echo
    echo "Fix: \`FIX=1 ./watch.sh\`, or \`PUSH=1 authormark-rollout <repo>\`"
    echo
  fi
  if [ ${#unmarked[@]} -gt 0 ]; then
    echo "### 🆕 Repos with no watermarks at all"
    echo "New repos, or ones never set up."
    for r in "${unmarked[@]}"; do echo "- \`$r\`"; done
    echo
    echo "Fix: \`FIX=1 ./watch.sh\`, or \`PUSH=1 authormark-rollout ${unmarked[*]}\`"
    echo
  fi
  if [ ${#fixed[@]} -gt 0 ]; then
    echo "### 🤖 Fix PRs opened"
    echo "Branch \`$BRANCH\`, committed as \`$BOT_NAME\`. Review and merge:"
    for r in "${fixed[@]}"; do echo "- $r"; done
    echo
  fi
  if [ ${#fixfailed[@]} -gt 0 ]; then
    echo "### ❌ Could not open a fix PR"
    echo "The token needs **Contents: read and write** and **Pull requests: read and write** on these."
    for r in "${fixfailed[@]}"; do echo "- \`$r\`"; done
    echo
  fi
  if [ ${#failed[@]} -gt 0 ]; then
    echo "### ❓ Could not be checked"
    for r in "${failed[@]}"; do echo "- \`$r\` (clone failed — permissions or token scope?)"; done
    echo
  fi
  if [ ${#clean[@]} -gt 0 ]; then
    echo "<details><summary>${#clean[@]} clean repos</summary>"
    echo
    for r in "${clean[@]}"; do echo "- \`$r\`"; done
    echo
    echo "</details>"
  fi
} > "$WORK/report.md"

cat "$WORK/report.md"

# Keep exactly one issue open, updated in place, so this never spams.
[ "${REPORT:-1}" = "1" ] || exit 0
TITLE="authormark: authorship watermark status"
existing=$(gh issue list --repo "$OWNER/authormark-watch" --state open \
  --search "$TITLE in:title" --json number --jq '.[0].number' 2>/dev/null)

if [ "$problems" -gt 0 ]; then
  if [ -n "$existing" ]; then
    gh issue edit "$existing" --repo "$OWNER/authormark-watch" --body-file "$WORK/report.md" >/dev/null
    gh issue comment "$existing" --repo "$OWNER/authormark-watch" \
      --body "Re-scanned: **$problems** repo(s) still need attention." >/dev/null
  else
    gh issue create --repo "$OWNER/authormark-watch" --title "$TITLE" --body-file "$WORK/report.md" >/dev/null
  fi
  echo "::error::$problems repo(s) have missing or stripped watermarks"
  exit 1
elif [ -n "$existing" ]; then
  gh issue comment "$existing" --repo "$OWNER/authormark-watch" --body "All repos clean again. Closing." >/dev/null
  gh issue close "$existing" --repo "$OWNER/authormark-watch" >/dev/null
fi
