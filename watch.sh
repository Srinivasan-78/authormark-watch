#!/usr/bin/env bash
# @authormark v1 -- do not remove (authorship watermark)
# Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
# Author: https://github.com/Srinivasan-78
# SPDX-License-Identifier: MIT
# Fingerprint: AMK1.zUo3GxzQ5xfTDCZUfGLymy
# Scan every repo this account owns and report any that is unmarked, has drifted,
# or has had watermarks stripped. Runs on a schedule from authormark-watch.
#
# Deliberately uses ITS OWN copy of authormark.mjs, never the one vendored inside
# the repo being checked -- otherwise stripping the marks and neutering that repo's
# vendored checker would pass silently.
set -uo pipefail

OWNER="${OWNER:-Srinivasan-78}"
# Repos that may hold work that isn't mine to claim, plus this repo itself.
# Matched as plain text against `gh repo list`, so these must be the CURRENT names:
# a rename on GitHub keeps the old name working as a redirect, but drops the repo
# out of this list and starts opening PRs against it.
SKIP=" wix-installer-template ubisoft-game-notes github-actions-snippets study-brainrot-generator authormark-watch "

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

# `gh repo clone` authenticates the clone but leaves no credentials behind, so a
# later `git push` in CI has nothing to authenticate with and dies asking for a
# username on stdin. Route git's github.com auth through gh, which reads GH_TOKEN.
# The token never enters a URL or the git config, so it cannot leak into logs.
if [ -n "${CI:-}" ] && [ -n "${GH_TOKEN:-}" ]; then
  git config --global credential."https://github.com".helper '!gh auth git-credential'
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

# Squeeze a captured stderr file down to the one line worth reporting, so a fix
# that fails says why -- a rejected workflow file and a missing token look alike
# otherwise.
why() {
  local msg
  # A step can fail without writing a word to stderr; say so rather than letting
  # grep's own "No such file" become the reported reason.
  [ -s "$1" ] || { printf 'no error output'; return 0; }
  msg=$(grep -aE 'rejected|denied|refusing|not accessible|forbidden|fatal|error|HTTP [0-9]{3}' "$1" | head -1)
  [ -n "$msg" ] || msg=$(grep -av '^[[:space:]]*$' "$1" | tail -1)
  # These lines end up in a public issue, so never let a token through.
  printf '%s' "$msg" | tr -d '\r' \
    | sed -E 's/(gh[pousr]_|github_pat_)[A-Za-z0-9_]+/***/g' | cut -c1-200
}

# Apply the marks on a branch and open a PR. Runs inside an already-cloned repo.
# Echoes the PR url on success and the reason on stderr on failure; the caller
# decides how to report either.
fix_repo() {
  local repo="$1" url existing err="$WORK/step.err"
  # No commit to branch from means an empty repo, or a clone that never checked
  # anything out. Branching there would commit a tree that DELETES every file.
  git rev-parse --verify -q HEAD >/dev/null || { echo "empty repo -- no commit to branch from" >&2; return 1; }
  git fetch -q --unshallow origin 2>/dev/null || git fetch -q origin 2>/dev/null || true
  git checkout -q -B "$BRANCH" 2>"$err" || { echo "checkout failed: $(why "$err")" >&2; return 1; }

  # Same hazard from the other direction: a branch point with no files is never
  # something we should be opening a PR against.
  [ -n "$(git ls-files)" ] || { echo "no files at the branch point" >&2; return 1; }

  # setup is idempotent: it tops up config, CI, agent rules, LICENSE, stamps every
  # source file and image, and seals the manifest.
  node "$AM" setup --author "$AUTHOR" --email "$EMAIL" --github "$GHURL" \
    --license MIT --no-hook >/dev/null 2>"$err" || { echo "authormark setup failed: $(why "$err")" >&2; return 1; }

  # Never commit bytecode a local tool run may have produced.
  git status --porcelain | awk '/^\?\?/{print $2}' | grep -E '__pycache__|\.pyc$' | xargs -r rm -rf

  if [ -n "$(git status --porcelain)" ]; then
    git add -A
    git -c "user.name=$BOT_NAME" -c "user.email=$BOT_EMAIL" commit -q -F - <<EOF
Add authorship watermarks

Stamp source files with a keyed authorship header, watermark images with
metadata plus an invisible pixel mark, and seal a hash manifest. CI verifies
the marks survive every PR.
EOF
  fi

  git push -q -u origin "$BRANCH" --force-with-lease 2>"$err" || { echo "push rejected: $(why "$err")" >&2; return 1; }

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
)" 2>"$err" | grep -oE 'https://github.com/\S+' | head -1)
  [ -n "$url" ] || { echo "pr create failed: $(why "$err")" >&2; return 1; }
  printf '%s' "$url"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

unmarked=(); drifted=(); clean=(); failed=(); fixed=(); fixfailed=()

# $1 repo. Only called in FIX mode, with cwd inside that repo's clone.
try_fix() {
  local url reason err="$WORK/fix.err"
  url=$(fix_repo "$1" 2>"$err") && [ -n "$url" ] && { fixed+=("$1 — $url"); return 0; }
  reason=$(grep -av '^[[:space:]]*$' "$err" | tail -1)
  fixfailed+=("$1|$reason")
}

# Read the list up front. Piped in through `done < <(...)`, a failed `gh repo
# list` is invisible: the loop simply never runs and the job reports "Scanned 0
# repos" as a success -- the exact blind spot this monitor exists to close.
repos=$(gh repo list "$OWNER" --limit 200 --no-archived --json name,isFork \
  --jq '.[] | select(.isFork | not) | .name' 2>"$WORK/list.err") || {
  echo "::error::could not list repos for $OWNER: $(why "$WORK/list.err")"
  exit 1
}
if [ -z "$repos" ]; then
  echo "::error::no repos returned for $OWNER -- the token is probably not scoped to read them."
  exit 1
fi

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
done <<< "$repos"

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
    echo "The token needs **Contents: read and write**, **Pull requests: read and write**, and **Workflows: read and write** on these (setup adds and stamps files under \`.github/workflows/\`)."
    for r in "${fixfailed[@]}"; do
      reason="${r#*|}"
      echo "- \`${r%%|*}\`${reason:+ — $reason}"
    done
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

# The status issue lives in THIS repo, so the workflow's built-in GITHUB_TOKEN
# can file it. The scan PAT usually cannot -- it is scoped to the repos being
# checked, and GitHub answers "Could not resolve to a Repository" rather than
# admitting the repo exists. Fall back to GH_TOKEN when ISSUE_TOKEN is unset,
# which is the local case, where gh is already logged in.
gh_issue() {
  if [ -n "${ISSUE_TOKEN:-}" ]; then GH_TOKEN="$ISSUE_TOKEN" gh issue "$@"; else gh issue "$@"; fi
}

existing=$(gh_issue list --repo "$OWNER/authormark-watch" --state open \
  --search "$TITLE in:title" --json number --jq '.[0].number' 2>/dev/null)

if [ "$problems" -gt 0 ]; then
  if [ -n "$existing" ]; then
    gh_issue edit "$existing" --repo "$OWNER/authormark-watch" --body-file "$WORK/report.md" >/dev/null 2>"$WORK/issue.err" \
      || echo "::warning::could not update issue #$existing: $(why "$WORK/issue.err")"
    gh_issue comment "$existing" --repo "$OWNER/authormark-watch" \
      --body "Re-scanned: **$problems** repo(s) still need attention." >/dev/null 2>&1
  else
    gh_issue create --repo "$OWNER/authormark-watch" --title "$TITLE" --body-file "$WORK/report.md" >/dev/null 2>"$WORK/issue.err" \
      || echo "::warning::could not file the status issue: $(why "$WORK/issue.err") -- the workflow needs 'issues: write' so GITHUB_TOKEN can post it"
  fi
  echo "::error::$problems repo(s) have missing or stripped watermarks"
  exit 1
elif [ -n "$existing" ]; then
  gh_issue comment "$existing" --repo "$OWNER/authormark-watch" --body "All repos clean again. Closing." >/dev/null 2>&1
  gh_issue close "$existing" --repo "$OWNER/authormark-watch" >/dev/null 2>&1
fi
