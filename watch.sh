#!/usr/bin/env bash
# @authormark v1 -- do not remove (authorship watermark)
# Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
# Author: https://github.com/Srinivasan-78
# SPDX-License-Identifier: MIT
# Fingerprint: AMK1.3TvUT594Rz5tEvF_ZpGfZ0
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

AM="$(dirname "$(readlink -f "$0")")/authormark.mjs"
[ -f "$AM" ] || { echo "authormark.mjs not found at $AM" >&2; exit 1; }

# In CI the built-in GITHUB_TOKEN cannot see other repos, so a PAT is required.
# Fail with the actual reason rather than a confusing clone error.
if [ -n "${CI:-}" ] && [ -z "${GH_TOKEN:-}" ]; then
  echo "::error::WATCH_TOKEN secret is not set -- this job cannot read your other repos yet. See README steps 1-2."
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

unmarked=(); drifted=(); clean=(); failed=()

while IFS= read -r name; do
  [ -z "$name" ] && continue
  case "$SKIP" in *" $name "*) continue ;; esac

  dir="$WORK/$name"
  if ! gh repo clone "$OWNER/$name" "$dir" -- --depth 1 --quiet >/dev/null 2>&1; then
    failed+=("$name"); continue
  fi
  cd "$dir" || { failed+=("$name"); continue; }

  if [ ! -f .authormark.json ]; then
    unmarked+=("$name"); continue
  fi

  out=$(node "$AM" check --presence . 2>&1)
  if [ $? -eq 0 ]; then
    clean+=("$name")
  else
    n=$(printf '%s' "$out" | grep -cE '^  (MISSING|STALE)')
    drifted+=("$name ($n file(s))")
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
    echo "Fix: \`PUSH=1 authormark-rollout <repo>\`"
    echo
  fi
  if [ ${#unmarked[@]} -gt 0 ]; then
    echo "### 🆕 Repos with no watermarks at all"
    echo "New repos, or ones never set up."
    for r in "${unmarked[@]}"; do echo "- \`$r\`"; done
    echo
    echo "Fix: \`PUSH=1 authormark-rollout ${unmarked[*]}\`"
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
