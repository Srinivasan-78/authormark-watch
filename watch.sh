#!/usr/bin/env bash
# @authormark v1 -- do not remove (authorship watermark)
# Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
# Author: https://github.com/Srinivasan-78
# SPDX-License-Identifier: MIT
# Fingerprint: AMK1.zUo3GxzQ5xfTDCZUfGLymy
# Master Bot supervisor for @Srinivasan-78:
#  - AuthorMark code watermarking & automated fix PRs
#  - Multi-language code linting & repository hygiene
#  - Automated PR tagging & labeling
#  - Automated issue tagging & triage
#  - Flagship automatch watch
#  - Account-wide dashboard issue management
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOT="$DIR/bot.mjs"
KEY_FILE="${KEY_FILE:-$HOME/.authormark.key}"

# In CI the built-in GITHUB_TOKEN cannot see other repos, so a PAT is required.
if [ -n "${CI:-}" ] && [ -z "${GH_TOKEN:-}" ] && [ -z "${BOT_TOKEN:-}" ] && [ -z "${WATCH_TOKEN:-}" ]; then
  echo "::error::WATCH_TOKEN or BOT_TOKEN secret is not set -- this job cannot read your other repos yet. See README setup."
  exit 1
fi

# Configure git credentials for pushes in CI
if [ -n "${CI:-}" ] && [ -n "${GH_TOKEN:-}" ]; then
  if command -v gh >/dev/null 2>&1; then
    git config --global credential."https://github.com".helper '!gh auth git-credential'
  fi
fi

# In FIX mode, write the signing key if provided via secret
if [ "${FIX:-0}" = "1" ] || [[ " $* " == *" --fix "* ]]; then
  if [ ! -f "$KEY_FILE" ] && [ -n "${AUTHORMARK_KEY:-}" ]; then
    mkdir -p "$(dirname "$KEY_FILE")"
    ( umask 077; printf '%s\n' "$AUTHORMARK_KEY" > "$KEY_FILE" )
  fi
fi

# Execute Master Bot Node.js Engine
if command -v node >/dev/null 2>&1 && [ -f "$BOT" ]; then
  ARGS=()
  [ "${FIX:-0}" = "1" ] && [[ " $* " != *" --fix "* ]] && ARGS+=(--fix)
  node "$BOT" "${ARGS[@]}" "$@"
  exit $?
else
  echo "::error::Node.js is required to run Master Bot engine ($BOT)." >&2
  exit 1
fi
