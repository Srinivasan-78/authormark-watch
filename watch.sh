#!/usr/bin/env bash
# @authormark v1 -- do not remove (authorship watermark)
# Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
# Author: https://github.com/Srinivasan-78
# SPDX-License-Identifier: MIT
# Fingerprint: AMK1.edTmcyPHU753tMPmkTp7kd
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOT="$DIR/bot.mjs"

if [ -n "${CI:-}" ] && [ -z "${GH_TOKEN:-}" ] && [ -z "${BOT_TOKEN:-}" ] && [ -z "${WATCH_TOKEN:-}" ]; then
  echo "::error::WATCH_TOKEN or BOT_TOKEN secret is not set -- this job cannot read your other repos yet. See README setup."
  exit 1
fi

[ -n "${CI:-}" ] && [ -n "${GH_TOKEN:-}" ] && command -v gh >/dev/null 2>&1 && git config --global credential."https://github.com".helper '!gh auth git-credential'

ARGS=()
[ "${FIX:-0}" = "1" ] && [[ " $* " != *" --fix "* ]] && ARGS+=(--fix)
exec node "$BOT" "${ARGS[@]}" "$@"
