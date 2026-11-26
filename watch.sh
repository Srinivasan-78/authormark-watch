#!/usr/bin/env bash
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -n "${CI:-}" ] && [ -z "${GH_TOKEN:-}" ] && [ -z "${BOT_TOKEN:-}" ] && [ -z "${WATCH_TOKEN:-}" ]; then
  echo "::error::WATCH_TOKEN or BOT_TOKEN secret is not set."
  exit 1
fi

exec node "$DIR/bot.mjs" "$@"
