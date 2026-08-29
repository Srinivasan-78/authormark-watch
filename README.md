<!--
  @authormark v1 -- do not remove (authorship watermark)⁠​‌‌​​‌‌​​‌‌‌​‌​​​‌​‌​‌‌‌​‌‌​​​‌‌​‌​‌​‌​​​‌​‌‌​‌​​‌​​‌‌​​​‌​‌​​​‌​​‌‌​​‌​​‌​‌​‌‌‌​‌‌​‌‌‌​​‌‌​‌​‌‌​‌‌‌​‌‌‌​‌​‌​‌​‌​‌​​​​​‌​‌​​​‌‌‌​‌‌​‌‌​​​‌​‌‌​​​​​‌​‌‌​‌​‌​‌‌​​​​‌​‌‌​​​​​‌‌​‌​​⁠
  Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
  Author: https://github.com/Srinivasan-78
  SPDX-License-Identifier: MIT
  Fingerprint: AMK1.ftWcTZLQ2WnkwUAGlX-XX4
-->
# authormark-watch

One scheduled job that keeps eyes on **every** repo in this account.

Each repo's own `authormark` workflow only watches itself, and only if someone remembered to set
it up. This repo is the backstop: daily, it enumerates every non-archived, non-fork repo and
reports any that has no watermarks, has had them stripped, or has drifted (new files added
unstamped). Findings go into a single GitHub issue that is updated in place and closed
automatically once everything is clean again — so it never spams.

It also catches **brand-new repos** you forgot to run `authormark setup` on.

With `FIX=1` it does more than report: for every repo that is unmarked or drifted it applies the
marks on an `authormark` branch, commits as a bot account, pushes, and opens a pull request. One PR
per repo — a later run pushes to the same branch and reuses the open PR rather than opening a second
one.

## Why it uses its own checker

`watch.sh` runs *this repo's* copy of `authormark.mjs`, never the one vendored inside the repo
being checked. Someone who strips the watermarks from a repo could just as easily edit that repo's
own `.authormark/authormark.mjs` to always exit 0 — the repo's CI would go green while lying.
Checking from outside, with a copy they don't control, closes that hole.

## One-time setup

The workflow needs a token that can read your other repos. `GITHUB_TOKEN` can't — it is scoped to
this repo alone.

1. Create a **fine-grained personal access token** at
   <https://github.com/settings/personal-access-tokens/new>
   - Resource owner: `Srinivasan-78`
   - Repository access: **All repositories**
   - Permissions → Repository: **Contents: Read-only**, **Metadata: Read-only**,
     **Issues: Read and write**
   - Expiration: set a reminder to rotate it

   A classic PAT with the `repo` scope also works, but grants far more than this needs.

2. Add it as a secret named `WATCH_TOKEN`:

   ```sh
   gh secret set WATCH_TOKEN --repo Srinivasan-78/authormark-watch
   ```

3. Trigger a first run:

   ```sh
   gh workflow run watch.yml --repo Srinivasan-78/authormark-watch
   gh workflow run watch.yml --repo Srinivasan-78/authormark-watch -f fix=true   # and fix what it finds
   ```

Until `WATCH_TOKEN` exists the scheduled run will fail at the clone step — that failure is the
signal that step 2 is still outstanding.

The status issue is filed in *this* repo, so it does not use that PAT at all: the workflow passes
the built-in `GITHUB_TOKEN` as `ISSUE_TOKEN` and grants itself `issues: write`. A PAT scoped to the
repos being scanned usually cannot see this one, and GitHub reports that as
`Could not resolve to a Repository` rather than as a permission error.

## Opening fix PRs automatically

Reporting is the default. To have the watcher fix what it finds:

```sh
FIX=1 ./watch.sh
```

For each unmarked or drifted repo it checks out a branch named `authormark`, runs `authormark
setup` (config, vendored tool, CI workflow, agent rules, LICENSE, stamped sources, watermarked
images, sealed manifest), commits, pushes with `--force-with-lease`, and opens a PR. Repos that are
already clean are untouched, and nothing is ever pushed to a default branch. The PR links appear in
the status issue alongside everything else.

### Who the PR comes from

The pull request is opened by whichever account owns the token in `GH_TOKEN`, so to have it come
from a bot rather than from you, give the workflow a bot account's token as the `BOT_TOKEN` secret:

```sh
gh secret set BOT_TOKEN --repo Srinivasan-78/authormark-watch
```

That token needs **Contents: read and write**, **Pull requests: read and write**, and **Workflows:
read and write** on the repos it will fix, plus **Metadata: read-only**. Workflows permission is
required because `authormark setup` adds `.github/workflows/authormark.yml` and stamps any workflow
files already there; without it the push is rejected and the fix is reported as failed. When `BOT_TOKEN` is absent the workflow falls back to
`WATCH_TOKEN`, which is read-only, and every fix attempt will be reported as failed.

The commits themselves are attributed to `github-actions[bot]`. Override with the `BOT_NAME` and
`BOT_EMAIL` environment variables if your bot account is a different one.

### The signing key

Fingerprints are HMACs, so nothing can be stamped without `~/.authormark.key`. Locally that file is
already there and `FIX=1` just works. In CI the job reads the key from an `AUTHORMARK_KEY` secret
and writes it to that path.

Think carefully before adding that secret. The key is the thing that makes a fingerprint provably
yours, and a copy of it in GitHub Actions is a copy you no longer fully control — anyone who can
push a workflow to this repository, or who gains admin access to it, can print it. Running `FIX=1`
from your own machine on a schedule keeps the key off GitHub entirely, and is the safer default. If
you do put it in CI, restrict who can edit workflows in this repo and plan to rotate the key if that
ever changes — though note that rotating invalidates every fingerprint already issued, so the
practical answer is usually to keep the key local.

Without the key, `FIX=1` exits immediately with an explanation rather than opening empty PRs.

## Running it locally

```sh
./watch.sh              # scan and open/update the issue
REPORT=0 ./watch.sh     # scan and print the report only
FIX=1 ./watch.sh        # scan, then open a fix PR per problem repo
```

Locally it uses your `gh auth` session, so no token setup is needed — which also means locally the
PRs come from *your* account, not the bot's. Set `GH_TOKEN` to the bot's token to get bot-authored
PRs from a local run too.

## Excluded repos

`SKIP` at the top of `watch.sh` lists repos left alone because they may contain work that isn't
mine to claim: `WixTemplate`, `Ubisoft_spool`, `Simple-Actions`, `Brainrot_Study`. Archived repos
and forks are skipped automatically.
