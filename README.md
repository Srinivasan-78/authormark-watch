<!--
  @authormark v1 -- do not remove (authorship watermark)⁠​‌​‌​​​​​‌​‌​‌‌‌​‌‌‌​​‌​​‌​​​​‌‌​​‌‌​‌‌‌​‌​‌​​​‌​‌‌​‌‌‌‌​​‌‌​​‌‌​‌​​​‌‌​​‌​​‌​​‌​‌‌​​‌​​​‌‌‌​​​‌​‌‌‌​​‌​​​‌‌​​​‌​‌​‌‌​​​​‌​​​​‌​​‌​‌​‌‌‌​‌​​‌​‌​​‌‌​‌‌​‌​​‌‌​​‌‌​​‌‌​​​‌​‌​‌‌​​‌⁠
  Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
  Author: https://github.com/Srinivasan-78
  SPDX-License-Identifier: MIT
  Fingerprint: AMK1.PWrC7Qo3FIdqr1XBWJm31Y
-->
# authormark-watch

One scheduled job that keeps eyes on **every** repo in this account.

Each repo's own `authormark` workflow only watches itself, and only if someone remembered to set
it up. This repo is the backstop: daily, it enumerates every non-archived, non-fork repo and
reports any that has no watermarks, has had them stripped, or has drifted (new files added
unstamped). Findings go into a single GitHub issue that is updated in place and closed
automatically once everything is clean again — so it never spams.

It also catches **brand-new repos** you forgot to run `authormark setup` on.

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
   ```

Until `WATCH_TOKEN` exists the scheduled run will fail at the clone step — that failure is the
signal that step 2 is still outstanding.

## Running it locally

```sh
./watch.sh              # scan and open/update the issue
REPORT=0 ./watch.sh     # scan and print the report only
```

Locally it uses your `gh auth` session, so no token setup is needed.

## Excluded repos

`SKIP` at the top of `watch.sh` lists repos left alone because they may contain work that isn't
mine to claim: `WixTemplate`, `Ubisoft_spool`, `Simple-Actions`, `Brainrot_Study`. Archived repos
and forks are skipped automatically.
