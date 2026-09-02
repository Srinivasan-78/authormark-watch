/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.Jov99f_26V419_iNHue_4N
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

test('buildDependabotConfig groups every ecosystem and caps open PRs', () => {
  const yml = buildDependabotConfig(['npm', 'github-actions']);
  assert.match(yml, /package-ecosystem: "npm"/);
  assert.match(yml, /package-ecosystem: "github-actions"/);
  assert.match(yml, /npm-minor-patch:/);
  assert.match(yml, /github-actions-minor-patch:/);
  assert.match(yml, /open-pull-requests-limit: 10/);
  assert.match(yml, /update-types: \["minor", "patch"\]/);
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
