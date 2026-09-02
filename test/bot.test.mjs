/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.botTestPlaceholder0000000000
 */
// Unit tests for the pure classifiers, linter and report builder in bot.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  classifyPullRequest, classifyIssue, sanitize,
  buildMarkdownReport, lintRepository,
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
