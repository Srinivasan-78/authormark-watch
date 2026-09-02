/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.cliIntegrationTestPlaceholder
 */
// End-to-end CLI tests for the stateful commands (init/stamp/check/seal/chain/
// rotate/attest). Each runs in a throwaway directory with its own key file.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const AM = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), 'authormark.mjs');

let dir, home;
before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-cli-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'am-home-'));
});
after(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(home, { recursive: true, force: true });
});

const run = (...args) => execFileSync(process.execPath, [AM, ...args], {
  cwd: dir,
  encoding: 'utf8',
  env: { ...process.env, HOME: home, USERPROFILE: home },
});

test('init writes config and a key', () => {
  run('init', '--author', 'Test', '--email', 't@e.co', '--github', 'https://github.com/t');
  assert.ok(fs.existsSync(path.join(dir, '.authormark.json')));
  assert.ok(fs.existsSync(path.join(home, '.authormark.key')));
});

test('stamp then check passes with a valid fingerprint', () => {
  fs.writeFileSync(path.join(dir, 'a.js'), 'export const x = 1\n');
  run('stamp', 'a.js', '--zw');
  const marked = fs.readFileSync(path.join(dir, 'a.js'), 'utf8');
  assert.match(marked, /@authormark v1/);
  assert.match(marked, /Fingerprint: AMK1\./);
  const out = run('check', '.');
  assert.match(out, /valid fingerprint/);
});

test('editing a stamped file makes check fail until re-stamped', () => {
  fs.appendFileSync(path.join(dir, 'a.js'), '\nexport const y = 2\n');
  assert.throws(() => run('check', '.'), /Command failed|STALE/);
  run('stamp', 'a.js');
  assert.match(run('check', '.'), /valid fingerprint/);
});

test('check --json reports machine-readable status', () => {
  const out = JSON.parse(run('check', '--json', '.'));
  assert.equal(out.ok, true);
  assert.equal(typeof out.total, 'number');
  assert.deepEqual(out.missing, []);
});

test('seal appends a verifiable hash-chained log entry each time', () => {
  run('seal');
  run('seal');
  const log = fs.readFileSync(path.join(dir, 'AUTHORSHIP.log'), 'utf8').trim().split('\n');
  assert.equal(log.length, 2);
  const out = run('chain');
  assert.match(out, /0 broken link\(s\), 0 bad mac\(s\)/);
});

test('tampering with a past log line breaks the chain', () => {
  const p = path.join(dir, 'AUTHORSHIP.log');
  fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('"seq":0', '"seq":7'));
  assert.throws(() => run('chain'), /Command failed/);
});

test('rotate keeps old fingerprints verifiable via the archived key', () => {
  fs.rmSync(path.join(dir, 'AUTHORSHIP.log'), { force: true });
  run('rotate');
  assert.ok(fs.existsSync(path.join(home, '.authormark.key.d')));
  assert.match(run('check', '.'), /valid fingerprint/); // archived key still tried
});

test('attest writes an in-toto SLSA provenance statement', () => {
  run('attest', '.');
  const st = JSON.parse(fs.readFileSync(path.join(dir, 'AUTHORSHIP.intoto.jsonl'), 'utf8'));
  assert.equal(st._type, 'https://in-toto.io/Statement/v1');
  assert.equal(st.predicateType, 'https://slsa.dev/provenance/v1');
  assert.ok(st.subject.some(s => s.name === 'a.js' && /^[0-9a-f]{64}$/.test(s.digest.sha256)));
});
