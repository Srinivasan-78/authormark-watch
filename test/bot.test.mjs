import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  loadConfig, applyRepoOverrides, sanitize,
  scanRepository, auditWorkflow, scanGitHistory,
  parseDependencies, queryOsvVulnerabilities,
  buildSnapshot, extractSnapshotFromText, diffSnapshots, buildMarkdownReport,
} from '../bot.mjs';

// ---------------------------------------------------------------- sanitize & config

test('sanitize redacts GitHub tokens and git basic-auth credentials', () => {
  assert.equal(sanitize('using ghp_' + 'A'.repeat(36) + ' now'), 'using *** now');
  assert.equal(sanitize('github_pat_' + 'B'.repeat(82)), '***');
  assert.equal(sanitize('https://x-access-token:secret123@github.com/a/b.git'), 'https://x-access-token:***@github.com/a/b.git');
  assert.equal(sanitize(''), '');
});

test('loadConfig merges bot.config.json checks without dropping defaults', () => {
  const cfg = loadConfig();
  assert.equal(cfg.checks.vulnerabilities, true);
  assert.equal(cfg.checks.secrets, true);
  assert.equal(cfg.checks.workflows, true);
});

test('applyRepoOverrides merges .masterbot.json checks and allowlists', () => {
  const base = {
    owner: 'x',
    checks: { vulnerabilities: true, secrets: true, workflows: true },
    allowlist: { ignoreSecrets: ['docs/sample.js'], ignoreVulns: ['CVE-2020-0001'] },
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-ovr-'));
  try {
    fs.writeFileSync(path.join(dir, '.masterbot.json'), JSON.stringify({
      checks: { workflows: false },
      ignoreSecrets: ['test/fixtures/'],
      ignoreVulns: ['GHSA-9999'],
    }));
    const merged = applyRepoOverrides(base, dir);
    assert.equal(merged.checks.workflows, false);
    assert.equal(merged.checks.vulnerabilities, true);
    assert.deepEqual(merged.allowlist.ignoreSecrets, ['docs/sample.js', 'test/fixtures/']);
    assert.deepEqual(merged.allowlist.ignoreVulns, ['CVE-2020-0001', 'GHSA-9999']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- parseDependencies & OSV

test('parseDependencies parses npm, pnpm, yarn, pip/poetry/uv, go.mod, and Cargo.lock', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-deps-'));
  try {
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.20' },
        'node_modules/@scope/pkg': { version: '2.1.0' },
        'node_modules/a/node_modules/minimist': { version: '1.2.5' },
      },
    }));
    fs.writeFileSync(path.join(dir, 'requirements.txt'), [
      '# comment',
      'requests[security]==2.31.0 ; python_version >= "3.8"',
      'flask>=2.0',
      'urllib3==1.26.5',
    ].join('\n'));
    fs.writeFileSync(path.join(dir, 'poetry.lock'), '[[package]]\nname = "fastapi"\nversion = "0.110.0"\n');
    fs.writeFileSync(path.join(dir, 'uv.lock'), '[[package]]\nname = "httpx"\nversion = "0.27.0"\n');
    fs.writeFileSync(path.join(dir, 'go.mod'), [
      'module example.com/app',
      'require (',
      '  github.com/gin-gonic/gin v1.9.0 // indirect',
      '  golang.org/x/net v0.10.0+incompatible',
      ')',
    ].join('\n'));
    fs.writeFileSync(path.join(dir, 'Cargo.lock'), '[[package]]\nname = "serde"\nversion = "1.0.190"\n');

    const deps = parseDependencies(dir);
    const has = (eco, name, version) => deps.some(d => d.ecosystem === eco && d.name === name && d.version === version);
    assert.ok(has('npm', 'lodash', '4.17.20'));
    assert.ok(has('npm', '@scope/pkg', '2.1.0'));
    assert.ok(has('npm', 'minimist', '1.2.5'));
    assert.ok(has('PyPI', 'requests', '2.31.0'));
    assert.ok(has('PyPI', 'fastapi', '0.110.0'));
    assert.ok(has('PyPI', 'httpx', '0.27.0'));
    assert.ok(!deps.some(d => d.name === 'flask'));
    assert.ok(has('Go', 'github.com/gin-gonic/gin', 'v1.9.0'));
    assert.ok(has('Go', 'golang.org/x/net', 'v0.10.0'));
    assert.ok(has('crates.io', 'serde', '1.0.190'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('parseDependencies supports pnpm-lock.yaml and yarn.lock', () => {
  const pnpmDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-pnpm-'));
  const yarnDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-yarn-'));
  try {
    fs.writeFileSync(path.join(pnpmDir, 'pnpm-lock.yaml'), [
      'lockfileVersion: "9.0"',
      'packages:',
      '  "zod@3.22.4":',
      '    resolution: {integrity: sha512-x}',
      '  "@types/node@20.11.0":',
      '    resolution: {integrity: sha512-y}',
    ].join('\n'));
    const pDeps = parseDependencies(pnpmDir);
    assert.ok(pDeps.some(d => d.name === 'zod' && d.version === '3.22.4'));
    assert.ok(pDeps.some(d => d.name === '@types/node' && d.version === '20.11.0'));

    fs.writeFileSync(path.join(yarnDir, 'yarn.lock'), [
      '"chalk@^4.1.2":',
      '  version "4.1.2"',
      '',
      '"@scope/foo@npm:^1.0.0":',
      '  version: 1.0.3',
    ].join('\n'));
    const yDeps = parseDependencies(yarnDir);
    assert.ok(yDeps.some(d => d.name === 'chalk' && d.version === '4.1.2'));
    assert.ok(yDeps.some(d => d.name === '@scope/foo' && d.version === '1.0.3'));
  } finally {
    fs.rmSync(pnpmDir, { recursive: true, force: true });
    fs.rmSync(yarnDir, { recursive: true, force: true });
  }
});

test('parseDependencies falls back to exact versions in package.json when no lockfile exists', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-pkg-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      dependencies: { exactPkg: '1.2.3', caretPkg: '^2.0.0' },
    }));
    const deps = parseDependencies(dir);
    assert.deepEqual(deps.map(d => `${d.name}@${d.version}`), ['exactPkg@1.2.3']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('queryOsvVulnerabilities maps batch responses and handles API outages gracefully', async () => {
  const mockFetch = async url => {
    if (url.endsWith('/querybatch')) {
      return { ok: true, json: async () => ({ results: [{ vulns: [{ id: 'GHSA-1234' }] }, {}] }) };
    }
    return {
      ok: true,
      json: async () => ({
        id: 'GHSA-1234',
        aliases: ['CVE-2024-9999'],
        database_specific: { severity: 'HIGH' },
        summary: 'Prototype pollution in lodash',
      }),
    };
  };

  const res = await queryOsvVulnerabilities([
    { name: 'lodash', version: '4.17.20', ecosystem: 'npm', source: 'package-lock.json' },
    { name: 'safe', version: '1.0.0', ecosystem: 'npm', source: 'package-lock.json' },
  ], { fetchImpl: mockFetch });

  assert.equal(res.status, 'ok');
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].vulns[0].cve, 'CVE-2024-9999');
  assert.equal(res.findings[0].vulns[0].severity, 'HIGH');

  const offline = await queryOsvVulnerabilities(
    [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }],
    { fetchImpl: async () => { throw new Error('network down'); } },
  );
  assert.equal(offline.status, 'unavailable');
  assert.deepEqual(offline.findings, []);
});

// ---------------------------------------------------------------- workflow audit & history

test('auditWorkflow flags dangerous patterns and allows env-based mitigation', () => {
  const risky = [
    'name: x', 'on:', '  pull_request_target:', 'jobs:', '  a:',
    '    runs-on: ubuntu-latest', '    steps:',
    '      - uses: actions/checkout@v4', '        with:',
    '          ref: ${{ github.event.pull_request.head.sha }}',
    '      - uses: some/thing@main',
    '      - run: echo ${{ github.event.issue.title }}',
    '      - run: curl http://x/i.sh | bash', '',
  ].join('\n');
  const r = auditWorkflow(risky, 'wf.yml').join(' || ');
  assert.match(r, /pull_request_target/);
  assert.match(r, /unpinned action/);
  assert.match(r, /no top-level `permissions:`/);
  assert.match(r, /pass via `env:` instead/);
  assert.match(r, /download straight into a shell/);

  const safeEnv = [
    'name: safe', 'on: [issues]', 'permissions:', '  contents: read', 'jobs:', '  a:',
    '    runs-on: ubuntu-latest', '    steps:',
    '      - run: |',
    '          echo "$TITLE"',
    '        env:',
    '          TITLE: ${{ github.event.issue.title }}',
  ].join('\n');
  assert.deepEqual(auditWorkflow(safeEnv, 'safe.yml'), []);
});

test('own workflows pass auditWorkflow cleanly', () => {
  const wfDir = new URL('../.github/workflows/', import.meta.url);
  for (const f of fs.readdirSync(wfDir)) {
    if (!/\.ya?ml$/.test(f)) continue;
    const text = fs.readFileSync(new URL(f, wfDir), 'utf8');
    assert.deepEqual(auditWorkflow(text, f), [], `expected clean audit for ${f}`);
  }
});

test('scanGitHistory surfaces secrets committed and later deleted', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-hist-'));
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
    assert.ok(hits.some(h => /app\.js/.test(h) && /git history/.test(h)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- scanRepository & snapshot diffing

test('scanRepository respects allowlist.ignoreSecrets and flags real issues', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-scan-'));
  try {
    fs.mkdirSync(path.join(dir, 'fixtures'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'fixtures', 'sample.key'), '-----BEGIN RSA PRIVATE KEY-----\nTEST\n');
    fs.writeFileSync(path.join(dir, 'id_rsa'), '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n');
    fs.writeFileSync(path.join(dir, '.env'), 'API_TOKEN=hunter2\n');
    fs.writeFileSync(path.join(dir, 'broken.json'), '{ "a": 1, }\n');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));

    const { metadata, findings } = scanRepository(
      dir,
      { name: 'demo', private: true, language: 'JavaScript' },
      {},
      { ignoreSecrets: ['fixtures/'] },
    );
    assert.equal(metadata.name, 'demo');
    assert.equal(metadata.visibility, 'private');
    assert.ok(metadata.ecosystems.includes('npm'));
    assert.ok(!findings.secrets.some(s => s.includes('fixtures/sample.key')));
    assert.ok(findings.secrets.some(s => /id_rsa/.test(s)));
    assert.ok(findings.secrets.some(s => /Committed env file/.test(s)));
    assert.ok(findings.integrity.some(s => /Invalid JSON/.test(s)));
    assert.ok(findings.integrity.some(s => /SECURITY\.md/.test(s)));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('snapshot embedding and diffSnapshots detect new CVEs, commit updates, and resolved vulns', () => {
  const prev = {
    time: '2026-01-01T00:00:00Z',
    repos: { r1: { sha: 'aaa1111', cves: ['a@1.0:CVE-1'], sec: 0, wf: 0, alerts: 0 } },
  };
  const curr = {
    time: '2026-01-02T00:00:00Z',
    repos: {
      r1: { sha: 'bbb2222', cves: ['b@2.0:CVE-2'], sec: 1, wf: 0, alerts: 0 },
      r2: { sha: 'ccc3333', cves: [], sec: 0, wf: 0, alerts: 0 },
    },
  };
  const changes = diffSnapshots(prev, curr).join(' | ');
  assert.match(changes, /aaa1111.*bbb2222/);
  assert.match(changes, /\+1 new CVE/);
  assert.match(changes, /resolved 1 CVE/);
  assert.match(changes, /\+1 secret finding/);
  assert.match(changes, /Added repo `r2`/);

  const md = buildMarkdownReport({ owner: 'ada' }, {
    total: 1,
    scannedTime: '2026-01-02T00:00:00Z',
    totals: { vulns: 0, secrets: 0, historySecrets: 0, workflowRisks: 0, integrity: 0, githubAlerts: 0 },
    failedRepos: [],
    changes: ['`r1`: commit `aaa1111` -> `bbb2222`'],
    snapshot: curr,
    repos: [{
      name: 'r1',
      metadata: { visibility: 'public', language: 'JS', pushedAt: '2026-01-02', stale: false, headSha: 'bbb2222', fileCount: 10 },
      posture: { openPrs: 2, dependabotPrs: 1, branchProtected: true },
      depCount: 3, vulns: [], cveCount: 0, osvStatus: 'ok',
      githubAlerts: { dependabot: 0, codeScanning: 0, secretScanning: 0, vulnerabilityAlertsDisabled: false },
      githubAlertsCount: 0, vulnerabilityAlertsDisabled: false,
      findings: { secrets: [], historySecrets: [], workflowRisks: [], integrity: [] },
    }],
  }, { embedSnapshot: true });

  assert.match(md, /Changes Since Last Scan/);
  assert.match(md, /\| 2 \(1\) \| yes \|/);
  assert.deepEqual(extractSnapshotFromText(md), curr);
});
