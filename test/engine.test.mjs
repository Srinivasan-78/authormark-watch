import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  auditWorkflow,
  detectStack,
  auditRepository,
  generateRepoPatches,
  transformRepository,
  verifyGitHubSignature,
  createWebhookServer,
  buildPortfolioAuditReport,
  writePortfolioReports,
} from '../bot.mjs';
import { analyzeWithGemini } from '../lib/ai.mjs';

test('detectStack identifies Python, Node/TS, and profile repositories accurately', () => {
  const pyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-py-'));
  const profDir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-prof-'));
  try {
    fs.writeFileSync(path.join(pyDir, 'pyproject.toml'), '[project]\nname = "demo"\n[tool.ruff]\nline-length = 100\n');
    fs.mkdirSync(path.join(pyDir, 'tests'));
    fs.writeFileSync(path.join(pyDir, 'tests', 'test_app.py'), 'def test_ok(): assert True\n');
    const pyStack = detectStack(pyDir, { name: 'demo', owner: { login: 'Srinivasan-78' } });
    assert.ok(pyStack.languages.includes('python'));
    assert.ok(pyStack.codeqlLanguages.includes('python'));
    assert.ok(pyStack.linters.includes('ruff'));
    assert.equal(pyStack.hasTests, true);
    assert.equal(pyStack.isPublishable, true);
    assert.equal(pyStack.isProfileRepo, false);

    fs.writeFileSync(path.join(profDir, 'README.md'), '# Hi\n');
    const profStack = detectStack(profDir, { name: 'Srinivasan-78', owner: { login: 'Srinivasan-78' } });
    assert.equal(profStack.isProfileRepo, true);
  } finally {
    fs.rmSync(pyDir, { recursive: true, force: true });
    fs.rmSync(profDir, { recursive: true, force: true });
  }
});

test('auditRepository produces 15-category scorecard and flags missing LICENSE without auto-adding', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-aud-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'sample-app', main: 'index.js' }));
    fs.writeFileSync(path.join(dir, 'index.js'), 'console.log(1);\n');
    const audit = auditRepository(dir, { name: 'sample-app', owner: { login: 'Srinivasan-78' } }, {
      cveCount: 0,
      findings: { secrets: [], historySecrets: [], workflowRisks: [], integrity: [] },
    }, { branchProtected: false });

    assert.equal(audit.scorecard.length, 15);
    const licTodo = audit.todos.find(t => t.id === 'LEG-01');
    assert.ok(licTodo);
    assert.equal(licTodo.autoFixable, false);

    const patches = generateRepoPatches(audit, {
      owner: 'Srinivasan-78',
      defaultBranch: 'main',
      existingCheck: rel => fs.existsSync(path.join(dir, rel)),
    });
    assert.ok(!patches.some(p => p.path === 'LICENSE'));
    assert.ok(patches.some(p => p.path === '.github/workflows/ci.yml'));
    assert.ok(patches.some(p => p.path === '.github/workflows/codeql.yml'));
    assert.ok(patches.some(p => p.path === '.github/workflows/secret-scan.yml'));
    assert.ok(patches.some(p => p.path === '.github/dependabot.yml'));

    // Every generated workflow must pass authormark-watch's own security audit!
    for (const p of patches) {
      if (p.path.startsWith('.github/workflows/')) {
        assert.deepEqual(auditWorkflow(p.content, p.path), [], `generated workflow ${p.path} failed auditWorkflow`);
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('generateRepoPatches never overwrites existing workflows or configs', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-keep-'));
  try {
    fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'custom' }));
    fs.writeFileSync(path.join(dir, '.github', 'workflows', 'ci.yml'), 'name: Custom CI\n');
    fs.writeFileSync(path.join(dir, 'SECURITY.md'), '# Existing Security\n');

    const audit = auditRepository(dir, { name: 'custom', owner: { login: 'Srinivasan-78' } }, {
      cveCount: 0,
      findings: { secrets: [], historySecrets: [], workflowRisks: [], integrity: [] },
    }, null);
    const patches = generateRepoPatches(audit, {
      owner: 'Srinivasan-78',
      existingCheck: rel => fs.existsSync(path.join(dir, rel)),
    });
    assert.ok(!patches.some(p => p.path === '.github/workflows/ci.yml'));
    assert.ok(!patches.some(p => p.path === 'SECURITY.md'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('transformRepository dry-run builds PR report and portfolio writer saves markdown files', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-tr-'));
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-rep-'));
  try {
    fs.writeFileSync(path.join(dir, 'README.md'), '# Demo\n');
    fs.writeFileSync(path.join(dir, 'main.py'), 'print("hi")\n');
    const res = await transformRepository({
      owner: 'Srinivasan-78',
      repoDir: dir,
      repoMeta: { name: 'py-demo', default_branch: 'main', owner: { login: 'Srinivasan-78' } },
      scanResult: { cveCount: 0, findings: { secrets: [], historySecrets: [], workflowRisks: [], integrity: [] } },
      posture: { branchProtected: false },
      dryRun: true,
    });
    assert.equal(res.prAction, 'dry-run');
    assert.ok(res.patchesCount > 0);
    assert.match(res.reportMarkdown, /Repository Health Scorecard/);

    const portfolioPath = writePortfolioReports(outDir, 'Srinivasan-78', '2026-11-27T00:00:00Z', [res]);
    assert.ok(fs.existsSync(portfolioPath));
    assert.ok(fs.existsSync(path.join(outDir, 'py-demo.md')));
    const md = buildPortfolioAuditReport('Srinivasan-78', '2026-11-27T00:00:00Z', [res]);
    assert.match(md, /py-demo/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test('analyzeWithGemini skips without key and parses valid Gemini response', async () => {
  const skipped = await analyzeWithGemini({ repoName: 'x', stack: { languages: [] }, scorecard: [], todos: [] }, { apiKey: '' });
  assert.equal(skipped.status, 'skipped');

  const ok = await analyzeWithGemini(
    { repoName: 'x', stack: { languages: ['javascript'] }, scorecard: [], todos: [] },
    {
      apiKey: 'dummy-key',
      fetchImpl: async () => ({
        ok: true,
        json: async () => ({ candidates: [{ content: { parts: [{ text: '- Add integration tests' }] } }] }),
      }),
    },
  );
  assert.equal(ok.status, 'ok');
  assert.match(ok.insights, /Add integration tests/);
});

test('verifyGitHubSignature and createWebhookServer validate HMAC-SHA256 signatures', async () => {
  const secret = 'test-webhook-secret';
  const payload = JSON.stringify({ action: 'created', repository: { name: 'new-repo' } });
  const goodSig = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
  assert.equal(verifyGitHubSignature(Buffer.from(payload), goodSig, secret), true);
  assert.equal(verifyGitHubSignature(Buffer.from(payload), 'sha256=deadbeef', secret), false);

  const server = createWebhookServer({ secret });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address();
    const health = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(health.status, 200);

    const badRes = await fetch(`http://127.0.0.1:${port}/webhook`, {
      method: 'POST',
      headers: { 'x-hub-signature-256': 'sha256=invalid', 'x-github-event': 'repository' },
      body: payload,
    });
    assert.equal(badRes.status, 401);

    const goodRes = await fetch(`http://127.0.0.1:${port}/webhook`, {
      method: 'POST',
      headers: { 'x-hub-signature-256': goodSig, 'x-github-event': 'repository' },
      body: payload,
    });
    assert.equal(goodRes.status, 202);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
