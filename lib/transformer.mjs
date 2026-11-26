import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { gitAuthEnv, sanitize } from './github.mjs';
import { STANDARD_LABELS, auditRepository } from './auditor.mjs';
import { generateRepoPatches } from './templates.mjs';
import { analyzeWithGemini } from './ai.mjs';

const DEFAULT_BRANCH_NAME = 'chore/authormark-engineering-standards';

function buildPrBody(audit, patches, aiResult, posture) {
  const lines = [];
  lines.push(`# Automated DevSecOps, Quality & Governance Audit for \`${audit.repo}\``);
  lines.push('');
  lines.push(`**Detected Stack:** ${audit.stack.languages.join(', ') || 'docs/static'} (Package manager: \`${audit.stack.packageManager || 'none'}\`)`);
  lines.push('');

  if (patches.length) {
    lines.push('## Changes Included in This PR');
    lines.push('');
    for (const p of patches) lines.push(`- \`${p.path}\` — ${p.reason}`);
    lines.push('');
  } else {
    lines.push('## Changes Included in This PR\n\nNo missing baseline files to add.\n');
  }

  lines.push('## Repository Health Scorecard (Baseline)');
  lines.push('');
  lines.push('| Category | Status | Evidence |');
  lines.push('|---|---|---|');
  for (const s of audit.scorecard) {
    lines.push(`| ${s.category} | ${s.status} | ${s.evidence} |`);
  }
  lines.push('');

  if (audit.todos.length) {
    lines.push('## Remaining TODOs & Manual Admin Checklist');
    lines.push('');
    for (const t of audit.todos) {
      const tag = t.autoFixable ? 'Auto-addressed in PR' : 'Manual Action Required';
      lines.push(`- **[${t.priority}] ${t.id}: ${t.title}** (${tag}) — ${t.reason} *Resolution:* ${t.resolution}`);
    }
    lines.push('');
  }

  if (posture?.branchProtected === false) {
    lines.push('> [!IMPORTANT]');
    lines.push('> Default branch protection is currently disabled. Enable PR reviews, required status checks, and force-push protection in **Settings -> Branches**.');
    lines.push('');
  }

  if (aiResult?.status === 'ok' && aiResult.insights) {
    lines.push('## AI Architecture & QA Recommendations');
    lines.push('');
    lines.push(aiResult.insights);
    lines.push('');
  }

  lines.push('---');
  lines.push('*Generated automatically by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*');
  return lines.join('\n');
}

function applyPatchesToDisk(repoDir, patches) {
  for (const p of patches) {
    const dest = path.join(repoDir, p.path);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, p.content, 'utf8');
  }
}

async function transformRepository({
  owner,
  repoDir,
  repoMeta,
  scanResult,
  posture,
  client,
  token,
  dryRun = false,
  useAi = false,
  syncLabels = true,
  branchName = DEFAULT_BRANCH_NAME,
} = {}) {
  const repoName = repoMeta?.name || path.basename(repoDir);
  const defaultBranch = repoMeta?.default_branch || 'main';
  const audit = auditRepository(repoDir, repoMeta, scanResult, posture);
  const patches = generateRepoPatches(audit, {
    owner,
    defaultBranch,
    existingCheck: rel => fs.existsSync(path.join(repoDir, rel)),
  });

  const aiResult = useAi
    ? await analyzeWithGemini({ repoName, stack: audit.stack, scorecard: audit.scorecard, todos: audit.todos })
    : { status: 'skipped', insights: null };

  const prBody = buildPrBody(audit, patches, aiResult, posture);
  const result = {
    repo: repoName,
    audit,
    patchesCount: patches.length,
    patchedFiles: patches.map(p => p.path),
    prUrl: null,
    prAction: dryRun ? 'dry-run' : 'none',
    labelsSynced: 0,
    aiStatus: aiResult.status,
    reportMarkdown: prBody,
  };

  if (dryRun) return result;

  if (client?.token && syncLabels) {
    const lblRes = await client.syncLabels(owner, repoName, STANDARD_LABELS);
    result.labelsSynced = lblRes.added;
  }

  if (!patches.length || !token || !client?.token) return result;

  const git = (args, extraEnv = {}) => execFileSync('git', args, {
    cwd: repoDir,
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    env: { ...gitAuthEnv(token), ...extraEnv },
  });

  try {
    git(['checkout', '-B', branchName]);
    applyPatchesToDisk(repoDir, patches);
    git(['add', '-A']);

    const status = git(['status', '--porcelain']).trim();
    if (!status) {
      result.prAction = 'up-to-date';
      return result;
    }

    git(['config', 'user.name', 'authormark-watch[bot]']);
    git(['config', 'user.email', 'authormark-watch[bot]@users.noreply.github.com']);
    git(['commit', '-m', 'chore: apply DevSecOps, CI, security, and governance standards']);
    git(['push', '--force-with-lease', 'origin', branchName]);

    const prTitle = 'chore: apply DevSecOps, CI, security & governance standards';
    const existingPr = await client.findOpenPrByBranch(owner, repoName, branchName);
    if (existingPr) {
      const updated = await client.updatePullRequest(owner, repoName, existingPr.number, { title: prTitle, body: prBody });
      result.prUrl = updated?.html_url || existingPr.html_url;
      result.prAction = 'updated';
    } else {
      const created = await client.createPullRequest(owner, repoName, {
        title: prTitle,
        body: prBody,
        head: branchName,
        base: defaultBranch,
      });
      result.prUrl = created?.html_url || null;
      result.prAction = 'created';
    }
  } catch (err) {
    result.prAction = 'error';
    result.error = sanitize(err.message);
  }

  return result;
}

export { DEFAULT_BRANCH_NAME, buildPrBody, applyPatchesToDisk, transformRepository };
