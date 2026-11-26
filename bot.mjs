#!/usr/bin/env node
// Read-only cross-repo security, vulnerability, and inventory monitor (Node >= 18, zero deps).

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  log, warn, errLog, sanitize, resolveToken, resolveIssueToken,
  cloneShallow, cloneForPr, notify, GitHubClient,
} from './lib/github.mjs';
import {
  walkFiles, auditWorkflow, scanGitHistory, scanRepository, SECRET_PATTERNS,
} from './lib/scanner.mjs';
import { parseDependencies, queryOsvVulnerabilities } from './lib/vulns.mjs';
import {
  buildSnapshot, extractSnapshotFromText, diffSnapshots, buildMarkdownReport,
  buildPortfolioAuditReport, writePortfolioReports,
} from './lib/report.mjs';
import { STANDARD_LABELS, detectStack, auditRepository } from './lib/auditor.mjs';
import { generateRepoPatches } from './lib/templates.mjs';
import { transformRepository } from './lib/transformer.mjs';
import { createWebhookServer, verifyGitHubSignature } from './lib/webhook.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_FILE = path.join(__dirname, 'bot.config.json');

function loadConfig() {
  const defaults = {
    owner: 'Srinivasan-78',
    repos: { include: [], exclude: [], skip: [], includeForks: false, includeArchived: false },
    checks: {
      vulnerabilities: true,
      githubAlerts: true,
      posture: true,
      secrets: true,
      gitHistorySecrets: true,
      workflows: true,
      integrity: true,
    },
    allowlist: { ignoreSecrets: [], ignoreVulns: [] },
    notify: {},
  };
  if (!fs.existsSync(CONFIG_FILE)) return defaults;
  try {
    const parsed = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    return {
      ...defaults,
      ...parsed,
      repos: { ...defaults.repos, ...(parsed.repos || {}) },
      checks: { ...defaults.checks, ...(parsed.checks || {}) },
      allowlist: { ...defaults.allowlist, ...(parsed.allowlist || {}) },
      notify: { ...defaults.notify, ...(parsed.notify || {}) },
    };
  } catch (e) {
    warn(`Failed to parse bot.config.json: ${e.message}. Using defaults.`);
    return defaults;
  }
}

function applyRepoOverrides(config, repoDir) {
  const p = path.join(repoDir, '.masterbot.json');
  if (!fs.existsSync(p)) return config;
  try {
    const o = JSON.parse(fs.readFileSync(p, 'utf8'));
    const baseAllow = config.allowlist || { ignoreSecrets: [], ignoreVulns: [] };
    const patchAllow = o.allowlist || {};
    return {
      ...config,
      ...o,
      checks: { ...config.checks, ...(o.checks || {}) },
      allowlist: {
        ignoreSecrets: [...(baseAllow.ignoreSecrets || []), ...(patchAllow.ignoreSecrets || []), ...(o.ignoreSecrets || [])],
        ignoreVulns: [...(baseAllow.ignoreVulns || []), ...(patchAllow.ignoreVulns || []), ...(o.ignoreVulns || [])],
      },
    };
  } catch {
    warn(`ignored malformed .masterbot.json in ${path.basename(repoDir)}`);
    return config;
  }
}

function flagVal(args, name) {
  const eq = args.find(a => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1) || null;
  const i = args.indexOf(name);
  if (i === -1) return null;
  const v = args[i + 1];
  return v && !v.startsWith('-') ? v : null;
}

const HELP = `authormark-watch -- cross-repo vulnerability scanner, auditor & DevSecOps transformer

Usage:
  node bot.mjs [options]
  node bot.mjs webhook

Options:
  --repo <name>      Target a single repository
  --public-only      Only target public repositories
  --audit            Run 15-category DevSecOps/Quality/Governance audit
  --transform        Open/update PRs with missing CI, security, and governance files
  --ai               Enable Gemini API architecture/QA insights (requires GEMINI_API_KEY)
  --write-reports    Write central reports to ./reports/PORTFOLIO_REPORT.md
  --snapshot <path>  Read/write previous JSON snapshot locally for change tracking
  --json             Print full JSON snapshot instead of Markdown report
  --no-osv           Skip live OSV vulnerability API queries
  --dry-run          Run checks/transforms without pushing branches, PRs, issues, or webhooks
  --help             Show this help message`;

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) { log(HELP); process.exit(0); }

  if (args[0] === 'webhook') {
    const port = Number(process.env.WEBHOOK_PORT || process.env.PORT || 8787);
    const server = createWebhookServer({
      onRepoEvent: async ({ repo }) => {
        log(`Triggering audit for ${repo} via webhook...`);
      },
    });
    server.listen(port, () => log(`authormark-watch webhook listening on :${port}`));
    return;
  }

  const config = loadConfig();
  const token = resolveToken();
  const issueToken = resolveIssueToken();
  const isDryRun = args.includes('--dry-run');
  const asJson = args.includes('--json');
  const doTransform = args.includes('--transform') || process.env.TRANSFORM === '1';
  const doAudit = doTransform || args.includes('--audit') || process.env.AUDIT === '1';
  const useAi = args.includes('--ai') || process.env.USE_AI === '1';
  const writeReports = args.includes('--write-reports') || process.env.WRITE_REPORTS === '1';
  const publicOnly = args.includes('--public-only') || process.env.PUBLIC_ONLY === '1';
  const skipOsv = args.includes('--no-osv') || process.env.SKIP_OSV === '1';
  const targetRepo = flagVal(args, '--repo') || process.env.TARGET_REPO || null;
  const snapshotPath = flagVal(args, '--snapshot') || process.env.SNAPSHOT_PATH || null;

  const client = new GitHubClient(token);
  const issueClient = new GitHubClient(issueToken || token);

  let existingIssue = null;
  if (issueClient.token) {
    existingIssue = await issueClient.findTrackingIssue(config.owner, 'authormark-watch', ['watch:', 'authormark:']);
  }

  let prevSnapshot = null;
  if (snapshotPath && fs.existsSync(snapshotPath)) {
    try { prevSnapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8')); } catch {}
  } else if (existingIssue?.body) {
    prevSnapshot = extractSnapshotFromText(existingIssue.body);
  }

  let repos = [];
  try {
    if (targetRepo) {
      const meta = token ? await client.getRepo(config.owner, targetRepo).catch(() => null) : null;
      repos = [meta || { name: targetRepo, fork: false, archived: false }];
    } else if (token) {
      repos = await client.listRepos(config.owner);
    } else {
      const parent = path.dirname(__dirname);
      for (const ent of fs.readdirSync(parent, { withFileTypes: true })) {
        if (ent.isDirectory() && fs.existsSync(path.join(parent, ent.name, '.git'))) {
          repos.push({ name: ent.name, fork: false, archived: false });
        }
      }
    }
  } catch (e) {
    errLog(`Could not retrieve repository list: ${sanitize(e.message)}`);
    if (config.repos.include?.length) repos = config.repos.include.map(name => ({ name, fork: false, archived: false }));
  }

  const seen = new Set(repos.map(r => r.name.toLowerCase()));
  for (const inc of config.repos.include || []) {
    if (!seen.has(inc.toLowerCase())) { repos.push({ name: inc, fork: false, archived: false }); seen.add(inc.toLowerCase()); }
  }

  const excludeSet = new Set([...(config.repos.exclude || []), ...(config.repos.skip || [])].map(r => r.toLowerCase()));
  const filtered = repos.filter(r => {
    const n = r.name.toLowerCase();
    return !excludeSet.has(n) && (config.repos.includeArchived || !r.archived) && (config.repos.includeForks || !r.fork) && (!publicOnly || !r.private);
  });

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-watch-'));
  const summary = {
    owner: config.owner,
    total: filtered.length,
    scannedTime: new Date().toISOString(),
    repos: [],
    failedRepos: [],
    changes: [],
    transformResults: [],
    totals: { vulns: 0, secrets: 0, historySecrets: 0, workflowRisks: 0, integrity: 0, githubAlerts: 0 },
  };

  try {
    for (const repoInfo of filtered) {
      const name = repoInfo.name;
      let repoDir = path.join(workDir, name);
      if (token) {
        try {
          if (doTransform && !isDryRun) cloneForPr(config.owner, name, repoDir, token);
          else cloneShallow(config.owner, name, repoDir, token);
        } catch (err) {
          warn(`Could not clone ${name}: ${sanitize(err.message)}`);
          summary.failedRepos.push({ name, reason: 'Clone failed or repository inaccessible' });
          continue;
        }
      } else {
        const localDir = path.join(path.dirname(__dirname), name);
        if (fs.existsSync(path.join(localDir, '.git'))) repoDir = localDir;
        else { summary.failedRepos.push({ name, reason: 'No local checkout and no GitHub token' }); continue; }
      }

      const repoCfg = applyRepoOverrides(config, repoDir);
      if (repoCfg.enabled === false) continue;

      const { metadata, findings } = scanRepository(repoDir, repoInfo, repoCfg.checks, repoCfg.allowlist);
      const deps = parseDependencies(repoDir);

      let osv = { status: 'skipped', checked: deps.length, findings: [] };
      if (repoCfg.checks.vulnerabilities !== false && !skipOsv && deps.length) {
        osv = await queryOsvVulnerabilities(deps);
        const ignoredVulns = new Set((repoCfg.allowlist?.ignoreVulns || []).map(v => String(v).toUpperCase()));
        if (ignoredVulns.size && osv.findings.length) {
          osv.findings = osv.findings.map(p => ({
            ...p,
            vulns: p.vulns.filter(v => !ignoredVulns.has(v.id.toUpperCase()) && !(v.cve && ignoredVulns.has(v.cve.toUpperCase()))),
          })).filter(p => p.vulns.length > 0);
        }
      }

      let githubAlerts = { dependabot: 0, codeScanning: 0, secretScanning: 0, vulnerabilityAlertsDisabled: false };
      if (token && repoCfg.checks.githubAlerts !== false) {
        try { githubAlerts = await client.countOpenAlerts(repoCfg.owner, name); }
        catch (e) { warn(`Could not read GitHub security alerts for ${name}: ${sanitize(e.message)}`); }
      }

      let posture = null;
      if (token && repoCfg.checks.posture !== false) {
        try { posture = await client.getRepoPosture(repoCfg.owner, name, repoInfo); }
        catch {}
      }

      const cveCount = osv.findings.reduce((n, f) => n + f.vulns.length, 0);
      const githubAlertsCount = githubAlerts.dependabot + githubAlerts.codeScanning + githubAlerts.secretScanning;

      const repoSummary = {
        name,
        metadata,
        posture,
        depCount: deps.length,
        osvStatus: osv.status,
        vulns: osv.findings,
        cveCount,
        githubAlerts,
        githubAlertsCount,
        vulnerabilityAlertsDisabled: githubAlerts.vulnerabilityAlertsDisabled,
        findings,
      };
      summary.repos.push(repoSummary);

      if (doAudit) {
        const tRes = await transformRepository({
          owner: repoCfg.owner,
          repoDir,
          repoMeta: repoInfo,
          scanResult: repoSummary,
          posture,
          client,
          token,
          dryRun: isDryRun || !doTransform,
          useAi,
        });
        summary.transformResults.push(tRes);
      }

      summary.totals.vulns += cveCount;
      summary.totals.secrets += findings.secrets.length;
      summary.totals.historySecrets += findings.historySecrets.length;
      summary.totals.workflowRisks += findings.workflowRisks.length;
      summary.totals.integrity += findings.integrity.length;
      summary.totals.githubAlerts += githubAlertsCount;
    }
  } finally {
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}
  }

  summary.snapshot = buildSnapshot(summary);
  summary.changes = diffSnapshots(prevSnapshot, summary.snapshot);

  if (snapshotPath && !isDryRun) {
    try { fs.writeFileSync(snapshotPath, JSON.stringify(summary.snapshot, null, 2) + '\n'); } catch {}
  }

  if (doAudit && writeReports && !isDryRun) {
    writePortfolioReports(path.join(__dirname, 'reports'), config.owner, summary.scannedTime, summary.transformResults);
  }

  const consoleReport = doAudit
    ? buildPortfolioAuditReport(config.owner, summary.scannedTime, summary.transformResults)
    : buildMarkdownReport(config, summary);
  if (asJson) process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  else console.log(consoleReport);

  const hasIssues =
    summary.totals.vulns > 0 || summary.totals.secrets > 0 || summary.totals.historySecrets > 0 ||
    summary.totals.workflowRisks > 0 || summary.totals.integrity > 0 ||
    summary.totals.githubAlerts > 0 || summary.failedRepos.length > 0 ||
    summary.repos.some(r => r.vulnerabilityAlertsDisabled);

  if (process.env.GITHUB_STEP_SUMMARY) {
    try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, consoleReport + '\n'); } catch {}
  }

  await notify(config, summary, hasIssues, isDryRun);

  if (process.env.REPORT !== '0' && !isDryRun && issueClient.token) {
    const dashboardTitle = 'watch: Security & Repo Monitor Dashboard';
    const issueBody = buildMarkdownReport(config, summary, { embedSnapshot: true });
    try {
      if (existingIssue) {
        await issueClient.updateIssue(config.owner, 'authormark-watch', existingIssue.number, {
          title: dashboardTitle, body: issueBody, state: hasIssues ? 'open' : 'closed',
        });
        await issueClient.addComment(config.owner, 'authormark-watch', existingIssue.number,
          `Scan completed at \`${summary.scannedTime}\`. Status: **${hasIssues ? 'Findings require attention' : 'All Clear'}**.`);
      } else if (hasIssues) {
        await issueClient.createIssue(config.owner, 'authormark-watch', dashboardTitle, issueBody, ['security']);
      }
    } catch (issueErr) { warn(`Could not update GitHub status issue: ${sanitize(issueErr.message)}`); }
  }
}

const isMain = (() => {
  try { return __filename === fs.realpathSync(process.argv[1]); } catch { return false; }
})();
if (isMain) {
  main().catch(err => { errLog(`Monitor execution error: ${err.stack || err.message}`); process.exit(1); });
}

export {
  loadConfig, applyRepoOverrides, sanitize, GitHubClient,
  scanRepository, walkFiles, auditWorkflow, scanGitHistory, SECRET_PATTERNS,
  parseDependencies, queryOsvVulnerabilities,
  buildSnapshot, extractSnapshotFromText, diffSnapshots, buildMarkdownReport,
  buildPortfolioAuditReport, writePortfolioReports,
  STANDARD_LABELS, detectStack, auditRepository,
  generateRepoPatches, transformRepository,
  createWebhookServer, verifyGitHubSignature,
};
