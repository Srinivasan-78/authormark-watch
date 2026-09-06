#!/usr/bin/env node
/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.BoiwJZbjiLA_i6gDLUcKoP
 */

/**
 * Master Bot & Account-Wide Repository Supervisor for @Srinivasan-78
 *
 * Capabilities:
 *  1. AuthorMark Code Watermarking & Signing (Detection + Automated Fix PRs)
 *  2. Multi-Language Code Linting & Repository Hygiene (Secrets, Syntax, Artifacts, Standards)
 *  3. Automated PR Tagging & Labeling (Size, Type, Languages, Workflow status)
 *  4. Automated Issue Tagging & Triage (Categories, Priorities, Needs-info, Good first issue)
 *  5. Consolidated Master Dashboard & Status Issue Management
 *
 * Zero dependencies. Node >= 18.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CWD = process.cwd();

const CONFIG_FILE = path.join(__dirname, 'bot.config.json');
const AM_SCRIPT = path.join(__dirname, 'authormark.mjs');

// ---------------------------------------------------------------- Configuration

function loadConfig() {
  const defaults = {
    owner: 'Srinivasan-78',
    repos: {
      include: [],
      exclude: ['wix-installer-template', 'ubisoft-game-notes', 'github-actions-snippets', 'study-brainrot-generator'],
      skip: ['authormark-watch'],
      includeForks: false,
      includeArchived: false,
    },
    features: {
      authormark: { enabled: true, autoFix: false, branch: 'authormark' },
      lint: { enabled: true, scanSecrets: true, scanHygiene: true, scanRepoHealth: true, autoFix: false },
      prTagger: { enabled: true, sizeLabels: true, typeLabels: true, langLabels: true, statusLabels: true, autoCreateLabels: true },
      issueTagger: { enabled: true, categoryLabels: true, priorityLabels: true, triageLabel: true, autoCreateLabels: true },
    },
    botIdentity: {
      name: 'github-actions[bot]',
      email: '41898282+github-actions[bot]@users.noreply.github.com',
      author: 'Srinivasan Vijayaraghavan',
      authorEmail: 'srinivasan.shyam2000@gmail.com',
      github: 'https://github.com/Srinivasan-78',
    },
    labelPalette: {},
    notify: {},
  };

  if (fs.existsSync(CONFIG_FILE)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      return {
        ...defaults,
        ...parsed,
        repos: { ...defaults.repos, ...(parsed.repos || {}) },
        features: { ...defaults.features, ...(parsed.features || {}) },
        botIdentity: { ...defaults.botIdentity, ...(parsed.botIdentity || {}) },
        labelPalette: { ...defaults.labelPalette, ...(parsed.labelPalette || {}) },
        notify: { ...defaults.notify, ...(parsed.notify || {}) },
      };
    } catch (e) {
      console.warn(`[warn] Failed to parse bot.config.json: ${e.message}. Using defaults.`);
    }
  }
  return defaults;
}

// A repo may ship its own `.masterbot.json` to override feature flags for
// itself only (shallow merge of the `features` and `repos` sub-trees).
function applyRepoOverrides(config, repoDir) {
  const p = path.join(repoDir, '.masterbot.json');
  if (!fs.existsSync(p)) return config;
  try {
    const o = JSON.parse(fs.readFileSync(p, 'utf8'));
    return {
      ...config,
      ...o,
      features: {
        authormark: { ...config.features.authormark, ...(o.features?.authormark || {}) },
        lint: { ...config.features.lint, ...(o.features?.lint || {}) },
        prTagger: { ...config.features.prTagger, ...(o.features?.prTagger || {}) },
        issueTagger: { ...config.features.issueTagger, ...(o.features?.issueTagger || {}) },
      },
    };
  } catch {
    warn(`ignored malformed .masterbot.json in ${path.basename(repoDir)}`);
    return config;
  }
}

// ---------------------------------------------------------------- Logger & Helpers

function log(msg) { console.log(msg); }
function warn(msg) { console.warn(`::warning::${msg}`); }
function errLog(msg) { console.error(`::error::${msg}`); }

function sanitize(text) {
  if (!text) return '';
  return String(text).replace(/(gh[pousr]_|github_pat_)[A-Za-z0-9_]+/g, '***');
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Exponential backoff with full jitter, capped at 30s.
function backoffMs(attempt) {
  return Math.min(30000, Math.round((2 ** attempt) * 500 * (0.5 + Math.random())));
}

// Prefer the server's own guidance (Retry-After seconds, or the epoch in
// x-ratelimit-reset) over blind backoff; fall back to exponential.
function rateLimitDelayMs(res, attempt) {
  const ra = Number(res.headers.get('retry-after'));
  if (Number.isFinite(ra) && ra > 0) return Math.min(60000, ra * 1000);
  const reset = Number(res.headers.get('x-ratelimit-reset'));
  if (Number.isFinite(reset) && reset > 0) {
    const wait = reset * 1000 - Date.now();
    if (wait > 0) return Math.min(60000, wait + 1000);
  }
  return backoffMs(attempt);
}

function resolveToken() {
  if (process.env.BOT_TOKEN) return process.env.BOT_TOKEN;
  if (process.env.WATCH_TOKEN) return process.env.WATCH_TOKEN;
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN;
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;

  // Try extracting from gh CLI if available
  try {
    const out = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (out) return out;
  } catch {}

  return null;
}

function resolveIssueToken() {
  if (process.env.ISSUE_TOKEN) return process.env.ISSUE_TOKEN;
  return resolveToken();
}

// Post a one-line status to Slack and/or Discord when there is something to
// report. Webhook URLs come from config.notify.{slack,discord} or the
// SLACK_WEBHOOK / DISCORD_WEBHOOK env vars.
async function notify(config, summary, hasIssues, isDryRun) {
  if (isDryRun || !hasIssues) return;
  const slack = config.notify?.slack || process.env.SLACK_WEBHOOK;
  const discord = config.notify?.discord || process.env.DISCORD_WEBHOOK;
  if (!slack && !discord) return;

  const am = summary.authormark;
  const parts = [];
  if (am.drifted.length + am.unmarked.length) parts.push(`${am.drifted.length + am.unmarked.length} watermark`);
  if (summary.lintFindings.length) parts.push(`${summary.lintFindings.length} hygiene`);
  if (summary.securityAlerts.length) parts.push(`${summary.securityAlerts.length} security`);
  if (summary.failedRepos.length) parts.push(`${summary.failedRepos.length} unreachable`);
  const text = `*Master Bot* (@${config.owner}) — ${parts.join(', ')} finding(s) across ${summary.total} repos. ` +
    `See the dashboard issue in authormark-watch.`;

  const post = (url, body) => fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }).catch(e => warn(`notify failed: ${sanitize(e.message)}`));

  if (slack) await post(slack, { text });
  if (discord) await post(discord, { content: text.replace(/\*/g, '**') });
}

// ---------------------------------------------------------------- GitHub REST API Client

class GitHubClient {
  constructor(token) {
    this.token = token;
    this.baseUrl = 'https://api.github.com';
    this.labelCache = new Map(); // repo -> Set of label names
  }

  async request(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`;
    const headers = {
      Accept: 'application/vnd.github.v3+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'AuthorMark-MasterBot/1.0 (+https://github.com/Srinivasan-78/authormark-watch)',
      ...(options.headers || {}),
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    const maxAttempts = options.retries ?? 4;
    let lastErr = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      let res;
      try {
        res = await fetch(url, { ...options, headers });
      } catch (e) {
        // Network blip: back off and retry.
        lastErr = new Error(`GitHub API Error: ${sanitize(e.message)}`);
        if (attempt < maxAttempts) { await sleep(backoffMs(attempt)); continue; }
        throw lastErr;
      }

      if (res.status === 204) return null;

      // Primary/secondary rate limits and transient server errors are retryable.
      const retryable = res.status === 429 || res.status >= 500 ||
        (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0');
      if (retryable && attempt < maxAttempts) {
        await sleep(rateLimitDelayMs(res, attempt));
        continue;
      }

      const data = await res.json().catch(() => null);
      if (!res.ok) {
        const msg = data && data.message ? data.message : `HTTP ${res.status}`;
        throw new Error(`${options.method || 'GET'} ${endpoint} failed (${res.status}): ${sanitize(msg)}`);
      }
      return data;
    }

    throw lastErr || new Error(`GitHub API Error: exhausted retries for ${endpoint}`);
  }

  // Full PR payload -- the list endpoint omits additions/deletions/changed_files.
  async getPullRequest(owner, repo, pullNumber) {
    return this.request(`/repos/${owner}/${repo}/pulls/${pullNumber}`);
  }

  // GitHub-native security alerts. Each may 403 (feature off / token scope) --
  // the caller treats a throw as "unknown", not "zero".
  async countOpenAlerts(owner, repo) {
    const result = { dependabot: 0, codeScanning: 0, secretScanning: 0, vulnerabilityAlertsDisabled: false };
    try {
      const d = await this.request(`/repos/${owner}/${repo}/dependabot/alerts?state=open&per_page=100`, { retries: 1 });
      result.dependabot = Array.isArray(d) ? d.length : 0;
    } catch {}
    try {
      const c = await this.request(`/repos/${owner}/${repo}/code-scanning/alerts?state=open&per_page=100`, { retries: 1 });
      result.codeScanning = Array.isArray(c) ? c.length : 0;
    } catch {}
    try {
      const s = await this.request(`/repos/${owner}/${repo}/secret-scanning/alerts?state=open&per_page=100`, { retries: 1 });
      result.secretScanning = Array.isArray(s) ? s.length : 0;
    } catch {}
    try {
      // 204 = enabled, 404 = disabled
      await this.request(`/repos/${owner}/${repo}/vulnerability-alerts`, { retries: 1 });
    } catch (e) {
      if (/\(404\)/.test(e.message)) result.vulnerabilityAlertsDisabled = true;
    }
    return result;
  }

  // Resolve a tag/branch ref to a full commit SHA (for pinning `uses:` lines).
  async resolveRef(owner, repo, ref) {
    try {
      const c = await this.request(`/repos/${owner}/${repo}/commits/${ref}`, { retries: 1 });
      return c && c.sha ? c.sha : null;
    } catch { return null; }
  }

  async listRepos(owner) {
    const repos = [];
    let page = 1;
    // With a token, use /user/repos so PRIVATE repos owned by the authenticated
    // user are included. /users/{owner}/repos only ever returns public repos,
    // even when authenticated as that same user.
    const base = this.token
      ? `/user/repos?affiliation=owner&per_page=100&sort=pushed`
      : `/users/${owner}/repos?per_page=100&sort=pushed`;
    while (true) {
      const batch = await this.request(`${base}&page=${page}`);
      if (!Array.isArray(batch) || batch.length === 0) break;
      // /user/repos can span multiple owners; keep only this owner's repos.
      for (const r of batch) {
        if (!r.owner || String(r.owner.login).toLowerCase() === String(owner).toLowerCase()) {
          repos.push(r);
        }
      }
      if (batch.length < 100) break;
      page++;
    }
    return repos;
  }

  async getRepo(owner, repo) {
    return this.request(`/repos/${owner}/${repo}`);
  }

  async listPullRequests(owner, repo, state = 'open') {
    return (await this.request(`/repos/${owner}/${repo}/pulls?state=${state}&per_page=100`)) || [];
  }

  async getPullRequestFiles(owner, repo, pullNumber) {
    return (await this.request(`/repos/${owner}/${repo}/pulls/${pullNumber}/files?per_page=100`)) || [];
  }

  async listIssues(owner, repo, state = 'open') {
    const items = (await this.request(`/repos/${owner}/${repo}/issues?state=${state}&per_page=100`)) || [];
    // GitHub Issues API includes Pull Requests; filter them out
    return items.filter(it => !it.pull_request);
  }

  async listRepoLabels(owner, repo) {
    const key = `${owner}/${repo}`;
    if (this.labelCache.has(key)) return this.labelCache.get(key);
    try {
      const list = (await this.request(`/repos/${owner}/${repo}/labels?per_page=100`)) || [];
      const set = new Set(list.map(l => l.name.toLowerCase()));
      this.labelCache.set(key, set);
      return set;
    } catch {
      return new Set();
    }
  }

  async ensureLabel(owner, repo, labelName, palette) {
    const key = `${owner}/${repo}`;
    const existing = await this.listRepoLabels(owner, repo);
    if (existing.has(labelName.toLowerCase())) return;

    const meta = palette[labelName] || { color: 'cfd3d7', description: `Managed by Master Bot` };
    try {
      await this.request(`/repos/${owner}/${repo}/labels`, {
        method: 'POST',
        body: JSON.stringify({
          name: labelName,
          color: meta.color.replace(/^#/, ''),
          description: meta.description || '',
        }),
      });
      existing.add(labelName.toLowerCase());
      this.labelCache.set(key, existing);
    } catch (e) {
      // If label exists under different casing or concurrent race, ignore
    }
  }

  async addLabels(owner, repo, issueOrPrNumber, labels) {
    if (!labels || labels.length === 0) return;
    return this.request(`/repos/${owner}/${repo}/issues/${issueOrPrNumber}/labels`, {
      method: 'POST',
      body: JSON.stringify({ labels }),
    });
  }

  async findTrackingIssue(owner, repo, titlePrefix) {
    try {
      const issues = (await this.request(`/repos/${owner}/${repo}/issues?state=open&per_page=50`)) || [];
      return issues.find(i => !i.pull_request && i.title.startsWith(titlePrefix));
    } catch {
      return null;
    }
  }

  async createIssue(owner, repo, title, body, labels = []) {
    return this.request(`/repos/${owner}/${repo}/issues`, {
      method: 'POST',
      body: JSON.stringify({ title, body, labels }),
    });
  }

  async updateIssue(owner, repo, issueNumber, { title, body, state }) {
    const payload = {};
    if (title !== undefined) payload.title = title;
    if (body !== undefined) payload.body = body;
    if (state !== undefined) payload.state = state;
    return this.request(`/repos/${owner}/${repo}/issues/${issueNumber}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }

  async addComment(owner, repo, issueNumber, body) {
    return this.request(`/repos/${owner}/${repo}/issues/${issueNumber}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body }),
    });
  }

  // Classify the newest PR for `branchRef`, looking across every state so a
  // merged / closed-unmerged PR is distinguishable from "no PR at all".
  async findBranchPr(owner, repo, branchRef) {
    const all = await this.listPullRequests(owner, repo, 'all');
    return classifyBranchPr(all, branchRef);
  }

  async reopenPullRequest(owner, repo, pullNumber) {
    return this.request(`/repos/${owner}/${repo}/pulls/${pullNumber}`, {
      method: 'PATCH',
      body: JSON.stringify({ state: 'open' }),
    });
  }

  // How many commits `head` is ahead of `base`. 0 means the branch carries
  // nothing new -- its work already landed. Any error is treated as "unknown"
  // (returns null) so callers can fall back to opening a PR.
  async commitsAhead(owner, repo, base, head) {
    try {
      const cmp = await this.request(`/repos/${owner}/${repo}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`);
      return cmp && typeof cmp.ahead_by === 'number' ? cmp.ahead_by : null;
    } catch {
      return null;
    }
  }
}

// Given the PR list from listPullRequests(..., 'all'), report the status of the
// newest PR whose head branch is `branchRef`:
//   MERGED  the change reached the base branch -- this criterion is satisfied
//   OPEN    a PR is up but NOT merged yet -- still blocking, keep re-flagging
//   CLOSED  a PR was closed without merging -- needs a reopen or a fresh PR
//   NONE    no PR was ever opened for this branch
function classifyBranchPr(prs, branchRef) {
  const matches = (prs || [])
    .filter(p => p && p.head && p.head.ref === branchRef)
    .sort((a, b) => (b.number || 0) - (a.number || 0));
  const pr = matches[0];
  if (!pr) return { status: 'NONE', pr: null };
  if (pr.merged_at) return { status: 'MERGED', pr };
  if (pr.state === 'open') return { status: 'OPEN', pr };
  return { status: 'CLOSED', pr };
}

// Ensure an OPEN, mergeable PR exists for `branch`: reuse an open one, reopen one
// that was closed unmerged, or open a fresh one. The returned `merged`/`awaiting`
// flags let the caller keep a repo on the "still blocking" list until its change
// actually lands on the default branch -- a PR merely existing is not "done".
async function ensureFixPr(client, owner, repo, branch, prSpec) {
  const found = await client.findBranchPr(owner, repo, branch);
  const base = prSpec.base || 'main';

  if (found.status === 'MERGED') {
    // A same-named PR merged before -- but the branch may have been re-pushed
    // with fresh work since. Only call it done when nothing is ahead of base.
    const ahead = await client.commitsAhead(owner, repo, base, branch);
    if (ahead === 0) {
      log(`    ✅ PR #${found.pr.number} already merged and no new commits — ${found.pr.html_url}`);
      return { url: found.pr.html_url, pr: found.pr, merged: true, awaiting: false, action: 'Already merged' };
    }
    log(`    🔁 PR #${found.pr.number} merged earlier but \`${branch}\` has new commits — opening a fresh PR`);
    // fall through to open a new PR
  } else if (found.status === 'OPEN') {
    log(`    ⏳ PR #${found.pr.number} already exists but is NOT merged yet — ${found.pr.html_url}`);
    return { url: found.pr.html_url, pr: found.pr, merged: false, awaiting: true, action: 'Updated PR' };
  }

  if (found.status === 'CLOSED') {
    try {
      const re = await client.reopenPullRequest(owner, repo, found.pr.number);
      const url = (re && re.html_url) || found.pr.html_url;
      log(`    ♻️ Reopened PR #${found.pr.number} — was closed without merging — ${url}`);
      return { url, pr: found.pr, merged: false, awaiting: true, action: 'Reopened PR' };
    } catch (e) {
      warn(`Could not reopen PR #${found.pr.number} for ${repo}: ${e.message} — opening a fresh PR`);
    }
  }

  const newPr = await client.request(`/repos/${owner}/${repo}/pulls`, {
    method: 'POST',
    body: JSON.stringify(prSpec),
  });
  log(`    🔀 Opened PR #${newPr.number} — ${newPr.html_url} (awaiting merge)`);
  return { url: newPr.html_url, pr: newPr, merged: false, awaiting: true, action: 'Opened PR' };
}

// ---------------------------------------------------------------- Multi-Language Lint & Hygiene

const LINT_SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', 'out', 'coverage',
  '.turbo', '.vercel', 'vendor', '__pycache__', 'venv', '.venv',
  'site-packages', 'third_party', 'target', '.mypy_cache', '.cache',
]);

const SECRET_PATTERNS = [
  { name: 'GitHub Personal Access Token', regex: /(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{82})/ },
  { name: 'Google / Firebase API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: 'Google OAuth Client Secret', regex: /GOCSPX-[A-Za-z0-9_-]{28}/ },
  { name: 'AWS Access Key ID', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/ },
  // Real PEM keys read "BEGIN RSA PRIVATE KEY" / "BEGIN OPENSSH PRIVATE KEY" etc.
  { name: 'Private Key', regex: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/ },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z_]+\/B[0-9A-Z_]+\/[0-9A-Za-z]+/ },
  { name: 'Discord Webhook', regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/ },
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'npm Access Token', regex: /npm_[A-Za-z0-9]{36}/ },
  { name: 'Generic JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
];

function walkFiles(dir, acc = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return acc; }

  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const fullPath = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (LINT_SKIP_DIRS.has(e.name)) continue;
      if (e.name.startsWith('.') && e.name !== '.github') continue;
      walkFiles(fullPath, acc);
    } else if (e.isFile()) {
      acc.push(fullPath);
    }
  }
  return acc;
}

// Best-effort GitHub Actions security audit -- string heuristics, no YAML parser.
// Returns an array of human-readable risk strings for one workflow file.
function auditWorkflow(text, file) {
  const risks = [];
  const lines = text.split('\n');
  const has = re => re.test(text);

  // 1. pull_request_target + a checkout of attacker-controlled PR code
  if (has(/^\s*pull_request_target\s*:/m) &&
      has(/uses:\s*actions\/checkout/) &&
      has(/ref:\s*\$\{\{\s*github\.event\.pull_request\.head/)) {
    risks.push(`\`${file}\`: \`pull_request_target\` checks out PR head code — runs untrusted code with a write token`);
  }

  // 2. Unpinned actions (tag/branch instead of a full commit SHA)
  const unpinned = new Set();
  for (const m of text.matchAll(/uses:\s*([^\s#'"]+)@([^\s#'"]+)/g)) {
    const [, action, ref] = m;
    if (action.startsWith('./') || action.startsWith('docker://')) continue;
    if (/^[0-9a-f]{40}$/.test(ref)) continue;
    unpinned.add(`${action}@${ref}`);
  }
  if (unpinned.size) risks.push(`\`${file}\`: ${unpinned.size} action(s) pinned to a tag, not a SHA: ${[...unpinned].slice(0, 6).join(', ')}`);

  // 3. Token scope
  if (has(/permissions:\s*write-all/)) risks.push(`\`${file}\`: \`permissions: write-all\` — grant least privilege instead`);
  else if (!has(/^\s*permissions\s*:/m)) risks.push(`\`${file}\`: no top-level \`permissions:\` — the job gets the default broad \`GITHUB_TOKEN\``);

  // 4. Script injection: untrusted event data interpolated into a shell step
  const risky = /\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|pull_request\.head\.label|comment\.body|review\.body|head_commit\.message|pages|commits)/;
  let inRun = false;
  for (const l of lines) {
    if (/^\s*(-\s*)?run:\s*[|>]?/.test(l)) inRun = true;
    else if (inRun && /^\s*\S/.test(l) && !/^\s+/.test(l.replace(/^\s*-\s*/, ''))) inRun = false;
    if (inRun && risky.test(l)) {
      risks.push(`\`${file}\`: untrusted \`\${{ github.event.* }}\` used in a \`run:\` step — inject via an env: var instead`);
      break;
    }
  }

  // 5. curl | sh
  if (has(/(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b/)) {
    risks.push(`\`${file}\`: pipes a network download straight into a shell`);
  }

  return risks;
}

// Rewrite `uses: owner/repo@tag` -> `uses: owner/repo@<sha>  # tag`, using a
// pre-resolved Map of "owner/repo@ref" -> sha. Pure; returns { text, changes }.
function pinWorkflowActions(text, shaMap) {
  const changes = [];
  const out = text.replace(/(\buses:\s*)([^\s#'"]+)@([^\s#'"]+)([^\n]*)/g, (m, pre, action, ref, rest) => {
    if (/^[0-9a-f]{40}$/.test(ref) || action.startsWith('./') || action.startsWith('docker://')) return m;
    const sha = shaMap.get(`${action}@${ref}`);
    if (!sha) return m;
    changes.push(`${action}@${ref} -> ${sha.slice(0, 12)}`);
    const trailing = /#/.test(rest) ? rest.replace(/#.*/, `# ${ref}`) : `${rest}  # ${ref}`;
    return `${pre}${action}@${sha}${trailing}`;
  });
  return { text: out, changes };
}

// Resolve every unpinned action ref in .github/workflows/* and rewrite the files.
async function pinActionsOnDisk(repoDir, client) {
  const dir = path.join(repoDir, '.github', 'workflows');
  if (!fs.existsSync(dir)) return 0;
  const wanted = new Set();
  const texts = {};
  for (const f of fs.readdirSync(dir)) {
    if (!/\.ya?ml$/.test(f)) continue;
    const t = fs.readFileSync(path.join(dir, f), 'utf8');
    texts[f] = t;
    for (const m of t.matchAll(/uses:\s*([^\s#'"]+)@([^\s#'"]+)/g)) {
      const [, action, ref] = m;
      if (/^[0-9a-f]{40}$/.test(ref) || action.startsWith('./') || action.startsWith('docker://')) continue;
      if (action.split('/').length < 2) continue;
      wanted.add(`${action}@${ref}`);
    }
  }
  const shaMap = new Map();
  for (const key of wanted) {
    const at = key.lastIndexOf('@');
    const action = key.slice(0, at), ref = key.slice(at + 1);
    const [o, r] = action.split('/');
    const sha = await client.resolveRef(o, r, ref);
    if (sha) shaMap.set(key, sha);
  }
  let total = 0;
  for (const [f, t] of Object.entries(texts)) {
    const { text: next, changes } = pinWorkflowActions(t, shaMap);
    if (changes.length) { fs.writeFileSync(path.join(dir, f), next); total += changes.length; }
  }
  return total;
}

const HISTORY_SECRET_RE = 'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_\\-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk_live_[0-9a-zA-Z]{24}';

// Look for secrets that were committed and later removed -- still recoverable
// from history. Prefilter with `git log -G` so we only `show` candidate commits.
function scanGitHistory(repoDir) {
  const out = [];
  try {
    const shas = execSync(
      `git log --all --no-merges -n 400 --format=%H -G"${HISTORY_SECRET_RE}"`,
      { cwd: repoDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).split('\n').filter(Boolean).slice(0, 15);
    const re = new RegExp(HISTORY_SECRET_RE);
    for (const sha of shas) {
      let diff = '';
      try {
        diff = execSync(`git show --no-color --format= ${sha}`, { cwd: repoDir, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
      } catch { continue; }
      let file = '';
      for (const l of diff.split('\n')) {
        const fm = l.match(/^\+\+\+ b\/(.+)/);
        if (fm) { file = fm[1]; continue; }
        if (l.startsWith('+') && !l.startsWith('+++') && re.test(l) && !/\.(md|test|spec|example|sample)\b/.test(file)) {
          out.push(`Secret-shaped string in \`${file}\` at commit \`${sha.slice(0, 10)}\` (still in history)`);
          break;
        }
      }
      if (out.length >= 10) break;
    }
  } catch {}
  return out;
}

function lintRepository(repoDir, repoName) {
  const findings = {
    secrets: [],
    syntaxErrors: [],
    unwantedArtifacts: [],
    standards: [],
    whitespaceIssues: [],
    workflowRisks: [],
    historySecrets: [],
  };

  const files = walkFiles(repoDir);
  const rel = f => path.relative(repoDir, f).replace(/\\/g, '/');

  // 0. GitHub Actions workflow security audit + secrets in git history
  const wfDir = path.join(repoDir, '.github', 'workflows');
  if (fs.existsSync(wfDir)) {
    for (const wf of fs.readdirSync(wfDir)) {
      if (!/\.ya?ml$/.test(wf)) continue;
      try {
        for (const risk of auditWorkflow(fs.readFileSync(path.join(wfDir, wf), 'utf8'), `.github/workflows/${wf}`)) {
          findings.workflowRisks.push(risk);
        }
      } catch {}
    }
  }
  for (const h of scanGitHistory(repoDir)) findings.historySecrets.push(h);

  // 1. Repo Health Standards
  const hasFile = name => fs.existsSync(path.join(repoDir, name));
  const licenses = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'LICENCE.md'];
  if (!licenses.some(hasFile)) {
    findings.standards.push('Missing `LICENSE` file');
  }
  if (!hasFile('README.md') && !hasFile('readme.md')) {
    findings.standards.push('Missing `README.md` file');
  } else {
    try {
      const readmeContent = fs.readFileSync(path.join(repoDir, hasFile('README.md') ? 'README.md' : 'readme.md'), 'utf8').trim();
      if (readmeContent.length < 30) {
        findings.standards.push('`README.md` is empty or lacks substantive content');
      }
    } catch {}
  }
  if (!hasFile('.gitignore')) {
    findings.standards.push('Missing `.gitignore` file');
  }
  if (!hasFile('AGENTS.md') && !hasFile('CLAUDE.md')) {
    findings.standards.push('Missing AI Agent guidance rules (`AGENTS.md` / `CLAUDE.md`)');
  }
  // SECURITY.md is valid at the root, in .github/, or in docs/ (GitHub reads all three).
  if (!['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'].some(hasFile)) {
    findings.standards.push('Missing `SECURITY.md` disclosure policy');
  }
  if (!['CONTRIBUTING.md', '.github/CONTRIBUTING.md', 'docs/CONTRIBUTING.md'].some(hasFile)) {
    findings.standards.push('Missing `CONTRIBUTING.md`');
  }
  if (!hasFile('.github/dependabot.yml') && !hasFile('.github/dependabot.yaml')) {
    findings.standards.push('No Dependabot config (`.github/dependabot.yml`)');
  } else {
    const dbRel = hasFile('.github/dependabot.yml') ? '.github/dependabot.yml' : '.github/dependabot.yaml';
    try {
      const dbContent = fs.readFileSync(path.join(repoDir, dbRel), 'utf8');
      if (dbContent.includes('package-ecosystem') && !dbContent.includes('groups:')) {
        findings.standards.push('Dependabot config is not grouped (ungrouped updates pile up and conflict)');
      }
    } catch {}
  }

  // 1b. Licence consistency: package.json `license` vs the SPDX headers / LICENSE.
  try {
    const pkgPath = path.join(repoDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const declared = (JSON.parse(fs.readFileSync(pkgPath, 'utf8')).license || '').trim();
      if (declared) {
        const licenseText = licenses.map(l => path.join(repoDir, l)).filter(fs.existsSync)
          .map(p => fs.readFileSync(p, 'utf8')).join('\n');
        const looksMIT = /MIT License|Permission is hereby granted, free of charge/i.test(licenseText);
        const looksApache = /Apache License/i.test(licenseText);
        if (looksMIT && !/^MIT$/i.test(declared)) {
          findings.standards.push(`\`package.json\` says license "${declared}" but LICENSE is MIT`);
        } else if (looksApache && !/apache/i.test(declared)) {
          findings.standards.push(`\`package.json\` says license "${declared}" but LICENSE is Apache-2.0`);
        }
      }
    }
  } catch {}

  // 2. Scan Individual Files
  for (const file of files) {
    const rPath = rel(file);
    const basename = path.basename(file);
    const ext = path.extname(file).toLowerCase();

    // Check unwanted tracked files/artifacts
    if (basename.endsWith('.pyc') || rPath.includes('__pycache__')) {
      findings.unwantedArtifacts.push(`Tracked Python bytecode: \`${rPath}\``);
    }
    if (basename === '.DS_Store' || basename === 'Thumbs.db') {
      findings.unwantedArtifacts.push(`OS metadata file: \`${rPath}\``);
    }
    if (basename === '.env' || basename === '.env.local' || basename === '.env.production') {
      findings.secrets.push(`Committed environment file containing possible secrets: \`${rPath}\``);
    }

    // Skip scanning large binary files
    try {
      const stat = fs.statSync(file);
      if (stat.size > 2 * 1024 * 1024) continue; // skip files > 2MB
    } catch {
      continue;
    }

    let content = '';
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue; // binary or unreadable
    }

    // Secrets scan
    for (const pat of SECRET_PATTERNS) {
      if (pat.regex.test(content)) {
        // Skip obvious sample or documentation placeholders
        if (!content.includes('AIzaSyDummy') && !content.includes('your-api-key') && !rPath.endsWith('.md')) {
          findings.secrets.push(`Possible ${pat.name} in \`${rPath}\``);
        }
      }
    }

    // Syntax validation
    if (ext === '.json' && !basename.includes('package-lock') && !basename.includes('tsconfig')) {
      try {
        JSON.parse(content);
      } catch (err) {
        findings.syntaxErrors.push(`Invalid JSON syntax in \`${rPath}\`: ${err.message}`);
      }
    }

    // Line hygiene (check for trailing carriage returns in non-windows configs or trailing whitespace)
    if (['.js', '.ts', '.jsx', '.tsx', '.py', '.rs', '.go', '.sh'].includes(ext)) {
      const lines = content.split('\n');
      let trailingWsCount = 0;
      for (const l of lines) {
        if (/[ \t]+$/.test(l.replace(/\r$/, ''))) trailingWsCount++;
      }
      if (trailingWsCount > 10) {
        findings.whitespaceIssues.push(`\`${rPath}\` has ${trailingWsCount} lines with trailing whitespace`);
      }
    }
  }

  return findings;
}

const STANDARD_GITIGNORE = `# Operating System Files
.DS_Store
Thumbs.db

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.venv/
.pytest_cache/
.mypy_cache/

# Node.js & Web
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.next/
dist/
build/
out/
.turbo/
.cache/

# Environment Variables & Secrets
.env
.env.local
.env.development.local
.env.test.local
.env.production.local
`;

// Grouped Dependabot config: a single catch-all group per ecosystem, so every
// bump -- major, minor and patch alike -- lands in one PR instead of Dependabot
// opening a separate lockfile-touching PR per dependency that then conflict with
// each other. `patterns: ["*"]` with no `update-types` filter sweeps in majors
// too; review the one combined PR rather than a dozen.
function buildDependabotConfig(ecosystems) {
  const ecos = ecosystems && ecosystems.length ? ecosystems : ['github-actions'];
  return `version: 2\nupdates:\n` + ecos.map(e =>
    `  - package-ecosystem: "${e}"\n` +
    `    directory: "/"\n` +
    `    schedule:\n      interval: "weekly"\n` +
    `    open-pull-requests-limit: 10\n` +
    `    groups:\n` +
    `      ${e}-all:\n` +
    `        patterns: ["*"]\n` +
    `        update-types: ["major", "minor", "patch"]\n`
  ).join('');
}

// Auto-merge Dependabot PRs once required checks pass -- majors excluded.
const DEPENDABOT_AUTOMERGE_WORKFLOW = `name: Dependabot auto-merge
on: pull_request
permissions:
  contents: write
  pull-requests: write
jobs:
  automerge:
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: dependabot/fetch-metadata@v2
        id: meta
        with:
          github-token: "\${{ secrets.GITHUB_TOKEN }}"
      - if: steps.meta.outputs.update-type != 'version-update:semver-major'
        run: gh pr merge --auto --squash "\${{ github.event.pull_request.html_url }}"
        env:
          GH_TOKEN: "\${{ secrets.GITHUB_TOKEN }}"
`;

function fixLintRepository(repoDir, repoName, config, token, branch = 'masterbot-hygiene') {
  const owner = config.owner;
  const botName = config.botIdentity.name;
  const botEmail = config.botIdentity.email;
  const author = config.botIdentity.author;
  const year = new Date().getFullYear();

  const changesMade = [];
  // Files this run scaffolds from scratch. They are written without an
  // `@authormark` header, so any repo that runs `authormark check` as a merge
  // gate would reject them -- stamp them before committing (see step 5c).
  const createdFiles = [];

  try {
    // 0. Ensure branch is checked out
    try {
      execSync('git fetch --unshallow origin', { cwd: repoDir, stdio: 'ignore' });
    } catch {}
    execSync(`git checkout -B "${branch}"`, { cwd: repoDir, stdio: 'ignore' });

    // 0b. Materialise the signing key from the environment if CI provided it,
    // so the stamp pass in step 5c writes a real keyed fingerprint.
    const keyPath = path.join(os.homedir(), '.authormark.key');
    if (!fs.existsSync(keyPath) && process.env.AUTHORMARK_KEY) {
      try {
        fs.writeFileSync(keyPath, process.env.AUTHORMARK_KEY.trim() + '\n', { mode: 0o600 });
      } catch {}
    }

    // 1. Remove unwanted tracked files (bytecode, OS files)
    let tracked = [];
    try {
      tracked = execSync('git ls-files', { cwd: repoDir, encoding: 'utf8' }).split('\n');
    } catch {}

    for (const file of tracked) {
      if (!file) continue;
      const bname = path.basename(file);
      if (bname.endsWith('.pyc') || file.includes('__pycache__') || bname === '.DS_Store' || bname === 'Thumbs.db') {
        try {
          execSync(`git rm -f --ignore-unmatch "${file}"`, { cwd: repoDir, stdio: 'ignore' });
          changesMade.push(`Removed tracked artifact: \`${file}\``);
        } catch {}
      }
    }

    // 2. Fix / Create .gitignore
    const gitignorePath = path.join(repoDir, '.gitignore');
    if (!fs.existsSync(gitignorePath)) {
      fs.writeFileSync(gitignorePath, STANDARD_GITIGNORE);
      changesMade.push('Created standard `.gitignore`');
    } else {
      let giContent = fs.readFileSync(gitignorePath, 'utf8');
      const additions = [];
      if (!giContent.includes('__pycache__')) additions.push('__pycache__/', '*.py[cod]');
      if (!giContent.includes('.DS_Store')) additions.push('.DS_Store', 'Thumbs.db');
      if (!giContent.includes('node_modules') && fs.existsSync(path.join(repoDir, 'package.json'))) additions.push('node_modules/');
      if (!giContent.includes('.env')) additions.push('.env', '.env.local');

      if (additions.length > 0) {
        giContent += '\n# Master Bot hygiene additions\n' + additions.join('\n') + '\n';
        fs.writeFileSync(gitignorePath, giContent);
        changesMade.push('Added missing security and cache ignore rules to `.gitignore`');
      }
    }

    // 3. Fix / Create LICENSE
    const hasLicense = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'LICENCE.md'].some(f => fs.existsSync(path.join(repoDir, f)));
    if (!hasLicense) {
      const mit = `MIT License\n\nCopyright (c) ${year} ${author}\n${config.botIdentity.github}\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the "Software"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n`;
      fs.writeFileSync(path.join(repoDir, 'LICENSE'), mit);
      changesMade.push('Created standard `LICENSE` (MIT)');
    }

    // 4. Fix / Create README.md
    if (!fs.existsSync(path.join(repoDir, 'README.md')) && !fs.existsSync(path.join(repoDir, 'readme.md'))) {
      const readme = `# ${repoName}\n\nRepository maintained by [@${owner}](https://github.com/${owner}).\n`;
      fs.writeFileSync(path.join(repoDir, 'README.md'), readme);
      createdFiles.push('README.md');
      changesMade.push('Created initial `README.md`');
    }

    // 5. Fix / Create AGENTS.md / CLAUDE.md
    if (!fs.existsSync(path.join(repoDir, 'AGENTS.md')) && !fs.existsSync(path.join(repoDir, 'CLAUDE.md'))) {
      const agents = `# Repo rules\n\n## Authorship headers — never remove\n\nSource files in this repo begin with an \`@authormark v1\` comment block (copyright, author URL, SPDX line, and a keyed \`Fingerprint:\`). It is a watermark, not boilerplate.\n\n- Never delete, edit, reorder, or relocate that block.\n- When you move or rename a file, the header moves with it.\n- CI runs checks on every PR.\n`;
      const claude = `# Repo rules\n\n@AGENTS.md\n`;
      fs.writeFileSync(path.join(repoDir, 'AGENTS.md'), agents);
      fs.writeFileSync(path.join(repoDir, 'CLAUDE.md'), claude);
      createdFiles.push('AGENTS.md', 'CLAUDE.md');
      changesMade.push('Created `AGENTS.md` and `CLAUDE.md` rules');
    }

    // 5b. Community-health scaffolds
    const ghDir = path.join(repoDir, '.github');
    if (!['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'].some(f => fs.existsSync(path.join(repoDir, f)))) {
      fs.mkdirSync(ghDir, { recursive: true });
      fs.writeFileSync(path.join(ghDir, 'SECURITY.md'),
        `# Security Policy\n\n## Reporting a Vulnerability\n\nPlease report security issues privately to ` +
        `[@${owner}](https://github.com/${owner}) via a GitHub Security Advisory or email. ` +
        `Do not open a public issue for undisclosed vulnerabilities.\n\nWe aim to acknowledge reports within 72 hours.\n`);
      createdFiles.push('.github/SECURITY.md');
      changesMade.push('Created `.github/SECURITY.md`');
    }
    if (!['CONTRIBUTING.md', '.github/CONTRIBUTING.md', 'docs/CONTRIBUTING.md'].some(f => fs.existsSync(path.join(repoDir, f)))) {
      fs.mkdirSync(ghDir, { recursive: true });
      fs.writeFileSync(path.join(ghDir, 'CONTRIBUTING.md'),
        `# Contributing\n\nThanks for helping out.\n\n1. Fork and branch from \`main\`.\n2. Keep changes focused; add or update tests.\n` +
        `3. Do not remove \`@authormark\` headers — refresh a stale fingerprint with \`authormark stamp <file>\`.\n` +
        `4. Open a pull request describing the change and its motivation.\n`);
      createdFiles.push('.github/CONTRIBUTING.md');
      changesMade.push('Created `.github/CONTRIBUTING.md`');
    }
    {
      const ecos = [];
      if (fs.existsSync(path.join(repoDir, 'package.json'))) ecos.push('npm');
      if (fs.existsSync(path.join(repoDir, 'requirements.txt')) || fs.existsSync(path.join(repoDir, 'pyproject.toml'))) ecos.push('pip');
      if (fs.existsSync(path.join(repoDir, 'go.mod'))) ecos.push('gomod');
      if (fs.existsSync(path.join(repoDir, 'Cargo.toml'))) ecos.push('cargo');
      ecos.push('github-actions');

      const ymlPath = path.join(ghDir, 'dependabot.yml');
      const yamlPath = path.join(ghDir, 'dependabot.yaml');
      const existing = fs.existsSync(ymlPath) ? ymlPath : fs.existsSync(yamlPath) ? yamlPath : null;

      if (!existing) {
        fs.mkdirSync(ghDir, { recursive: true });
        fs.writeFileSync(ymlPath, buildDependabotConfig(ecos));
        createdFiles.push('.github/dependabot.yml');
        changesMade.push('Created grouped `.github/dependabot.yml`');
      } else {
        // Upgrade an ungrouped config in place -- ungrouped updates are the main
        // source of conflicting Dependabot PRs. Only touch a recognisably
        // bot-shaped file so a hand-tuned config is left alone.
        const cur = fs.readFileSync(existing, 'utf8');
        if (cur.includes('package-ecosystem') && !cur.includes('groups:')) {
          const relYml = path.relative(repoDir, existing).split(path.sep).join('/');
          fs.writeFileSync(existing, buildDependabotConfig(ecos));
          createdFiles.push(relYml);
          changesMade.push(`Grouped \`${relYml}\` to cut Dependabot PR churn`);
        }
      }

      // Auto-merge workflow for non-major Dependabot PRs (opt-in via repo
      // settings: "Allow auto-merge" + required status checks).
      const amWfPath = path.join(ghDir, 'workflows', 'dependabot-automerge.yml');
      if (!fs.existsSync(amWfPath)) {
        fs.mkdirSync(path.join(ghDir, 'workflows'), { recursive: true });
        fs.writeFileSync(amWfPath, DEPENDABOT_AUTOMERGE_WORKFLOW);
        createdFiles.push('.github/workflows/dependabot-automerge.yml');
        changesMade.push('Added Dependabot auto-merge workflow');
      }
    }

    // 5c. Watermark every file we just scaffolded. Skipped when the repo does
    // not use AuthorMark (no `.authormark.json`), where a header would be noise
    // and no `authormark check` gate exists to satisfy.
    if (createdFiles.length && fs.existsSync(path.join(repoDir, '.authormark.json'))) {
      const stamped = createdFiles.filter(f => fs.existsSync(path.join(repoDir, f)));
      if (stamped.length) {
        try {
          execFileSync(process.execPath, [AM_SCRIPT, 'stamp', ...stamped], {
            cwd: repoDir,
            stdio: 'ignore',
          });
        } catch (err) {
          changesMade.push(`WARNING: could not stamp scaffolded files (${sanitize(err.message)})`);
        }
      }
    }

    // 6. Fix Trailing Whitespace in code/text files
    const allFiles = walkFiles(repoDir);
    let wsFilesFixed = 0;
    for (const f of allFiles) {
      const ext = path.extname(f).toLowerCase();
      if (['.js', '.ts', '.jsx', '.tsx', '.py', '.rs', '.go', '.sh', '.md', '.json', '.yml', '.yaml'].includes(ext)) {
        try {
          const raw = fs.readFileSync(f, 'utf8');
          const cleaned = raw.split('\n').map(l => l.replace(/[ \t]+$/, '')).join('\n');
          if (cleaned !== raw) {
            fs.writeFileSync(f, cleaned);
            wsFilesFixed++;
          }
        } catch {}
      }
    }
    if (wsFilesFixed > 0) {
      changesMade.push(`Normalized trailing whitespace in ${wsFilesFixed} file(s)`);
    }

    // Check git status
    const status = execSync('git status --porcelain', { cwd: repoDir, encoding: 'utf8' }).trim();
    if (!status) {
      return { success: true, changes: [], message: 'No changes needed' };
    }

    // Stage & Commit
    execSync('git add -A', { cwd: repoDir, stdio: 'ignore' });
    const commitMsg = `chore: code hygiene, standard files & ignore rules\n\n${changesMade.map(c => `- ${c}`).join('\n')}`;
    execSync(`git -c "user.name=${botName}" -c "user.email=${botEmail}" commit -m "${commitMsg}"`, {
      cwd: repoDir,
      stdio: 'ignore',
    });

    // Push branch. Plain --force, not --force-with-lease: the shallow clone has
    // no remote-tracking ref for `branch`, so --force-with-lease has no lease
    // and rejects ("stale info") whenever a lingering older `${branch}` has
    // diverged from the default branch -- which is every re-run. This branch is
    // wholly bot-owned and regenerated from scratch each time (and watch.yml
    // serialises runs via a concurrency group), so there is nothing to clobber.
    const pushRemote = token
      ? `https://x-access-token:${token}@github.com/${owner}/${repoName}.git`
      : 'origin';
    execSync(`git push -u "${pushRemote}" "${branch}" --force`, { cwd: repoDir, stdio: 'ignore' });

    return { success: true, branch, changes: changesMade, message: `Pushed hygiene fixes to ${branch}` };
  } catch (err) {
    return { success: false, changes: [], error: sanitize(err.message) };
  }
}

// ---------------------------------------------------------------- Intelligent PR Auto-Tagger

function classifyPullRequest(pr, files, palette) {
  const labelsToAdd = new Set();
  const filesArr = Array.isArray(files) ? files : [];

  // The list endpoint omits additions/deletions, so everything scored size/XS.
  // Use the full-PR counts when present, else sum the per-file diff stats.
  const additions = Number.isFinite(pr.additions)
    ? pr.additions
    : filesArr.reduce((s, f) => s + (f.additions || 0), 0);
  const deletions = Number.isFinite(pr.deletions)
    ? pr.deletions
    : filesArr.reduce((s, f) => s + (f.deletions || 0), 0);
  const totalLines = additions + deletions;

  // 1. Size Labels
  if (totalLines < 10) labelsToAdd.add('size/XS');
  else if (totalLines < 50) labelsToAdd.add('size/S');
  else if (totalLines < 250) labelsToAdd.add('size/M');
  else if (totalLines < 1000) labelsToAdd.add('size/L');
  else labelsToAdd.add('size/XL');

  // 2. PR Type based on title / branch
  const title = (pr.title || '').toLowerCase();
  const branch = (pr.head && pr.head.ref ? pr.head.ref : '').toLowerCase();
  const body = (pr.body || '').toLowerCase();

  if (/^(feat|feature)[\/:(]/.test(title) || /^(feat|feature)\//.test(branch)) {
    labelsToAdd.add('type/feat');
  } else if (/^(fix|bugfix|hotfix)[\/:(]/.test(title) || /^(fix|bugfix)\//.test(branch)) {
    labelsToAdd.add('type/fix');
  } else if (/^(docs|documentation)[\/:(]/.test(title) || /^(docs|doc)\//.test(branch)) {
    labelsToAdd.add('type/docs');
  } else if (/^(chore|maint)[\/:(]/.test(title) || /^(chore)\//.test(branch)) {
    labelsToAdd.add('type/chore');
  } else if (/^(refactor)[\/:(]/.test(title) || /^(refactor)\//.test(branch)) {
    labelsToAdd.add('type/refactor');
  } else if (/^(test)[\/:(]/.test(title) || /^(test)\//.test(branch)) {
    labelsToAdd.add('type/test');
  } else if (/^(ci|workflow)[\/:(]/.test(title) || /^(ci)\//.test(branch)) {
    labelsToAdd.add('type/ci');
  }

  if (title.includes('authormark') || branch.includes('authormark') || body.includes('authorship watermark')) {
    labelsToAdd.add('type/authormark');
    labelsToAdd.add('automated-pr');
  }

  if (pr.user && pr.user.login && pr.user.login.includes('bot')) {
    labelsToAdd.add('bot');
    if (pr.user.login.includes('dependabot') || title.includes('bump ') || title.includes('dependencies')) {
      labelsToAdd.add('type/dependencies');
    }
  }

  // 3. Status Labels
  if (pr.draft || title.startsWith('[wip]') || title.startsWith('wip:')) {
    labelsToAdd.add('work-in-progress');
  } else {
    labelsToAdd.add('needs-review');
  }

  // 4. Language / Scope Labels based on changed files
  if (Array.isArray(files) && files.length > 0) {
    const extensions = new Set(files.map(f => path.extname(f.filename || '').toLowerCase()));
    if (extensions.has('.ts') || extensions.has('.tsx')) labelsToAdd.add('lang/typescript');
    if (extensions.has('.js') || extensions.has('.jsx') || extensions.has('.mjs')) labelsToAdd.add('lang/javascript');
    if (extensions.has('.py')) labelsToAdd.add('lang/python');
    if (extensions.has('.rs')) labelsToAdd.add('lang/rust');
    if (extensions.has('.go')) labelsToAdd.add('lang/go');
    if (extensions.has('.html') || extensions.has('.css') || extensions.has('.scss') || extensions.has('.vue') || extensions.has('.svelte')) {
      labelsToAdd.add('lang/web');
    }
    if (extensions.has('.sh') || extensions.has('.bash') || extensions.has('.ps1')) labelsToAdd.add('lang/shell');
    if (extensions.has('.c') || extensions.has('.cpp') || extensions.has('.h') || extensions.has('.hpp')) labelsToAdd.add('lang/c-cpp');
  }

  // Filter out any labels already present on PR
  const existingNames = new Set((pr.labels || []).map(l => l.name.toLowerCase()));
  const newLabels = Array.from(labelsToAdd).filter(l => !existingNames.has(l.toLowerCase()));

  return { allComputed: Array.from(labelsToAdd), toAdd: newLabels };
}

// ---------------------------------------------------------------- Intelligent Issue Auto-Tagger

function classifyIssue(issue, palette) {
  const labelsToAdd = new Set();
  const title = (issue.title || '').toLowerCase();
  const body = (issue.body || '').toLowerCase();
  const text = `${title} ${body}`;

  // 1. Categories
  if (/bug|crash|error|exception|fail|failed|broken|does not work|traceback|glitch/.test(text)) {
    labelsToAdd.add('bug');
  }
  if (/feat|feature|enhancement|support|proposal|suggest|add|implement|request/.test(text)) {
    labelsToAdd.add('enhancement');
  }
  if (/docs|documentation|readme|guide|clarif|typo|comment/.test(text)) {
    labelsToAdd.add('documentation');
  }
  if (/how to|question|help|why does|where is|troubleshoot/.test(text)) {
    labelsToAdd.add('question');
  }
  if (/security|vulnerability|cve|exploit|leak|credential|token/.test(text)) {
    labelsToAdd.add('security');
    labelsToAdd.add('priority/high');
  }
  if (/slow|latency|speed|performance|lag|memory leak|optimize|benchmark/.test(text)) {
    labelsToAdd.add('performance');
  }

  // 2. Priority & Triage
  if (/critical|urgent|severe|blocker|fatal/.test(text)) {
    labelsToAdd.add('priority/high');
  } else if (/minor|trivial|cosmetic|nice to have/.test(text)) {
    labelsToAdd.add('priority/low');
  }

  // 3. Needs info if description is too sparse for a bug
  if (labelsToAdd.has('bug') && body.trim().length < 40 && !body.includes('repro')) {
    labelsToAdd.add('needs-info');
  }

  // 4. Default triage label for untagged issues
  if ((!issue.labels || issue.labels.length === 0) && labelsToAdd.size === 0) {
    labelsToAdd.add('triage');
  }

  const existingNames = new Set((issue.labels || []).map(l => l.name.toLowerCase()));
  const newLabels = Array.from(labelsToAdd).filter(l => !existingNames.has(l.toLowerCase()));

  return { allComputed: Array.from(labelsToAdd), toAdd: newLabels };
}

// ---------------------------------------------------------------- AuthorMark Execution

function checkAuthorMark(repoDir) {
  if (!fs.existsSync(path.join(repoDir, '.authormark.json'))) {
    return { status: 'UNMARKED', details: 'No .authormark.json configuration found' };
  }
  try {
    const out = execFileSync(process.execPath, [AM_SCRIPT, 'check', '--presence', repoDir], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 'CLEAN', details: out.trim() };
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString() : '';
    const stdout = err.stdout ? err.stdout.toString() : '';
    const combined = `${stdout}\n${stderr}`;
    const missingCount = (combined.match(/MISSING/g) || []).length;
    const staleCount = (combined.match(/STALE/g) || []).length;
    return {
      status: 'DRIFTED',
      details: `${missingCount} missing header(s), ${staleCount} stale fingerprint(s)`,
      output: combined,
    };
  }
}

function fixAuthorMark(repoDir, repoName, config, token) {
  const branch = config.features.authormark.branch || 'authormark';
  const owner = config.owner;
  const botName = config.botIdentity.name;
  const botEmail = config.botIdentity.email;
  const author = config.botIdentity.author;
  const authorEmail = config.botIdentity.authorEmail;
  const ghUrl = config.botIdentity.github;

  try {
    // 0. Ensure signing key is present if in env
    const keyPath = path.join(os.homedir(), '.authormark.key');
    if (!fs.existsSync(keyPath) && process.env.AUTHORMARK_KEY) {
      try {
        fs.writeFileSync(keyPath, process.env.AUTHORMARK_KEY.trim() + '\n', { mode: 0o600 });
      } catch {}
    }

    // 1. Fetch unshallow if needed and setup branch
    try { execSync('git fetch --unshallow origin', { cwd: repoDir, stdio: 'ignore' }); } catch {}
    execSync(`git checkout -B "${branch}"`, { cwd: repoDir, stdio: 'ignore' });

    // 2. Run AuthorMark setup
    execFileSync(process.execPath, [
      AM_SCRIPT,
      'setup',
      '--author', author,
      '--email', authorEmail,
      '--github', ghUrl,
      '--license', 'MIT',
      '--no-hook',
    ], { cwd: repoDir, stdio: 'ignore' });

    // Clean up temporary bytecode if any
    try {
      const untracked = execSync('git status --porcelain', { cwd: repoDir, encoding: 'utf8' });
      for (const line of untracked.split('\n')) {
        if (line.startsWith('??') && (line.includes('__pycache__') || line.endsWith('.pyc'))) {
          const target = line.slice(3).trim();
          fs.rmSync(path.join(repoDir, target), { recursive: true, force: true });
        }
      }
    } catch {}

    const status = execSync('git status --porcelain', { cwd: repoDir, encoding: 'utf8' }).trim();
    if (!status) {
      return { success: true, message: 'No changes required (already clean)' };
    }

    // 3. Stage & Commit
    execSync('git add -A', { cwd: repoDir, stdio: 'ignore' });
    const commitMsg = `Add authorship watermarks\n\nStamp source files with keyed authorship headers, zero-width marks, image watermarks, and seal manifest.`;
    execSync(`git -c "user.name=${botName}" -c "user.email=${botEmail}" commit -m "${commitMsg}"`, {
      cwd: repoDir,
      stdio: 'ignore',
    });

    // 4. Push branch. Plain --force (see fixLintRepository): the shallow clone
    // carries no remote-tracking ref, so --force-with-lease rejects a diverged
    // stale `${branch}` with "stale info". The branch is bot-owned and rebuilt
    // each run.
    const pushRemote = token
      ? `https://x-access-token:${token}@github.com/${owner}/${repoName}.git`
      : 'origin';
    execSync(`git push -u "${pushRemote}" "${branch}" --force`, { cwd: repoDir, stdio: 'ignore' });

    return { success: true, branch, message: `Pushed updates to ${branch}` };
  } catch (err) {
    return { success: false, error: sanitize(err.message) };
  }
}

// ---------------------------------------------------------------- Master Orchestrator

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    log(`
Master Bot & Repository Supervisor for @Srinivasan-78

Usage:
  node bot.mjs [options]

Options:
  --all            Run all checks (AuthorMark, Lint, PR Tagging, Issue Tagging)
  --fix            Automatically fix AuthorMark & hygiene issues and open PRs
  --lint           Run multi-language code linting & hygiene checks
  --tag-prs        Run automated PR tagging & labeling across repos
  --tag-issues     Run automated issue tagging & triage across repos
  --repo <name>    Target a single repository (e.g. --repo my-repo)
  --dry-run        Print findings and reports without applying changes or modifying issues
  --help           Show this help message

Environment Variables:
  BOT_TOKEN / WATCH_TOKEN / GH_TOKEN / GITHUB_TOKEN  - GitHub PAT with repo/issues/PR access
  ISSUE_TOKEN                                       - Token for updating status dashboard in this repo
  AUTHORMARK_KEY                                    - HMAC key for AuthorMark stamping
  FIX=1                                             - Equivalent to --fix
  REPORT=0                                          - Skip updating the GitHub issue dashboard
  SLACK_WEBHOOK / DISCORD_WEBHOOK                   - Post a summary line when findings need attention
  GITHUB_STEP_SUMMARY                               - (set by Actions) report is appended to the run summary

Per-repo override: a repo may ship .masterbot.json to set { "enabled": false }
or tune features.{authormark,lint}.autoFix for itself.
`);
    process.exit(0);
  }

  const config = loadConfig();
  const token = resolveToken();
  const issueToken = resolveIssueToken();

  // Ensure key is written from env if present
  const keyPath = path.join(os.homedir(), '.authormark.key');
  if (!fs.existsSync(keyPath) && process.env.AUTHORMARK_KEY) {
    try {
      fs.writeFileSync(keyPath, process.env.AUTHORMARK_KEY.trim() + '\n', { mode: 0o600 });
    } catch {}
  }

  const isFix = args.includes('--fix') || process.env.FIX === '1' || config.features?.authormark?.autoFix === true;
  const isDryRun = args.includes('--dry-run');
  const targetRepoArg = args.includes('--repo') ? args[args.indexOf('--repo') + 1] : null;

  const runAll = args.includes('--all') || (!args.includes('--lint') && !args.includes('--tag-prs') && !args.includes('--tag-issues'));
  const doLint = runAll || args.includes('--lint');
  const doPrTag = runAll || args.includes('--tag-prs');
  const doIssueTag = runAll || args.includes('--tag-issues');

  log(`🚀 Starting Master Bot supervisor for owner: ${config.owner}`);
  if (isDryRun) log(`🔍 Dry-run mode active. No changes will be published.`);

  const client = new GitHubClient(token);
  const issueClient = new GitHubClient(issueToken || token);

  // 1. Discover Repositories
  let repos = [];
  try {
    if (targetRepoArg) {
      repos = [{ name: targetRepoArg, fork: false, archived: false }];
    } else if (token) {
      log(`📡 Fetching repository list from GitHub API...`);
      const apiRepos = await client.listRepos(config.owner);
      repos = apiRepos;
    } else {
      log(`ℹ️ No GitHub token detected; checking local directories or fallback list.`);
      // Check local folders in parent directory
      const parent = path.dirname(__dirname);
      const localEntries = fs.readdirSync(parent, { withFileTypes: true });
      for (const ent of localEntries) {
        if (ent.isDirectory() && fs.existsSync(path.join(parent, ent.name, '.git'))) {
          repos.push({ name: ent.name, fork: false, archived: false });
        }
      }
    }
  } catch (e) {
    errLog(`Could not retrieve repository list: ${e.message}`);
    if (config.repos.include) {
      repos = config.repos.include.map(name => ({ name, fork: false, archived: false }));
    }
  }

  // Ensure explicitly included repos are present in the list
  const repoNameSet = new Set(repos.map(r => r.name.toLowerCase()));
  for (const inc of config.repos.include || []) {
    if (!repoNameSet.has(inc.toLowerCase())) {
      repos.push({ name: inc, fork: false, archived: false });
      repoNameSet.add(inc.toLowerCase());
    }
  }

  // Filter repos
  const excludeSet = new Set((config.repos.exclude || []).map(r => r.toLowerCase()));
  const skipSet = new Set((config.repos.skip || []).map(r => r.toLowerCase()));

  const filteredRepos = repos.filter(r => {
    const n = r.name.toLowerCase();
    if (skipSet.has(n)) return false;
    if (excludeSet.has(n)) return false;
    if (r.archived && !config.repos.includeArchived) return false;
    if (r.fork && !config.repos.includeForks) return false;
    return true;
  });

  log(`📦 Found ${filteredRepos.length} repository(ies) to supervise.`);

  // Prepare temporary workspace for cloning
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'master-bot-'));

  const summary = {
    total: filteredRepos.length,
    scannedTime: new Date().toISOString(),
    authormark: { clean: [], drifted: [], unmarked: [], fixed: [], fixFailed: [] },
    lintFindings: [],
    lintFixed: [],
    lintFixFailed: [],
    awaitingMerge: [],
    securityAlerts: [],
    prsTagged: [],
    issuesTagged: [],
    failedRepos: [],
  };

  // Process Each Repository
  for (const repoInfo of filteredRepos) {
    const name = repoInfo.name;
    log(`\n==================================================`);
    log(`🔍 Inspecting repository: ${name}`);

    let repoDir = path.join(path.dirname(__dirname), name);
    let isClonedTemp = false;

    if (!fs.existsSync(repoDir) || !fs.existsSync(path.join(repoDir, '.git'))) {
      repoDir = path.join(workDir, name);
      log(`📥 Cloning ${config.owner}/${name} into temporary workspace...`);
      try {
        const cloneUrl = token
          ? `https://x-access-token:${token}@github.com/${config.owner}/${name}.git`
          : `https://github.com/${config.owner}/${name}.git`;
        execSync(`git clone --depth 1 "${cloneUrl}" "${repoDir}"`, { stdio: 'ignore' });
        isClonedTemp = true;
      } catch (err) {
        warn(`Could not clone ${name}: ${sanitize(err.message)}`);
        summary.failedRepos.push({ name, reason: 'Clone failed or repository is inaccessible' });
        continue;
      }
    }

    // Let the repo veto or tune the bot for itself via .masterbot.json.
    const repoCfg = applyRepoOverrides(config, repoDir);
    if (repoCfg.enabled === false) {
      log(`  ⏭️  ${name} opts out via .masterbot.json (enabled: false)`);
      summary.authormark.clean.push(name);
      continue;
    }
    const repoFix = isFix &&
      repoCfg.features.authormark.autoFix !== false &&
      repoCfg.features.authormark.enabled !== false;

    // A. AuthorMark Check
    log(`  [1/4] Checking AuthorMark watermarks & signatures...`);
    const amResult = checkAuthorMark(repoDir);
    let fixPrUrl = null;

    if (amResult.status === 'CLEAN') {
      summary.authormark.clean.push(name);
      log(`    ✅ AuthorMark watermarks are intact.`);
    } else if (amResult.status === 'DRIFTED') {
      summary.authormark.drifted.push({ name, details: amResult.details });
      log(`    ⚠️ AuthorMark drifted: ${amResult.details}`);
    } else {
      summary.authormark.unmarked.push({ name, details: amResult.details });
      log(`    🆕 AuthorMark unmarked: ${amResult.details}`);
    }

    // Fix AuthorMark if requested
    if ((amResult.status === 'DRIFTED' || amResult.status === 'UNMARKED') && repoFix && !isDryRun) {
      log(`    🔧 Attempting AuthorMark automated fix & PR creation...`);
      const fixResult = fixAuthorMark(repoDir, name, config, token);
      if (fixResult.success) {
        log(`    ✅ ${fixResult.message}`);
        // Ensure a PR exists AND track it until it is merged into the default
        // branch -- a PR merely being open is not "done", so the repo stays on
        // the awaiting-merge list and gets re-flagged next run.
        if (token) {
          const amBranch = config.features.authormark.branch || 'authormark';
          try {
            const res = await ensureFixPr(client, config.owner, name, amBranch, {
              title: 'Add authorship watermarks',
              head: amBranch,
              base: repoInfo.default_branch || 'main',
              body: `Opened automatically by Master Bot ([authormark-watch](https://github.com/Srinivasan-78/authormark-watch)).\n\n- Keyed HMAC fingerprint headers\n- Invisible zero-width copy-paste watermark\n- Image watermarks\n- Sealed prior-art \`AUTHORSHIP.json\` manifest\n- CI workflow and agent rules`,
            });
            fixPrUrl = res.url;
            summary.authormark.fixed.push({ name, prUrl: res.url, action: res.action });
            if (res.awaiting) {
              summary.awaitingMerge.push({ name, kind: 'AuthorMark watermarks', prNumber: res.pr.number, url: res.url });
            }
            if (res.action === 'Opened PR') {
              await client.addLabels(config.owner, name, res.pr.number, ['automated-pr', 'bot', 'type/authormark', 'needs-review']);
            }
          } catch (prErr) {
            warn(`Could not open PR for ${name}: ${prErr.message}`);
          }
        }
      } else {
        errLog(`    ❌ AuthorMark fix failed: ${fixResult.error}`);
        summary.authormark.fixFailed.push({ name, reason: fixResult.error });
      }
    }

    // B. Multi-Language Code Lint & Hygiene
    let lintRes = null;
    if (doLint) {
      log(`  [2/4] Running multi-language linter & hygiene scan...`);
      lintRes = lintRepository(repoDir, name);
      const issueCount =
        lintRes.secrets.length +
        lintRes.syntaxErrors.length +
        lintRes.unwantedArtifacts.length +
        lintRes.standards.length +
        lintRes.whitespaceIssues.length +
        lintRes.workflowRisks.length +
        lintRes.historySecrets.length;

      if (issueCount > 0) {
        log(`    ⚠️ Found ${issueCount} hygiene / lint findings.`);
        summary.lintFindings.push({ name, ...lintRes });

        const lintAutoFix = (repoFix || repoCfg.features?.lint?.autoFix === true) &&
          repoCfg.features?.lint?.enabled !== false;

        // Pin unpinned GitHub Actions to a commit SHA (writes files to disk;
        // fixLintRepository's `git add -A` picks them up).
        let pinnedCount = 0;
        if (lintAutoFix && !isDryRun && token && lintRes.workflowRisks.some(r => /pinned to a tag/.test(r))) {
          pinnedCount = await pinActionsOnDisk(repoDir, client);
          if (pinnedCount) log(`    📌 Pinned ${pinnedCount} action reference(s) to a SHA`);
        }

        const hasFixable = lintRes.unwantedArtifacts.length > 0 || lintRes.standards.length > 0 ||
          lintRes.whitespaceIssues.length > 0 || pinnedCount > 0;

        if (hasFixable && lintAutoFix && !isDryRun) {
          log(`    🔧 Attempting automated repository hygiene & standards fix...`);
          const hygieneBranch = fixPrUrl ? (config.features.authormark.branch || 'authormark') : 'masterbot-hygiene';
          const lintFixResult = fixLintRepository(repoDir, name, config, token, hygieneBranch);
          if (lintFixResult.success && lintFixResult.changes.length > 0) {
            log(`    ✅ ${lintFixResult.message} (${lintFixResult.changes.length} change(s))`);
            if (!fixPrUrl && token) {
              try {
                const res = await ensureFixPr(client, config.owner, name, hygieneBranch, {
                  title: 'chore: repository hygiene & standard rules',
                  head: hygieneBranch,
                  base: repoInfo.default_branch || 'main',
                  body: `Opened automatically by Master Bot ([authormark-watch](https://github.com/Srinivasan-78/authormark-watch)) to apply code hygiene and repository standards:\n\n${lintFixResult.changes.map(c => `- ${c}`).join('\n')}`,
                });
                summary.lintFixed.push({ name, prUrl: res.url, action: res.action, changes: lintFixResult.changes });
                if (res.awaiting) {
                  summary.awaitingMerge.push({ name, kind: 'Repository hygiene', prNumber: res.pr.number, url: res.url });
                }
                if (res.action === 'Opened PR') {
                  await client.addLabels(config.owner, name, res.pr.number, ['automated-pr', 'bot', 'type/chore', 'needs-review']);
                }
              } catch (prErr) {
                warn(`Could not open hygiene PR for ${name}: ${prErr.message}`);
              }
            } else if (fixPrUrl) {
              summary.lintFixed.push({ name, prUrl: fixPrUrl, action: 'Included in PR', changes: lintFixResult.changes });
            }
          } else if (!lintFixResult.success) {
            // Previously swallowed -- a repo could show "Health & Standard
            // Guidelines" findings forever with no PR and no explanation.
            errLog(`    ❌ Hygiene fix failed: ${lintFixResult.error || 'unknown error'}`);
            summary.lintFixFailed.push({ name, reason: lintFixResult.error || 'unknown error' });
          } else {
            log(`    ℹ️ Hygiene scan flagged issues but nothing was auto-fixable.`);
          }
        }
      } else {
        log(`    ✅ Code lint & repository hygiene clean.`);
      }
    }

    // B2. GitHub-native security alerts
    if (doLint && token) {
      try {
        const a = await client.countOpenAlerts(config.owner, name);
        if (a.dependabot || a.codeScanning || a.secretScanning || a.vulnerabilityAlertsDisabled) {
          log(`    🛡️ Security alerts: ${a.dependabot} Dependabot / ${a.codeScanning} code-scanning / ${a.secretScanning} secret-scanning`);
          summary.securityAlerts.push({ name, ...a });
        }
      } catch (e) {
        warn(`Could not read security alerts for ${name}: ${e.message}`);
      }
    }

    // C. Automated PR Tagging
    if (doPrTag && token) {
      log(`  [3/4] Inspecting open pull requests for auto-tagging...`);
      try {
        const prs = await client.listPullRequests(config.owner, name, 'open');
        for (const pr of prs) {
          // Full payload for accurate size labels; files for language labels.
          const full = await client.getPullRequest(config.owner, name, pr.number).catch(() => pr);
          const files = await client.getPullRequestFiles(config.owner, name, pr.number).catch(() => []);
          const classification = classifyPullRequest(full, files, config.labelPalette);
          if (classification.toAdd.length > 0) {
            log(`    🏷️ PR #${pr.number} ("${pr.title}") -> Adding: [${classification.toAdd.join(', ')}]`);
            if (!isDryRun) {
              for (const l of classification.toAdd) {
                await client.ensureLabel(config.owner, name, l, config.labelPalette);
              }
              await client.addLabels(config.owner, name, pr.number, classification.toAdd);
            }
            summary.prsTagged.push({
              repo: name,
              prNumber: pr.number,
              title: pr.title,
              url: pr.html_url,
              addedLabels: classification.toAdd,
            });
          }
        }
        if (prs.length === 0) log(`    ℹ️ No open pull requests.`);
      } catch (prErr) {
        warn(`Could not inspect PRs for ${name}: ${prErr.message}`);
      }
    }

    // D. Automated Issue Tagging & Triage
    if (doIssueTag && token) {
      log(`  [4/4] Inspecting open issues for auto-tagging & triage...`);
      try {
        const issues = await client.listIssues(config.owner, name, 'open');
        for (const issue of issues) {
          const classification = classifyIssue(issue, config.labelPalette);
          if (classification.toAdd.length > 0) {
            log(`    🏷️ Issue #${issue.number} ("${issue.title}") -> Adding: [${classification.toAdd.join(', ')}]`);
            if (!isDryRun) {
              for (const l of classification.toAdd) {
                await client.ensureLabel(config.owner, name, l, config.labelPalette);
              }
              await client.addLabels(config.owner, name, issue.number, classification.toAdd);
            }
            summary.issuesTagged.push({
              repo: name,
              issueNumber: issue.number,
              title: issue.title,
              url: issue.html_url,
              addedLabels: classification.toAdd,
            });
          }
        }
        if (issues.length === 0) log(`    ℹ️ No open issues.`);
      } catch (issueErr) {
        warn(`Could not inspect issues for ${name}: ${issueErr.message}`);
      }
    }
  }

  // Clean up temporary workspace
  try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}

  // ---------------------------------------------------------------- Report Generation

  log(`\n==================================================`);
  log(`📊 Generating Consolidated Master Dashboard Report...`);

  const report = buildMarkdownReport(config, summary);
  console.log('\n' + report + '\n');

  const hasIssues =
    summary.authormark.drifted.length > 0 ||
    summary.authormark.unmarked.length > 0 ||
    summary.lintFindings.length > 0 ||
    summary.awaitingMerge.length > 0 ||
    (summary.lintFixFailed && summary.lintFixFailed.length > 0) ||
    summary.securityAlerts.length > 0 ||
    summary.failedRepos.length > 0;

  // GitHub Actions job summary -- shows the report on the run page, no issue needed.
  if (process.env.GITHUB_STEP_SUMMARY) {
    try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, report + '\n'); } catch {}
  }

  // Optional chat notification when something needs attention.
  await notify(config, summary, hasIssues, isDryRun);

  // ---------------------------------------------------------------- GitHub Status Issue

  const shouldPublishReport = (process.env.REPORT !== '0') && !isDryRun;
  if (shouldPublishReport && issueClient.token) {
    const dashboardTitle = 'authormark: Master Bot Status Dashboard';
    try {
      const existing = await issueClient.findTrackingIssue(config.owner, 'authormark-watch', 'authormark:');

      if (existing) {
        log(`📝 Updating Master Bot status dashboard issue #${existing.number}...`);
        await issueClient.updateIssue(config.owner, 'authormark-watch', existing.number, {
          title: dashboardTitle,
          body: report,
          state: hasIssues ? 'open' : 'closed',
        });
        await issueClient.addComment(
          config.owner,
          'authormark-watch',
          existing.number,
          `🔄 Scan completed on \`${summary.scannedTime}\`. Status: **${hasIssues ? 'Issues require attention' : 'All monitored repositories clean'}**.`
        );
      } else if (hasIssues) {
        log(`📝 Creating Master Bot status dashboard issue...`);
        await issueClient.createIssue(config.owner, 'authormark-watch', dashboardTitle, report, ['bot', 'triage']);
      }
    } catch (issueErr) {
      warn(`Could not update GitHub status issue: ${issueErr.message}`);
    }
  }

  log(`✨ Master Bot run finished successfully.`);
}

// ---------------------------------------------------------------- Report Builder

function buildMarkdownReport(config, summary) {
  const lines = [];
  const am = summary.authormark;
  const awaitingMerge = summary.awaitingMerge || [];
  const lintFixFailed = summary.lintFixFailed || [];
  const problemsCount = am.drifted.length + am.unmarked.length + summary.lintFindings.length +
    awaitingMerge.length + lintFixFailed.length +
    (summary.securityAlerts ? summary.securityAlerts.length : 0) + summary.failedRepos.length;

  lines.push(`# Master Bot Account Dashboard (@${config.owner})`);
  lines.push(`\nScanned **${summary.total}** monitored repositories on \`${summary.scannedTime}\`.\n`);

  if (problemsCount === 0) {
    lines.push(`> 🟢 **All Systems Nominal**: Every monitored repository is watermarked, code-linted, and up to date.\n`);
  } else {
    lines.push(`> ⚠️ **Attention Needed**: Found items requiring review across **${problemsCount}** checks.\n`);
  }

  // Hygiene fixes that errored out (git push rejects, stamp failures, ...).
  // Without this section such repos silently show findings but never a PR.
  if (lintFixFailed.length > 0) {
    lines.push(`## ❌ Hygiene Fix Failed`);
    lines.push(`The automated hygiene fix threw for these repos, so no PR was opened. They will be retried next run.\n`);
    for (const r of lintFixFailed) lines.push(`- \`${r.name}\`: ${r.reason}`);
    lines.push('');
  }

  // Awaiting-merge Section -- fix PRs that exist but have NOT landed yet. These
  // keep a repo on the attention list: a PR being open is not the finish line.
  if (awaitingMerge.length > 0) {
    lines.push(`## ⏳ Awaiting Merge (still blocking)`);
    lines.push(`These fix PRs exist but are **not merged** into the default branch yet. Each repo below stays flagged until its PR lands.\n`);
    for (const r of awaitingMerge) {
      lines.push(`- \`${r.name}\` — ${r.kind}: [PR #${r.prNumber}](${r.url}) — **not merged**`);
    }
    lines.push('');
  }

  // AuthorMark Section
  lines.push(`## 🔏 AuthorMark Watermarking & Signatures`);
  if (am.drifted.length > 0) {
    lines.push(`### ⚠️ Watermarks Missing or Drifted`);
    for (const r of am.drifted) lines.push(`- \`${r.name}\` — ${r.details}`);
    lines.push(`\n*Fix*: Run \`node bot.mjs --fix\` or \`FIX=1 ./watch.sh\`\n`);
  }
  if (am.unmarked.length > 0) {
    lines.push(`### 🆕 Repositories Lacking AuthorMark`);
    for (const r of am.unmarked) lines.push(`- \`${r.name}\` — ${r.details}`);
    lines.push(`\n*Fix*: Run \`node bot.mjs --fix\` or \`FIX=1 ./watch.sh\`\n`);
  }
  if (am.fixed.length > 0) {
    lines.push(`### 🤖 Automated Fix PRs Opened / Updated`);
    for (const r of am.fixed) lines.push(`- \`${r.name}\`: [${r.action}](${r.prUrl})`);
    lines.push('');
  }
  if (am.fixFailed.length > 0) {
    lines.push(`### ❌ Fix PR Failed`);
    for (const r of am.fixFailed) lines.push(`- \`${r.name}\`: ${r.reason}`);
    lines.push('');
  }
  if (am.clean.length > 0) {
    lines.push(`<details><summary><b>${am.clean.length} Clean AuthorMark Repositories</b></summary>\n`);
    for (const r of am.clean) lines.push(`- \`${r}\``);
    lines.push(`\n</details>\n`);
  }

  // Code Lint & Hygiene Section
  lines.push(`## 🧹 Multi-Language Code Lint & Repository Hygiene`);
  if (summary.lintFixed && summary.lintFixed.length > 0) {
    lines.push(`### 🤖 Automated Hygiene Fix PRs Opened / Updated`);
    for (const r of summary.lintFixed) {
      lines.push(`- \`${r.name}\`: [${r.action}](${r.prUrl}) — ${r.changes.join(', ')}`);
    }
    lines.push('');
  }
  if (summary.lintFindings.length === 0) {
    lines.push(`- ✅ All repositories passed secret scans, syntax checks, and repository standards.\n`);
  } else {
    for (const item of summary.lintFindings) {
      lines.push(`### \`${item.name}\``);
      if (item.secrets.length > 0) {
        lines.push(`- 🔴 **Secret / Token Findings**:`);
        for (const s of item.secrets) lines.push(`  - ${s}`);
      }
      if (item.syntaxErrors.length > 0) {
        lines.push(`- 🟠 **Syntax / Manifest Errors**:`);
        for (const s of item.syntaxErrors) lines.push(`  - ${s}`);
      }
      if (item.unwantedArtifacts.length > 0) {
        lines.push(`- 🟡 **Unwanted Tracked Artifacts**:`);
        for (const s of item.unwantedArtifacts) lines.push(`  - ${s}`);
      }
      if (item.standards.length > 0) {
        lines.push(`- ⚪ **Health & Standard Guidelines**:`);
        for (const s of item.standards) lines.push(`  - ${s}`);
      }
      if (item.workflowRisks && item.workflowRisks.length > 0) {
        lines.push(`- 🟣 **GitHub Actions Security**:`);
        for (const s of item.workflowRisks) lines.push(`  - ${s}`);
      }
      if (item.historySecrets && item.historySecrets.length > 0) {
        lines.push(`- 🔴 **Secrets in Git History**:`);
        for (const s of item.historySecrets) lines.push(`  - ${s}`);
      }
      lines.push('');
    }
  }

  // GitHub-native security alerts (Dependabot / code scanning / secret scanning)
  if (summary.securityAlerts && summary.securityAlerts.length > 0) {
    lines.push(`## 🛡️ GitHub Security Alerts`);
    for (const a of summary.securityAlerts) {
      const bits = [];
      if (a.dependabot) bits.push(`${a.dependabot} Dependabot`);
      if (a.codeScanning) bits.push(`${a.codeScanning} code-scanning`);
      if (a.secretScanning) bits.push(`${a.secretScanning} secret-scanning`);
      if (a.vulnerabilityAlertsDisabled) bits.push('Dependabot alerts disabled');
      if (bits.length) lines.push(`- \`${a.name}\`: ${bits.join(', ')}`);
    }
    lines.push('');
  }

  // PR Tagging Summary
  lines.push(`## 🏷️ Automated PR Tagging`);
  if (summary.prsTagged.length === 0) {
    lines.push(`- All open pull requests have up-to-date labels.\n`);
  } else {
    lines.push(`Tagged **${summary.prsTagged.length}** open PR(s):`);
    for (const pr of summary.prsTagged) {
      lines.push(`- [\`${pr.repo}#${pr.prNumber}\`](${pr.url}) *${pr.title}* -> Added \`[${pr.addedLabels.join(', ')}]\``);
    }
    lines.push('');
  }

  // Issue Tagging Summary
  lines.push(`## 📋 Automated Issue Tagging & Triage`);
  if (summary.issuesTagged.length === 0) {
    lines.push(`- All open issues have up-to-date triage labels.\n`);
  } else {
    lines.push(`Triaged & Tagged **${summary.issuesTagged.length}** issue(s):`);
    for (const is of summary.issuesTagged) {
      lines.push(`- [\`${is.repo}#${is.issueNumber}\`](${is.url}) *${is.title}* -> Added \`[${is.addedLabels.join(', ')}]\``);
    }
    lines.push('');
  }

  // Inaccessible Repositories
  if (summary.failedRepos.length > 0) {
    lines.push(`## ❓ Inaccessible Repositories`);
    for (const r of summary.failedRepos) lines.push(`- \`${r.name}\`: ${r.reason}`);
    lines.push('');
  }

  lines.push(`---`);
  lines.push(`*Generated autonomously by [AuthorMark Master Bot](https://github.com/Srinivasan-78/authormark-watch)*`);

  return lines.join('\n');
}

// Only run the supervisor when invoked directly, so tests can import the
// classifiers and report builder without a network round-trip.
const isMain = (() => {
  try { return __filename === fs.realpathSync(process.argv[1]); } catch { return false; }
})();

if (isMain) {
  main().catch(err => {
    errLog(`Master Bot execution error: ${err.stack || err.message}`);
    process.exit(1);
  });
}

export {
  loadConfig, applyRepoOverrides, sanitize, GitHubClient, lintRepository, walkFiles,
  classifyPullRequest, classifyIssue, buildMarkdownReport, classifyBranchPr,
  auditWorkflow, scanGitHistory, pinWorkflowActions, buildDependabotConfig,
  SECRET_PATTERNS,
};

