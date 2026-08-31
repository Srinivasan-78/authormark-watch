#!/usr/bin/env node
/*!
 * @authormark v1 -- do not remove (authorship watermark)
 * Copyright (c) 2026 Srinivasan Vijayaraghavan <srinivasan.shyam2000@gmail.com>
 * Author: https://github.com/Srinivasan-78
 * SPDX-License-Identifier: MIT
 * Fingerprint: AMK1.MasterBotCentralEngine78
 */

/**
 * Master Bot & Account-Wide Repository Supervisor for @Srinivasan-78
 *
 * Capabilities:
 *  1. AuthorMark Code Watermarking & Signing (Detection + Automated Fix PRs)
 *  2. Multi-Language Code Linting & Repository Hygiene (Secrets, Syntax, Artifacts, Standards)
 *  3. Automated PR Tagging & Labeling (Size, Type, Languages, Workflow status)
 *  4. Automated Issue Tagging & Triage (Categories, Priorities, Needs-info, Good first issue)
 *  5. Flagship `automatch` Dedicated Monitoring
 *  6. Consolidated Master Dashboard & Status Issue Management
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
      include: ['automatch'],
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
      };
    } catch (e) {
      console.warn(`[warn] Failed to parse bot.config.json: ${e.message}. Using defaults.`);
    }
  }
  return defaults;
}

// ---------------------------------------------------------------- Logger & Helpers

function log(msg) { console.log(msg); }
function warn(msg) { console.warn(`::warning::${msg}`); }
function errLog(msg) { console.error(`::error::${msg}`); }

function sanitize(text) {
  if (!text) return '';
  return String(text).replace(/(gh[pousr]_|github_pat_)[A-Za-z0-9_]+/g, '***');
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
      'User-Agent': 'AuthorMark-MasterBot/1.0 (+https://github.com/Srinivasan-78/authormark-watch)',
      ...(options.headers || {}),
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    try {
      const res = await fetch(url, { ...options, headers });
      if (res.status === 204) return null;
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        const msg = data && data.message ? data.message : `HTTP ${res.status}`;
        throw new Error(`${options.method || 'GET'} ${endpoint} failed (${res.status}): ${msg}`);
      }
      return data;
    } catch (e) {
      throw new Error(`GitHub API Error: ${sanitize(e.message)}`);
    }
  }

  async listRepos(owner) {
    const repos = [];
    let page = 1;
    while (true) {
      const batch = await this.request(`/users/${owner}/repos?per_page=100&page=${page}&sort=pushed`);
      if (!Array.isArray(batch) || batch.length === 0) break;
      repos.push(...batch);
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
}

// ---------------------------------------------------------------- Multi-Language Lint & Hygiene

const LINT_SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', 'out', 'coverage',
  '.turbo', '.vercel', 'vendor', '__pycache__', 'venv', '.venv',
  'site-packages', 'third_party', 'target', '.mypy_cache', '.cache',
]);

const SECRET_PATTERNS = [
  { name: 'GitHub Personal Access Token', regex: /(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})/ },
  { name: 'Google / Firebase API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: 'AWS Access Key ID', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/ },
  { name: 'Private Key', regex: /-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP|PRIVATE) KEY-----/ },
  { name: 'Slack Webhook / Token', regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z_]+\/B[0-9A-Z_]+\/[0-9A-Za-z]+/ },
  { name: 'Discord Webhook', regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/ },
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

function lintRepository(repoDir, repoName) {
  const findings = {
    secrets: [],
    syntaxErrors: [],
    unwantedArtifacts: [],
    standards: [],
    whitespaceIssues: [],
  };

  const files = walkFiles(repoDir);
  const rel = f => path.relative(repoDir, f).replace(/\\/g, '/');

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

// ---------------------------------------------------------------- Intelligent PR Auto-Tagger

function classifyPullRequest(pr, files, palette) {
  const labelsToAdd = new Set();
  const additions = pr.additions || 0;
  const deletions = pr.deletions || 0;
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
    // 1. Setup branch
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

    // 4. Push branch
    if (token) {
      const pushUrl = `https://x-access-token:${token}@github.com/${owner}/${repoName}.git`;
      execSync(`git push -u "${pushUrl}" "${branch}" --force-with-lease`, { cwd: repoDir, stdio: 'ignore' });
    } else {
      execSync(`git push -u origin "${branch}" --force-with-lease`, { cwd: repoDir, stdio: 'ignore' });
    }

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
  --repo <name>    Target a single repository (e.g. --repo automatch)
  --dry-run        Print findings and reports without applying changes or modifying issues
  --help           Show this help message

Environment Variables:
  BOT_TOKEN / WATCH_TOKEN / GH_TOKEN / GITHUB_TOKEN  - GitHub PAT with repo/issues/PR access
  ISSUE_TOKEN                                       - Token for updating status dashboard in this repo
  AUTHORMARK_KEY                                    - HMAC key for AuthorMark stamping
  FIX=1                                             - Equivalent to --fix
  REPORT=0                                          - Skip updating the GitHub issue dashboard
`);
    process.exit(0);
  }

  const config = loadConfig();
  const token = resolveToken();
  const issueToken = resolveIssueToken();

  const isFix = args.includes('--fix') || process.env.FIX === '1';
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

  // Ensure explicitly included repos like automatch are present in the list
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
    automatchStatus: null,
    authormark: { clean: [], drifted: [], unmarked: [], fixed: [], fixFailed: [] },
    lintFindings: [],
    prsTagged: [],
    issuesTagged: [],
    failedRepos: [],
  };

  // Process Each Repository
  for (const repoInfo of filteredRepos) {
    const name = repoInfo.name;
    const isAutomatch = name.toLowerCase() === 'automatch';
    log(`\n==================================================`);
    log(`🔍 Inspecting repository: ${name}${isAutomatch ? ' [FLAGSHIP REPO]' : ''}`);

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
        if (isAutomatch) summary.automatchStatus = { error: 'Failed to clone automatch repository' };
        continue;
      }
    }

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
    if ((amResult.status === 'DRIFTED' || amResult.status === 'UNMARKED') && isFix && !isDryRun) {
      log(`    🔧 Attempting AuthorMark automated fix & PR creation...`);
      const fixResult = fixAuthorMark(repoDir, name, config, token);
      if (fixResult.success) {
        log(`    ✅ ${fixResult.message}`);
        // Create or reuse PR via GitHub API
        try {
          const prs = await client.listPullRequests(config.owner, name, 'open');
          const existingPr = prs.find(p => p.head && p.head.ref === (config.features.authormark.branch || 'authormark'));
          if (existingPr) {
            fixPrUrl = existingPr.html_url;
            summary.authormark.fixed.push({ name, prUrl: fixPrUrl, action: 'Updated PR' });
          } else if (token) {
            const newPr = await client.request(`/repos/${config.owner}/${name}/pulls`, {
              method: 'POST',
              body: JSON.stringify({
                title: 'Add authorship watermarks',
                head: config.features.authormark.branch || 'authormark',
                base: 'main',
                body: `Opened automatically by Master Bot ([authormark-watch](https://github.com/Srinivasan-78/authormark-watch)).\n\n- Keyed HMAC fingerprint headers\n- Invisible zero-width copy-paste watermark\n- Image watermarks\n- Sealed prior-art \`AUTHORSHIP.json\` manifest\n- CI workflow and agent rules`,
              }),
            });
            fixPrUrl = newPr.html_url;
            summary.authormark.fixed.push({ name, prUrl: fixPrUrl, action: 'Opened PR' });
            // Tag newly created PR
            await client.addLabels(config.owner, name, newPr.number, ['automated-pr', 'bot', 'type/authormark', 'needs-review']);
          }
        } catch (prErr) {
          warn(`Could not open PR for ${name}: ${prErr.message}`);
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
        lintRes.standards.length;

      if (issueCount > 0) {
        log(`    ⚠️ Found ${issueCount} hygiene / lint findings.`);
        summary.lintFindings.push({ name, ...lintRes });
      } else {
        log(`    ✅ Code lint & repository hygiene clean.`);
      }
    }

    // C. Automated PR Tagging
    if (doPrTag && token) {
      log(`  [3/4] Inspecting open pull requests for auto-tagging...`);
      try {
        const prs = await client.listPullRequests(config.owner, name, 'open');
        for (const pr of prs) {
          const files = await client.getPullRequestFiles(config.owner, name, pr.number).catch(() => []);
          const classification = classifyPullRequest(pr, files, config.labelPalette);
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

    // Capture automatch flagship status
    if (isAutomatch) {
      summary.automatchStatus = {
        authormark: amResult.status,
        authormarkDetails: amResult.details,
        lint: lintRes,
        fixPrUrl,
      };
    }
  }

  // Clean up temporary workspace
  try { fs.rmSync(workDir, { recursive: true, force: true }); } catch {}

  // ---------------------------------------------------------------- Report Generation

  log(`\n==================================================`);
  log(`📊 Generating Consolidated Master Dashboard Report...`);

  const report = buildMarkdownReport(config, summary);
  console.log('\n' + report + '\n');

  // ---------------------------------------------------------------- GitHub Status Issue

  const shouldPublishReport = (process.env.REPORT !== '0') && !isDryRun;
  if (shouldPublishReport && issueClient.token) {
    const dashboardTitle = 'authormark: Master Bot Status Dashboard';
    try {
      const existing = await issueClient.findTrackingIssue(config.owner, 'authormark-watch', 'authormark:');
      const hasIssues =
        summary.authormark.drifted.length > 0 ||
        summary.authormark.unmarked.length > 0 ||
        summary.lintFindings.length > 0 ||
        summary.failedRepos.length > 0;

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
  const problemsCount = am.drifted.length + am.unmarked.length + summary.lintFindings.length + summary.failedRepos.length;

  lines.push(`# Master Bot Account Dashboard (@${config.owner})`);
  lines.push(`\nScanned **${summary.total}** monitored repositories on \`${summary.scannedTime}\`.\n`);

  if (problemsCount === 0) {
    lines.push(`> 🟢 **All Systems Nominal**: Every monitored repository is watermarked, code-linted, and up to date.\n`);
  } else {
    lines.push(`> ⚠️ **Attention Needed**: Found items requiring review across **${problemsCount}** checks.\n`);
  }

  // Flagship Automatch Section
  if (summary.automatchStatus) {
    lines.push(`## 🎯 Flagship Watch: \`automatch\``);
    const ast = summary.automatchStatus;
    if (ast.error) {
      lines.push(`- ❌ **Status**: ${ast.error}`);
    } else {
      lines.push(`- **AuthorMark Status**: \`${ast.authormark}\` (${ast.authormarkDetails})`);
      if (ast.fixPrUrl) lines.push(`- **Fix PR**: [View PR](${ast.fixPrUrl})`);
      if (ast.lint) {
        const lCount = ast.lint.secrets.length + ast.lint.syntaxErrors.length + ast.lint.standards.length;
        lines.push(`- **Hygiene & Standards**: ${lCount === 0 ? '✅ Clean' : `⚠️ ${lCount} findings`}`);
      }
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
      lines.push('');
    }
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

main().catch(err => {
  errLog(`Master Bot execution error: ${err.stack || err.message}`);
  process.exit(1);
});

