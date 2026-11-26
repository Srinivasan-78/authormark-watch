import { execFileSync } from 'node:child_process';

const log = msg => console.log(msg);
const warn = msg => console.warn(`::warning::${msg}`);
const errLog = msg => console.error(`::error::${msg}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));

function sanitize(text) {
  if (!text) return '';
  return String(text)
    .replace(/(gh[pousr]_|github_pat_)[A-Za-z0-9_]+/g, '***')
    .replace(/x-access-token:[^@\s]+@/g, 'x-access-token:***@');
}

function backoffMs(attempt) {
  return Math.min(30000, Math.round((2 ** attempt) * 500 * (0.5 + Math.random())));
}

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
  for (const name of ['BOT_TOKEN', 'WATCH_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN']) {
    if (process.env[name]) return process.env[name];
  }
  try {
    const out = execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (out) return out;
  } catch {}
  return null;
}

const resolveIssueToken = () => process.env.ISSUE_TOKEN || resolveToken();

// Inject GitHub PAT via env HTTP header instead of CLI URL arguments.
function gitAuthEnv(token) {
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
  if (token) {
    const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = 'http.https://github.com/.extraheader';
    env.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${basic}`;
  }
  return env;
}

function cloneShallow(owner, repoName, destDir, token) {
  const url = `https://github.com/${owner}/${repoName}.git`;
  execFileSync('git', ['clone', '--depth', '1', url, destDir], {
    stdio: 'ignore',
    env: gitAuthEnv(token),
  });
}

function cloneForPr(owner, repoName, destDir, token) {
  const url = `https://github.com/${owner}/${repoName}.git`;
  execFileSync('git', ['clone', '--depth', '20', url, destDir], {
    stdio: 'ignore',
    env: gitAuthEnv(token),
  });
}

async function notify(config, summary, hasIssues, isDryRun) {
  if (isDryRun || !hasIssues) return;
  const slack = config.notify?.slack || process.env.SLACK_WEBHOOK;
  const discord = config.notify?.discord || process.env.DISCORD_WEBHOOK;
  if (!slack && !discord) return;

  const t = summary.totals;
  const parts = [];
  if (t.vulns) parts.push(`${t.vulns} CVE(s)`);
  if (t.secrets + t.historySecrets) parts.push(`${t.secrets + t.historySecrets} secret(s)`);
  if (t.workflowRisks) parts.push(`${t.workflowRisks} workflow risk(s)`);
  if (t.githubAlerts) parts.push(`${t.githubAlerts} GitHub alert(s)`);
  if (summary.failedRepos.length) parts.push(`${summary.failedRepos.length} unreachable`);

  const text = `*Repo Watch* (@${config.owner}) — ${parts.join(', ')} across ${summary.total} repo(s).`;
  const post = (url, body) => fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).catch(e => warn(`notify failed: ${sanitize(e.message)}`));

  if (slack) await post(slack, { text });
  if (discord) await post(discord, { content: text.replace(/\*/g, '**') });
}

class GitHubClient {
  constructor(token) {
    this.token = token;
    this.baseUrl = 'https://api.github.com';
  }

  async request(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`;
    const headers = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'authormark-watch/2.0 (+https://github.com/Srinivasan-78/authormark-watch)',
      ...(options.headers || {}),
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;

    const maxAttempts = options.retries ?? 4;
    let lastErr = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      let res;
      try {
        res = await fetch(url, { ...options, headers });
      } catch (e) {
        lastErr = new Error(`GitHub API error: ${sanitize(e.message)}`);
        if (attempt < maxAttempts) { await sleep(backoffMs(attempt)); continue; }
        throw lastErr;
      }

      if (res.status === 204) return null;
      const retryable = res.status === 429 || res.status >= 500 ||
        (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0');
      if (retryable && attempt < maxAttempts) {
        await sleep(rateLimitDelayMs(res, attempt));
        continue;
      }

      const data = await res.json().catch(() => null);
      if (!res.ok) {
        const msg = data?.message || `HTTP ${res.status}`;
        throw new Error(`${options.method || 'GET'} ${endpoint} failed (${res.status}): ${sanitize(msg)}`);
      }
      return data;
    }
    throw lastErr || new Error(`GitHub API error: exhausted retries for ${endpoint}`);
  }

  async listRepos(owner) {
    const repos = [];
    const base = this.token
      ? '/user/repos?affiliation=owner&per_page=100&sort=pushed'
      : `/users/${owner}/repos?per_page=100&sort=pushed`;
    for (let page = 1; ; page++) {
      const batch = await this.request(`${base}&page=${page}`);
      if (!Array.isArray(batch) || batch.length === 0) break;
      for (const r of batch) {
        if (!r.owner || String(r.owner.login).toLowerCase() === String(owner).toLowerCase()) repos.push(r);
      }
      if (batch.length < 100) break;
    }
    return repos;
  }

  getRepo(owner, repo) {
    return this.request(`/repos/${owner}/${repo}`);
  }

  async countOpenAlerts(owner, repo) {
    const result = { dependabot: 0, codeScanning: 0, secretScanning: 0, vulnerabilityAlertsDisabled: false };
    const fetchLen = async p => {
      try { const d = await this.request(p, { retries: 1 }); return Array.isArray(d) ? d.length : 0; }
      catch { return 0; }
    };
    result.dependabot = await fetchLen(`/repos/${owner}/${repo}/dependabot/alerts?state=open&per_page=100`);
    result.codeScanning = await fetchLen(`/repos/${owner}/${repo}/code-scanning/alerts?state=open&per_page=100`);
    result.secretScanning = await fetchLen(`/repos/${owner}/${repo}/secret-scanning/alerts?state=open&per_page=100`);
    try { await this.request(`/repos/${owner}/${repo}/vulnerability-alerts`, { retries: 1 }); }
    catch (e) { if (/\(404\)/.test(e.message)) result.vulnerabilityAlertsDisabled = true; }
    return result;
  }

  async getRepoPosture(owner, repo, repoInfo) {
    const branch = repoInfo?.default_branch || 'main';
    let branchProtected = null;
    try {
      await this.request(`/repos/${owner}/${repo}/branches/${encodeURIComponent(branch)}/protection`, { retries: 1 });
      branchProtected = true;
    } catch (e) {
      if (/\(404\)/.test(e.message)) branchProtected = false;
    }

    let openPrs = 0;
    let dependabotPrs = 0;
    try {
      const prs = (await this.request(`/repos/${owner}/${repo}/pulls?state=open&per_page=100`, { retries: 1 })) || [];
      openPrs = prs.length;
      dependabotPrs = prs.filter(p => p.user?.login === 'dependabot[bot]').length;
    } catch {}

    const sec = repoInfo?.security_and_analysis;
    return {
      branchProtected,
      pushProtection: sec?.secret_scanning_push_protection?.status === 'enabled' ? true
        : sec?.secret_scanning_push_protection?.status === 'disabled' ? false : null,
      openPrs,
      dependabotPrs,
    };
  }

  async findTrackingIssue(owner, repo, prefixes = ['watch:', 'authormark:']) {
    try {
      const issues = (await this.request(`/repos/${owner}/${repo}/issues?state=open&per_page=50`)) || [];
      return issues.find(i => !i.pull_request && prefixes.some(p => i.title.startsWith(p)));
    } catch { return null; }
  }

  createIssue(owner, repo, title, body, labels = []) {
    return this.request(`/repos/${owner}/${repo}/issues`, { method: 'POST', body: JSON.stringify({ title, body, labels }) });
  }

  updateIssue(owner, repo, issueNumber, { title, body, state }) {
    const payload = {};
    if (title !== undefined) payload.title = title;
    if (body !== undefined) payload.body = body;
    if (state !== undefined) payload.state = state;
    return this.request(`/repos/${owner}/${repo}/issues/${issueNumber}`, { method: 'PATCH', body: JSON.stringify(payload) });
  }

  addComment(owner, repo, issueNumber, body) {
    return this.request(`/repos/${owner}/${repo}/issues/${issueNumber}/comments`, { method: 'POST', body: JSON.stringify({ body }) });
  }

  async syncLabels(owner, repo, labels) {
    let existing = new Set();
    try {
      const list = (await this.request(`/repos/${owner}/${repo}/labels?per_page=100`, { retries: 1 })) || [];
      existing = new Set(list.map(l => String(l.name).toLowerCase()));
    } catch { return { added: 0, skipped: labels.length }; }

    let added = 0;
    for (const lbl of labels) {
      if (existing.has(lbl.name.toLowerCase())) continue;
      try {
        await this.request(`/repos/${owner}/${repo}/labels`, { method: 'POST', body: JSON.stringify(lbl), retries: 1 });
        added++;
      } catch {}
    }
    return { added, skipped: labels.length - added };
  }

  async findOpenPrByBranch(owner, repo, headBranch) {
    try {
      const prs = (await this.request(`/repos/${owner}/${repo}/pulls?state=open&head=${encodeURIComponent(`${owner}:${headBranch}`)}&per_page=10`)) || [];
      return prs[0] || null;
    } catch { return null; }
  }

  createPullRequest(owner, repo, { title, body, head, base }) {
    return this.request(`/repos/${owner}/${repo}/pulls`, {
      method: 'POST',
      body: JSON.stringify({ title, body, head, base }),
    });
  }

  updatePullRequest(owner, repo, prNumber, { title, body }) {
    return this.request(`/repos/${owner}/${repo}/pulls/${prNumber}`, {
      method: 'PATCH',
      body: JSON.stringify({ title, body }),
    });
  }
}

export {
  log, warn, errLog, sanitize, backoffMs, rateLimitDelayMs,
  resolveToken, resolveIssueToken, gitAuthEnv, cloneShallow, cloneForPr, notify, GitHubClient,
};
