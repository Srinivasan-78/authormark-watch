import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

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
  { name: 'Private Key', regex: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/ },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z_]+\/B[0-9A-Z_]+\/[0-9A-Za-z]+/ },
  { name: 'Discord Webhook', regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/ },
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'npm Access Token', regex: /npm_[A-Za-z0-9]{36}/ },
  { name: 'Generic JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
];

const HISTORY_SECRET_RE = 'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_\\-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk_live_[0-9a-zA-Z]{24}';
const UNTRUSTED_EVENT_RE = /\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|pull_request\.head\.label|comment\.body|review\.body|head_commit\.message|pages|commits)/;

function matchPattern(relPath, patterns = []) {
  const norm = relPath.replace(/\\/g, '/');
  return patterns.some(pat => {
    let p = String(pat).replace(/\\/g, '/');
    while (p.endsWith('/')) p = p.slice(0, -1);
    if (!p) return false;
    if (norm === p || norm.startsWith(`${p}/`)) return true;
    const rx = p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*');
    return new RegExp(`^${rx}(/|$)`).test(norm);
  });
}

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

function repoTargetFiles(repoDir) {
  if (fs.existsSync(path.join(repoDir, '.git'))) {
    try {
      const out = execFileSync('git', ['ls-files', '-z'], {
        cwd: repoDir,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      return out.split('\0').filter(Boolean).map(p => path.join(repoDir, p)).filter(p => fs.existsSync(p));
    } catch {}
  }
  return walkFiles(repoDir);
}

function auditWorkflow(text, file) {
  const risks = [];
  const lines = String(text).split('\n').map(r => r.replace(/\r$/, ''));

  const hasPrTarget = lines.some(l => {
    const t = l.trimStart();
    return t.startsWith('pull_request_target') && t.slice('pull_request_target'.length).trimStart().startsWith(':');
  });
  const hasCheckout = text.includes('actions/checkout');
  const hasHeadRef = text.includes('github.event.pull_request.head');
  if (hasPrTarget && hasCheckout && hasHeadRef) {
    risks.push(`\`${file}\`: \`pull_request_target\` checks out PR head code — runs untrusted code with a write token`);
  }

  const unpinned = new Set();
  for (const l of lines) {
    const t = l.trimStart().replace(/^-\s*/, '');
    if (!t.startsWith('uses:')) continue;
    const val = t.slice('uses:'.length).split('#')[0].trim().replace(/^['"]|['"]$/g, '');
    const atIdx = val.indexOf('@');
    if (atIdx <= 0) continue;
    const action = val.slice(0, atIdx);
    const ref = val.slice(atIdx + 1);
    if (action.startsWith('./') || action.startsWith('docker://') || /^[0-9a-f]{40}$/.test(ref)) continue;
    unpinned.add(`${action}@${ref}`);
  }
  if (unpinned.size) risks.push(`\`${file}\`: ${unpinned.size} unpinned action ref(s): ${[...unpinned].slice(0, 6).join(', ')}`);

  const hasWriteAll = lines.some(l => l.trim().startsWith('permissions:') && l.includes('write-all'));
  const hasPermissions = lines.some(l => l.trimStart().startsWith('permissions:'));
  if (hasWriteAll) risks.push(`\`${file}\`: \`permissions: write-all\` — grant least privilege instead`);
  else if (!hasPermissions) risks.push(`\`${file}\`: no top-level \`permissions:\` — job inherits broad default token`);

  let runIndent = -1;
  for (const l of lines) {
    const indent = l.length - l.trimStart().length;
    const trimmed = l.trimStart();
    const afterDash = trimmed.startsWith('- ') ? trimmed.slice(2).trimStart() : trimmed;
    if (afterDash.startsWith('run:')) {
      const val = afterDash.slice('run:'.length).trim();
      if (UNTRUSTED_EVENT_RE.test(val)) {
        risks.push(`\`${file}\`: untrusted \`\${{ github.event.* }}\` in \`run:\` — pass via \`env:\` instead`);
        break;
      }
      runIndent = (!val || val.startsWith('|') || val.startsWith('>')) ? indent : -1;
      continue;
    }
    if (runIndent >= 0) {
      if (!trimmed || trimmed.startsWith('#')) continue;
      if (indent <= runIndent) { runIndent = -1; continue; }
      if (UNTRUSTED_EVENT_RE.test(l)) {
        risks.push(`\`${file}\`: untrusted \`\${{ github.event.* }}\` in \`run:\` — pass via \`env:\` instead`);
        break;
      }
    }
  }

  if (/(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b/.test(text)) {
    risks.push(`\`${file}\`: pipes a network download straight into a shell`);
  }
  return risks;
}

function scanGitHistory(repoDir, ignoreSecrets = []) {
  const out = [];
  try {
    const shas = execFileSync(
      'git',
      ['log', '--all', '--no-merges', '-n', '400', '--format=%H', '-G', HISTORY_SECRET_RE],
      { cwd: repoDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).split('\n').filter(Boolean).slice(0, 15);
    const re = new RegExp(HISTORY_SECRET_RE);
    for (const sha of shas) {
      let diff = '';
      try {
        diff = execFileSync('git', ['show', '--no-color', '--format=', sha], { cwd: repoDir, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
      } catch { continue; }
      let file = '';
      for (const l of diff.split('\n')) {
        const fm = l.match(/^\+\+\+ b\/(.+)/);
        if (fm) { file = fm[1]; continue; }
        if (l.startsWith('+') && !l.startsWith('+++') && re.test(l) &&
          !/\.(md|test|spec|example|sample)\b/.test(file) && !matchPattern(file, ignoreSecrets)) {
          out.push(`Secret-shaped string in \`${file}\` at commit \`${sha.slice(0, 10)}\` (in git history)`);
          break;
        }
      }
      if (out.length >= 10) break;
    }
  } catch {}
  return out;
}

function gitHeadInfo(repoDir) {
  if (!fs.existsSync(path.join(repoDir, '.git'))) return { headSha: null, headDate: null, headSubject: null };
  try {
    const out = execFileSync('git', ['log', '-1', '--format=%h\t%cs\t%s'], {
      cwd: repoDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const [headSha, headDate, headSubject] = out.split('\t');
    return {
      headSha: headSha || null,
      headDate: headDate || null,
      headSubject: headSubject ? headSubject.slice(0, 60) : null,
    };
  } catch { return { headSha: null, headDate: null, headSubject: null }; }
}

function scanRepository(repoDir, repoMeta = {}, checks = {}, allowlist = {}) {
  const findings = {
    secrets: [],
    historySecrets: [],
    workflowRisks: [],
    integrity: [],
  };
  const ignoreSecrets = allowlist.ignoreSecrets || [];
  const files = repoTargetFiles(repoDir);
  const hasFile = name => fs.existsSync(path.join(repoDir, name));

  const ecosystems = [];
  if (hasFile('package.json')) ecosystems.push('npm');
  if (hasFile('requirements.txt') || hasFile('pyproject.toml') || hasFile('poetry.lock') || hasFile('uv.lock')) ecosystems.push('pip');
  if (hasFile('go.mod')) ecosystems.push('go');
  if (hasFile('Cargo.toml')) ecosystems.push('cargo');

  if (checks.workflows !== false) {
    const wfDir = path.join(repoDir, '.github', 'workflows');
    if (fs.existsSync(wfDir)) {
      for (const wf of fs.readdirSync(wfDir)) {
        if (!/\.ya?ml$/.test(wf)) continue;
        try { findings.workflowRisks.push(...auditWorkflow(fs.readFileSync(path.join(wfDir, wf), 'utf8'), `.github/workflows/${wf}`)); }
        catch {}
      }
    }
  }

  if (checks.gitHistorySecrets !== false) {
    findings.historySecrets.push(...scanGitHistory(repoDir, ignoreSecrets));
  }

  if (checks.integrity !== false) {
    if (!hasFile('.gitignore')) findings.integrity.push('Missing `.gitignore`');
    if (!['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'].some(hasFile)) findings.integrity.push('Missing `SECURITY.md`');
    const dbRel = hasFile('.github/dependabot.yml') ? '.github/dependabot.yml' : hasFile('.github/dependabot.yaml') ? '.github/dependabot.yaml' : null;
    if (dbRel) {
      try {
        const db = fs.readFileSync(path.join(repoDir, dbRel), 'utf8');
        if (db.includes('package-ecosystem') && !db.includes('groups:')) findings.integrity.push(`\`${dbRel}\` is ungrouped`);
      } catch {}
    }
  }

  let totalBytes = 0;
  for (const file of files) {
    const rPath = path.relative(repoDir, file).replace(/\\/g, '/');
    const basename = path.basename(file);
    const ext = path.extname(file).toLowerCase();
    const skipSecret = matchPattern(rPath, ignoreSecrets);

    if (checks.secrets !== false && !skipSecret && (basename === '.env' || basename === '.env.local' || basename === '.env.production')) {
      findings.secrets.push(`Committed env file: \`${rPath}\``);
    }
    if (checks.integrity !== false && (basename.endsWith('.pyc') || rPath.includes('__pycache__') || basename === '.DS_Store' || basename === 'Thumbs.db')) {
      findings.integrity.push(`Tracked artifact: \`${rPath}\``);
    }

    let stat;
    try { stat = fs.statSync(file); totalBytes += stat.size; } catch { continue; }
    if (stat.size > 2 * 1024 * 1024) continue;

    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }

    if (checks.secrets !== false && !skipSecret && !rPath.endsWith('.md') && !content.includes('AIzaSyDummy') && !content.includes('your-api-key')) {
      for (const pat of SECRET_PATTERNS) {
        if (pat.regex.test(content)) findings.secrets.push(`Possible ${pat.name} in \`${rPath}\``);
      }
    }

    if (checks.integrity !== false && ext === '.json' && !basename.includes('package-lock') && !basename.includes('tsconfig')) {
      try { JSON.parse(content); }
      catch (err) { findings.integrity.push(`Invalid JSON in \`${rPath}\`: ${err.message}`); }
    }
  }

  const head = gitHeadInfo(repoDir);
  const pushedAt = repoMeta.pushed_at ? String(repoMeta.pushed_at).slice(0, 10) : (head.headDate || null);
  const daysSincePush = pushedAt ? Math.floor((Date.now() - Date.parse(pushedAt)) / 86400000) : null;

  const metadata = {
    name: repoMeta.name || path.basename(repoDir),
    visibility: repoMeta.private === true ? 'private' : repoMeta.private === false ? 'public' : 'local',
    language: repoMeta.language || null,
    defaultBranch: repoMeta.default_branch || null,
    pushedAt,
    stale: Number.isFinite(daysSincePush) && daysSincePush >= 90,
    headSha: head.headSha,
    headSubject: head.headSubject,
    fileCount: files.length,
    sizeKb: Math.round(totalBytes / 1024),
    ecosystems,
  };

  return { metadata, findings };
}

export {
  LINT_SKIP_DIRS, SECRET_PATTERNS, walkFiles, auditWorkflow,
  scanGitHistory, scanRepository,
};
