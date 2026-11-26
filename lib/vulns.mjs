import fs from 'node:fs';
import path from 'node:path';

function addPkg(map, name, version, ecosystem, source) {
  if (!name || !version) return;
  const cleanVer = String(version).trim();
  if (!cleanVer || cleanVer === '*') return;
  const key = `${ecosystem}:${name}@${cleanVer}`;
  if (!map.has(key)) map.set(key, { name, version: cleanVer, ecosystem, source });
}

function parseNpmLock(repoDir, map) {
  const p = path.join(repoDir, 'package-lock.json');
  if (!fs.existsSync(p)) return false;
  let data;
  try { data = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return false; }

  if (data.packages && typeof data.packages === 'object') {
    for (const [pkgPath, meta] of Object.entries(data.packages)) {
      if (!pkgPath || !meta?.version) continue;
      const idx = pkgPath.lastIndexOf('node_modules/');
      const name = idx >= 0 ? pkgPath.slice(idx + 'node_modules/'.length) : (meta.name || pkgPath);
      addPkg(map, name, meta.version, 'npm', 'package-lock.json');
    }
    return true;
  }

  const walkDeps = deps => {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, meta] of Object.entries(deps)) {
      if (meta?.version && !meta.version.startsWith('file:')) addPkg(map, name, meta.version, 'npm', 'package-lock.json');
      if (meta?.dependencies) walkDeps(meta.dependencies);
    }
  };
  walkDeps(data.dependencies);
  return true;
}

function parsePnpmLock(repoDir, map) {
  const p = path.join(repoDir, 'pnpm-lock.yaml');
  if (!fs.existsSync(p)) return false;
  let text;
  try { text = fs.readFileSync(p, 'utf8'); }
  catch { return false; }

  let inPackages = false;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (/^packages:\s*$/.test(line)) { inPackages = true; continue; }
    if (inPackages && /^\S/.test(line)) { inPackages = false; continue; }
    if (!inPackages) continue;
    const m = line.match(/^  ['"]?\/?([^'"(\s]+?)['"]?:\s*$/);
    if (!m) continue;
    const spec = m[1].split('(')[0];
    // Handles v6/v9 `pkg@1.2.3` / `@scope/pkg@1.2.3` and v5 `pkg/1.2.3`.
    const atIdx = spec.lastIndexOf('@');
    if (atIdx > 0) {
      addPkg(map, spec.slice(0, atIdx), spec.slice(atIdx + 1), 'npm', 'pnpm-lock.yaml');
    } else {
      const slashIdx = spec.lastIndexOf('/');
      if (slashIdx > 0) {
        const ver = spec.slice(slashIdx + 1);
        if (/^\d/.test(ver)) addPkg(map, spec.slice(0, slashIdx), ver, 'npm', 'pnpm-lock.yaml');
      }
    }
  }
  return true;
}

function parseYarnLock(repoDir, map) {
  const p = path.join(repoDir, 'yarn.lock');
  if (!fs.existsSync(p)) return false;
  let text;
  try { text = fs.readFileSync(p, 'utf8'); }
  catch { return false; }

  let curNames = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (!line || line.startsWith('#') || line.startsWith('__metadata:')) continue;
    if (/^\S/.test(line) && line.endsWith(':')) {
      const header = line.slice(0, -1);
      curNames = header.split(',').map(part => {
        const s = part.trim().replace(/^['"]|['"]$/g, '');
        const idx = s.lastIndexOf('@');
        return idx > 0 ? s.slice(0, idx) : '';
      }).filter(Boolean);
      continue;
    }
    const vm = line.match(/^\s{2}version(?::\s*|\s+)['"]?([^\s'"]+)['"]?/);
    if (vm && curNames.length) {
      for (const name of new Set(curNames)) addPkg(map, name, vm[1], 'npm', 'yarn.lock');
      curNames = [];
    }
  }
  return true;
}

function parsePackageJsonPinned(repoDir, map) {
  const p = path.join(repoDir, 'package.json');
  if (!fs.existsSync(p)) return;
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return; }
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = pkg[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, ver] of Object.entries(deps)) {
      if (typeof ver === 'string' && /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(ver.trim())) {
        addPkg(map, name, ver.trim(), 'npm', 'package.json');
      }
    }
  }
}

function parseRequirementsTxt(repoDir, map) {
  let files = [];
  try { files = fs.readdirSync(repoDir).filter(f => /^requirements.*\.txt$/i.test(f)); }
  catch { return; }
  for (const file of files) {
    let text;
    try { text = fs.readFileSync(path.join(repoDir, file), 'utf8'); }
    catch { continue; }
    for (const rawLine of text.split('\n')) {
      const line = rawLine.replace(/#.*$/, '').replace(/;.*$/, '').trim();
      if (!line || line.startsWith('-')) continue;
      const m = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([^\s,]+)$/);
      if (m) addPkg(map, m[1], m[2], 'PyPI', file);
    }
  }
}

function parseGoMod(repoDir, map) {
  const p = path.join(repoDir, 'go.mod');
  if (!fs.existsSync(p)) return;
  let text;
  try { text = fs.readFileSync(p, 'utf8'); }
  catch { return; }
  let inBlock = false;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (/^require\s*\($/.test(line)) { inBlock = true; continue; }
    if (inBlock && line === ')') { inBlock = false; continue; }
    const target = inBlock ? line : (line.startsWith('require ') ? line.slice(8).trim() : null);
    if (!target) continue;
    const m = target.match(/^(\S+)\s+(v[^\s]+)/);
    if (m) addPkg(map, m[1], m[2].replace(/\+incompatible$/, ''), 'Go', 'go.mod');
  }
}

function parseTomlPackages(repoDir, filename, ecosystem, map) {
  const p = path.join(repoDir, filename);
  if (!fs.existsSync(p)) return;
  let text;
  try { text = fs.readFileSync(p, 'utf8'); }
  catch { return; }
  for (const block of text.split(/\[\[package\]\]/)) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) addPkg(map, name, version, ecosystem, filename);
  }
}

function parseDependencies(repoDir) {
  const map = new Map();
  const hasNpmLock = parseNpmLock(repoDir, map) || parsePnpmLock(repoDir, map) || parseYarnLock(repoDir, map);
  if (!hasNpmLock) parsePackageJsonPinned(repoDir, map);
  parseRequirementsTxt(repoDir, map);
  parseGoMod(repoDir, map);
  parseTomlPackages(repoDir, 'Cargo.lock', 'crates.io', map);
  parseTomlPackages(repoDir, 'poetry.lock', 'PyPI', map);
  parseTomlPackages(repoDir, 'uv.lock', 'PyPI', map);
  return [...map.values()];
}

function extractSeverity(vuln) {
  const dbSev = vuln?.database_specific?.severity;
  if (typeof dbSev === 'string' && dbSev) return dbSev.toUpperCase();
  const cvss = Array.isArray(vuln?.severity) ? vuln.severity[0]?.score : null;
  if (cvss) return String(cvss);
  return 'UNKNOWN';
}

async function fetchJsonWithTimeout(url, options, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await options.fetchImpl(url, { ...options.init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function queryOsvVulnerabilities(packages, { fetchImpl = fetch, timeoutMs = 15000 } = {}) {
  if (!packages?.length) return { status: 'ok', checked: 0, findings: [] };

  const matched = [];
  const uniqueIds = new Set();

  for (let i = 0; i < packages.length; i += 500) {
    const chunk = packages.slice(i, i + 500);
    let res;
    try {
      res = await fetchJsonWithTimeout('https://api.osv.dev/v1/querybatch', {
        fetchImpl,
        init: {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            queries: chunk.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
          }),
        },
      }, timeoutMs);
    } catch (e) {
      return { status: 'unavailable', error: e.message, checked: packages.length, findings: [] };
    }
    if (!res.ok) {
      return { status: 'unavailable', error: `OSV API HTTP ${res.status}`, checked: packages.length, findings: [] };
    }
    const data = await res.json().catch(() => null);
    const results = data?.results || [];
    chunk.forEach((pkg, idx) => {
      const vulns = results[idx]?.vulns;
      if (Array.isArray(vulns) && vulns.length) {
        const ids = vulns.map(v => v.id).filter(Boolean);
        if (ids.length) {
          matched.push({ pkg, ids });
          for (const id of ids) if (uniqueIds.size < 25) uniqueIds.add(id);
        }
      }
    });
  }

  const details = new Map();
  await Promise.all([...uniqueIds].map(async id => {
    try {
      const res = await fetchJsonWithTimeout(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
        fetchImpl,
        init: { method: 'GET' },
      }, timeoutMs);
      if (res.ok) details.set(id, await res.json());
    } catch {}
  }));

  const findings = matched.map(({ pkg, ids }) => ({
    name: pkg.name,
    version: pkg.version,
    ecosystem: pkg.ecosystem,
    source: pkg.source,
    vulns: ids.map(id => {
      const d = details.get(id);
      const cve = (d?.aliases || []).find(a => /^CVE-/i.test(a)) || null;
      return {
        id,
        cve,
        severity: d ? extractSeverity(d) : 'UNKNOWN',
        summary: d?.summary || d?.details?.split('\n')[0]?.slice(0, 120) || 'Vulnerability reported in OSV',
        url: `https://osv.dev/vulnerability/${id}`,
      };
    }),
  }));

  return { status: 'ok', checked: packages.length, findings };
}

export { parseDependencies, queryOsvVulnerabilities };
