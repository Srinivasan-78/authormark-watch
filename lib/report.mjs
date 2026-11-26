import fs from 'node:fs';
import path from 'node:path';

const SNAPSHOT_RE = /<!--\s*watch-snapshot:(\{[\s\S]*?\})\s*-->/;

function buildSnapshot(summary) {
  const repos = {};
  for (const r of summary.repos) {
    const cveIds = [];
    for (const p of r.vulns) {
      for (const v of p.vulns) cveIds.push(`${p.name}@${p.version}:${v.cve || v.id}`);
    }
    repos[r.name] = {
      sha: r.metadata.headSha || null,
      cves: cveIds.sort(),
      sec: r.findings.secrets.length + r.findings.historySecrets.length,
      wf: r.findings.workflowRisks.length,
      alerts: r.githubAlertsCount,
    };
  }
  return { time: summary.scannedTime, repos };
}

function extractSnapshotFromText(text) {
  if (!text) return null;
  const m = String(text).match(SNAPSHOT_RE);
  if (!m) return null;
  try { return JSON.parse(m[1]); }
  catch { return null; }
}

function diffSnapshots(prev, curr) {
  if (!prev?.repos) return [];
  const changes = [];
  for (const [name, cur] of Object.entries(curr.repos)) {
    const old = prev.repos[name];
    if (!old) { changes.push(`Added repo \`${name}\``); continue; }
    if (old.sha && cur.sha && old.sha !== cur.sha) changes.push(`\`${name}\`: commit \`${old.sha}\` -> \`${cur.sha}\``);
    const oldSet = new Set(old.cves || []);
    const curSet = new Set(cur.cves || []);
    const newCves = [...curSet].filter(x => !oldSet.has(x));
    const fixedCves = [...oldSet].filter(x => !curSet.has(x));
    if (newCves.length) changes.push(`\`${name}\`: **+${newCves.length} new CVE(s)** (${newCves.slice(0, 4).join(', ')})`);
    if (fixedCves.length) changes.push(`\`${name}\`: resolved ${fixedCves.length} CVE(s)`);
    if (cur.sec > old.sec) changes.push(`\`${name}\`: **+${cur.sec - old.sec} secret finding(s)**`);
    if (cur.wf > old.wf) changes.push(`\`${name}\`: **+${cur.wf - old.wf} workflow risk(s)**`);
    if (cur.alerts > old.alerts) changes.push(`\`${name}\`: **+${cur.alerts - old.alerts} GitHub alert(s)**`);
  }
  for (const oldName of Object.keys(prev.repos)) {
    if (!curr.repos[oldName]) changes.push(`Removed/excluded repo \`${oldName}\``);
  }
  return changes;
}

function buildMarkdownReport(config, summary, { embedSnapshot = false } = {}) {
  const lines = [];
  const t = summary.totals;
  const problemCount = t.vulns + t.secrets + t.historySecrets + t.workflowRisks + t.integrity + t.githubAlerts + summary.failedRepos.length;

  lines.push(`# Repository Security & Status Monitor (@${config.owner})`);
  lines.push(`\nScanned **${summary.total}** repository(ies) at \`${summary.scannedTime}\`.\n`);
  lines.push(problemCount === 0
    ? `> **All Clear**: No vulnerabilities, leaked secrets, workflow risks, or GitHub alerts detected across **${summary.total}** repo(s).\n`
    : `> **Attention Needed**: **${t.vulns}** CVE(s), **${t.secrets + t.historySecrets}** secret finding(s), **${t.workflowRisks}** workflow risk(s), **${t.githubAlerts}** GitHub alert(s), **${t.integrity}** config/hygiene note(s).\n`);

  if (summary.changes?.length) {
    lines.push('## Changes Since Last Scan\n');
    for (const c of summary.changes) lines.push(`- ${c}`);
    lines.push('');
  }

  const actionable = summary.repos.filter(r =>
    r.vulns.length || r.findings.secrets.length || r.findings.historySecrets.length ||
    r.findings.workflowRisks.length || r.findings.integrity.length || r.githubAlertsCount > 0 || r.vulnerabilityAlertsDisabled);

  if (actionable.length) {
    lines.push('## Security & Vulnerability Findings\n');
    for (const r of actionable) {
      lines.push(`### \`${r.name}\``);
      if (r.vulns.length) {
        lines.push('- **Dependency Vulnerabilities**:');
        for (const p of r.vulns) {
          for (const v of p.vulns) {
            const label = v.cve ? `${v.id} / ${v.cve}` : v.id;
            lines.push(`  - \`${p.name}@${p.version}\` (${p.ecosystem}): [${label}](${v.url}) [${v.severity}] — ${v.summary}`);
          }
        }
      }
      if (r.osvStatus === 'unavailable') lines.push('- **OSV Check**: unavailable during this run (network/API error)');
      const addList = (title, items) => {
        if (!items?.length) return;
        lines.push(`- **${title}**:`);
        for (const s of items) lines.push(`  - ${s}`);
      };
      addList('Secrets / Tokens', r.findings.secrets);
      addList('Secrets in Git History', r.findings.historySecrets);
      addList('Workflow Security Risks', r.findings.workflowRisks);
      if (r.githubAlertsCount > 0 || r.vulnerabilityAlertsDisabled) {
        const a = r.githubAlerts;
        const bits = [];
        if (a.dependabot) bits.push(`${a.dependabot} Dependabot`);
        if (a.codeScanning) bits.push(`${a.codeScanning} code-scanning`);
        if (a.secretScanning) bits.push(`${a.secretScanning} secret-scanning`);
        if (a.vulnerabilityAlertsDisabled) bits.push('Dependabot alerts disabled');
        lines.push(`- **GitHub Security Alerts**: ${bits.join(', ')}`);
      }
      addList('Integrity / Policy', r.findings.integrity);
      lines.push('');
    }
  }

  if (summary.repos.length) {
    lines.push('## Repository Inventory\n');
    lines.push('| Repository | Visibility | Language | Last Push | HEAD | Files | Deps | CVEs | PRs (Dep) | Protected | Alerts | Status |');
    lines.push('|------------|------------|----------|-----------|------|------:|-----:|-----:|----------:|-----------|-------:|--------|');
    for (const r of summary.repos) {
      const m = r.metadata;
      const p = r.posture || {};
      const pushCol = m.pushedAt ? `${m.pushedAt}${m.stale ? ' (stale)' : ''}` : '-';
      const prCol = Number.isFinite(p.openPrs) ? `${p.openPrs}${p.dependabotPrs ? ` (${p.dependabotPrs})` : ''}` : '-';
      const protCol = p.branchProtected === true ? 'yes' : p.branchProtected === false ? 'no' : '-';
      const issueSum = r.cveCount + r.findings.secrets.length + r.findings.historySecrets.length +
        r.findings.workflowRisks.length + r.findings.integrity.length + r.githubAlertsCount;
      const status = issueSum === 0 && !r.vulnerabilityAlertsDisabled ? 'OK' : 'WARN';
      lines.push(`| \`${r.name}\` | ${m.visibility} | ${m.language || '-'} | ${pushCol} | ${m.headSha ? `\`${m.headSha}\`` : '-'} | ${m.fileCount} | ${r.depCount} | ${r.cveCount} | ${prCol} | ${protCol} | ${r.githubAlertsCount} | ${status} |`);
    }
    lines.push('');
  }

  if (summary.failedRepos.length) {
    lines.push('## Unreachable Repositories\n');
    for (const r of summary.failedRepos) lines.push(`- \`${r.name}\`: ${r.reason}`);
    lines.push('');
  }

  lines.push('---');
  lines.push('*Generated by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*');
  if (embedSnapshot && summary.snapshot) {
    lines.push(`<!-- watch-snapshot:${JSON.stringify(summary.snapshot)} -->`);
  }
  return lines.join('\n');
}

function buildPortfolioAuditReport(owner, scannedTime, results) {
  const lines = [];
  lines.push(`# Portfolio Engineering & DevSecOps Health Report (@${owner})`);
  lines.push('');
  lines.push(`Generated at \`${scannedTime}\` across **${results.length}** repository(ies).`);
  lines.push('');
  lines.push('| Repository | Stack | Pass | Needs Work | Blocked | Patches | PR Status |');
  lines.push('|---|---|---:|---:|---:|---:|---|');

  for (const r of results) {
    const sc = r.audit?.scorecard || [];
    const passCount = sc.filter(s => s.status === 'Pass').length;
    const nwCount = sc.filter(s => s.status === 'Needs Work').length;
    const blkCount = sc.filter(s => s.status === 'Blocked').length;
    const stackStr = r.audit?.stack?.languages?.join(', ') || 'docs';
    const prCell = r.prUrl ? `[${r.prAction}](${r.prUrl})` : r.prAction;
    lines.push(`| \`${r.repo}\` | ${stackStr} | ${passCount} | ${nwCount} | ${blkCount} | ${r.patchesCount} | ${prCell} |`);
  }
  lines.push('');
  lines.push('---');
  lines.push('*Generated by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*');
  return lines.join('\n');
}

function writePortfolioReports(reportsDir, owner, scannedTime, results) {
  fs.mkdirSync(reportsDir, { recursive: true });
  const portfolioMd = buildPortfolioAuditReport(owner, scannedTime, results);
  fs.writeFileSync(path.join(reportsDir, 'PORTFOLIO_REPORT.md'), portfolioMd + '\n', 'utf8');
  for (const r of results) {
    if (r.reportMarkdown) {
      fs.writeFileSync(path.join(reportsDir, `${r.repo}.md`), r.reportMarkdown + '\n', 'utf8');
    }
  }
  return path.join(reportsDir, 'PORTFOLIO_REPORT.md');
}

export {
  buildSnapshot, extractSnapshotFromText, diffSnapshots, buildMarkdownReport,
  buildPortfolioAuditReport, writePortfolioReports,
};
