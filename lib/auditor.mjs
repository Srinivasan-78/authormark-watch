import fs from 'node:fs';
import path from 'node:path';
import { walkFiles } from './scanner.mjs';

const STANDARD_LABELS = [
  { name: 'bug', color: 'd73a4a', description: "Something isn't working" },
  { name: 'enhancement', color: 'a2eeef', description: 'New feature or request' },
  { name: 'security', color: 'b60205', description: 'Security vulnerability or hardening' },
  { name: 'documentation', color: '0075ca', description: 'Improvements or additions to documentation' },
  { name: 'testing', color: '1d76db', description: 'Test coverage and QA improvements' },
  { name: 'performance', color: 'fbca04', description: 'Performance and resource efficiency' },
  { name: 'refactoring', color: 'd4c5f9', description: 'Code quality and architecture cleanup' },
  { name: 'dependencies', color: '0366d6', description: 'Dependency updates and supply chain' },
  { name: 'good first issue', color: '7057ff', description: 'Good for newcomers' },
  { name: 'help wanted', color: '008672', description: 'Extra attention is needed' },
  { name: 'breaking change', color: 'e99695', description: 'Backward-incompatible change' },
  { name: 'technical debt', color: 'fef2c0', description: 'Known technical debt to address' },
];

function readJsonSafe(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return null; }
}

function readTextSafe(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); }
  catch { return ''; }
}

function detectStack(repoDir, repoMeta = {}) {
  const has = rel => fs.existsSync(path.join(repoDir, rel));
  const files = walkFiles(repoDir).map(f => path.relative(repoDir, f).replace(/\\/g, '/'));
  const pkg = has('package.json') ? readJsonSafe(path.join(repoDir, 'package.json')) : null;
  const pyproject = has('pyproject.toml') ? readTextSafe(path.join(repoDir, 'pyproject.toml')) : '';

  const hasTs = has('tsconfig.json') || files.some(f => /\.(ts|tsx|mts|cts)$/.test(f));
  const hasJs = Boolean(pkg) || files.some(f => /\.(js|mjs|cjs|jsx)$/.test(f));
  const hasPy = has('requirements.txt') || has('pyproject.toml') || has('setup.py') || files.some(f => f.endsWith('.py'));
  const hasGo = has('go.mod') || files.some(f => f.endsWith('.go'));
  const hasRust = has('Cargo.toml') || files.some(f => f.endsWith('.rs'));
  const hasDocker = has('Dockerfile') || files.some(f => {
    const base = path.posix.basename(f);
    return base === 'Dockerfile' || base.startsWith('Dockerfile.');
  });
  const hasIac = files.some(f => /\.(tf|tfvars)$/.test(f) || /^(k8s|kubernetes|helm|charts)\//.test(f));
  const hasHtml = files.some(f => /\.html?$/.test(f));

  const languages = [];
  if (hasTs) languages.push('typescript');
  else if (hasJs) languages.push('javascript');
  if (hasPy) languages.push('python');
  if (hasGo) languages.push('go');
  if (hasRust) languages.push('rust');
  if (hasDocker) languages.push('docker');
  if (hasHtml && languages.length === 0) languages.push('html');

  const codeqlLanguages = [];
  if (hasTs || hasJs) codeqlLanguages.push('javascript-typescript');
  if (hasPy) codeqlLanguages.push('python');
  if (hasGo) codeqlLanguages.push('go');
  if (hasRust) codeqlLanguages.push('rust');

  const ecosystems = [];
  if (pkg) ecosystems.push('npm');
  if (hasPy && (has('requirements.txt') || has('pyproject.toml') || has('poetry.lock') || has('uv.lock'))) ecosystems.push('pip');
  if (hasGo) ecosystems.push('gomod');
  if (hasRust) ecosystems.push('cargo');
  if (hasDocker) ecosystems.push('docker');
  if (files.some(f => f.startsWith('.github/workflows/') && /\.ya?ml$/.test(f))) ecosystems.push('github-actions');

  let packageManager = null;
  if (pkg) {
    if (has('pnpm-lock.yaml')) packageManager = 'pnpm';
    else if (has('yarn.lock')) packageManager = 'yarn';
    else packageManager = 'npm';
  } else if (hasPy) {
    if (has('uv.lock')) packageManager = 'uv';
    else if (has('poetry.lock')) packageManager = 'poetry';
    else packageManager = 'pip';
  } else if (hasGo) {
    packageManager = 'go';
  } else if (hasRust) {
    packageManager = 'cargo';
  }

  const testFiles = files.filter(f => /(^|\/)(test|tests|__tests__)\/|(\.|_)(test|spec)\.(js|mjs|cjs|ts|tsx|py|go|rs)$/.test(f));
  const hasTestScript = Boolean(pkg?.scripts?.test && !/no test specified/i.test(pkg.scripts.test));
  const hasTests = testFiles.length > 0 || hasTestScript;

  const linters = [];
  if (pkg && (has('.eslintrc') || has('.eslintrc.json') || has('.eslintrc.js') || has('eslint.config.js') || has('eslint.config.mjs') || pkg.devDependencies?.eslint)) {
    linters.push('eslint');
  }
  if (pkg && (has('.prettierrc') || has('.prettierrc.json') || pkg.devDependencies?.prettier)) {
    linters.push('prettier');
  }
  if (hasPy && (has('ruff.toml') || has('.ruff.toml') || /\[tool\.ruff\]/.test(pyproject))) {
    linters.push('ruff');
  }
  if (hasPy && (has('mypy.ini') || /\[tool\.mypy\]/.test(pyproject))) {
    linters.push('mypy');
  }

  const isProfileRepo = Boolean(
    repoMeta?.name && repoMeta?.owner?.login &&
    repoMeta.name.toLowerCase() === repoMeta.owner.login.toLowerCase(),
  );

  const isPublishable = Boolean(
    (pkg && pkg.private !== true && pkg.name && (pkg.bin || pkg.main || pkg.exports)) ||
    (/\[project\]/.test(pyproject) && /name\s*=/.test(pyproject)) ||
    hasDocker,
  );

  const targetsWindowsOrMac = Boolean(
    (Array.isArray(pkg?.os) && pkg.os.some(o => /win32|darwin/i.test(o))) ||
    files.some(f => /\.ps1$|\.bat$|\.cmd$|\.wix$/.test(f)),
  );

  return {
    languages,
    codeqlLanguages,
    ecosystems,
    packageManager,
    hasTests,
    testFilesCount: testFiles.length,
    linters,
    hasDockerfile: hasDocker,
    hasIac,
    isProfileRepo,
    isPublishable,
    targetsWindowsOrMac,
    fileCount: files.length,
    files,
    pkg,
    pyproject,
  };
}

function readWorkflows(repoDir) {
  const wfDir = path.join(repoDir, '.github', 'workflows');
  if (!fs.existsSync(wfDir)) return [];
  const out = [];
  for (const name of fs.readdirSync(wfDir)) {
    if (!/\.ya?ml$/.test(name)) continue;
    out.push({ name, path: `.github/workflows/${name}`, content: readTextSafe(path.join(wfDir, name)) });
  }
  return out;
}

function auditRepository(repoDir, repoMeta = {}, scanResult = {}, posture = null) {
  const stack = detectStack(repoDir, repoMeta);
  const has = rel => fs.existsSync(path.join(repoDir, rel));
  const workflows = readWorkflows(repoDir);
  const allWfText = workflows.map(w => w.content).join('\n');
  const findings = scanResult.findings || { secrets: [], historySecrets: [], workflowRisks: [], integrity: [] };

  const hasCiWorkflow = workflows.some(w => /ci|test|build|lint/i.test(w.name) || /pull_request/i.test(w.content));
  const hasCodeql = Boolean(posture?.codeqlDefaultSetup) || workflows.some(w => /codeql/i.test(w.name) || /github\/codeql-action/.test(w.content));
  const hasDepReview = workflows.some(w => /dependency-review/i.test(w.name) || /actions\/dependency-review-action/.test(w.content));
  const hasSecretScanWf = workflows.some(w => /gitleaks|trufflehog|secret/i.test(w.name) || /gitleaks\/gitleaks-action/.test(w.content));
  const hasReleaseWf = workflows.some(w => /release/i.test(w.name) || /release-please|semantic-release/.test(w.content));
  const hasCoverageInCi = /coverage|--experimental-test-coverage|pytest-cov|coverage\.xml|lcov/i.test(allWfText);
  const hasDependabot = has('.github/dependabot.yml') || has('.github/dependabot.yaml');
  const hasSecurityMd = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'].some(has);
  const hasLicense = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING'].some(has);
  const hasReadme = ['README.md', 'readme.md'].some(has);
  const hasContributing = ['CONTRIBUTING.md', '.github/CONTRIBUTING.md'].some(has);
  const hasCodeowners = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'].some(has);
  const hasPrTemplate = ['.github/PULL_REQUEST_TEMPLATE.md', '.github/pull_request_template.md'].some(has);
  const hasIssueTemplates = has('.github/ISSUE_TEMPLATE') && fs.readdirSync(path.join(repoDir, '.github', 'ISSUE_TEMPLATE')).length > 0;

  const cveCount = scanResult.cveCount || 0;
  const secretCount = (findings.secrets?.length || 0) + (findings.historySecrets?.length || 0);
  const wfRiskCount = findings.workflowRisks?.length || 0;
  const integrityCount = findings.integrity?.length || 0;

  const todos = [];
  const addTodo = (id, title, priority, category, autoFixable, reason, resolution) => {
    todos.push({ id, title, priority, category, autoFixable, reason, resolution });
  };

  if (secretCount > 0) {
    addTodo('SEC-01', 'Remediate detected secrets or git history leaks', 'Critical', 'Secret Scanning', false,
      `${secretCount} secret finding(s) detected.`, 'Rotate exposed credentials and rewrite/clean git history or add verified false-positive paths to .masterbot.json.');
  }
  if (cveCount > 0) {
    addTodo('SEC-02', 'Upgrade dependencies with known CVEs', 'High', 'Dependency Security', false,
      `${cveCount} OSV CVE(s) detected in dependencies.`, 'Run package manager audit/update and merge Dependabot security PRs.');
  }
  if (!hasCiWorkflow && !stack.isProfileRepo) {
    addTodo('CI-01', 'Add core CI workflow (lint, test, build)', 'High', 'CI/CD', true,
      'No CI workflow found for pull requests and default branch pushes.', 'Add .github/workflows/ci.yml tailored to detected stack.');
  }
  if (stack.codeqlLanguages.length > 0 && !hasCodeql) {
    addTodo('SEC-03', 'Enable GitHub CodeQL SAST workflow', 'High', 'CodeQL', true,
      `CodeQL supports ${stack.codeqlLanguages.join(', ')} but no CodeQL workflow exists.`, 'Add .github/workflows/codeql.yml with security-extended queries.');
  }
  if (!hasSecretScanWf && !stack.isProfileRepo) {
    addTodo('SEC-04', 'Add Gitleaks secret scanning workflow', 'High', 'Secret Scanning', true,
      'No automated CI secret-scanning workflow configured.', 'Add .github/workflows/secret-scan.yml.');
  }
  if (!hasDependabot && stack.ecosystems.length > 0) {
    addTodo('DEP-01', 'Configure grouped Dependabot updates', 'High', 'Dependency Security', true,
      `Missing .github/dependabot.yml for ecosystems: ${stack.ecosystems.join(', ')}.`, 'Add .github/dependabot.yml with weekly grouped minor/patch updates.');
  }
  if (!hasDepReview && stack.ecosystems.some(e => e !== 'github-actions')) {
    addTodo('DEP-02', 'Add Dependency Review workflow for PRs', 'Medium', 'Dependency Security', true,
      'Pull requests are not gated on newly introduced vulnerable dependencies.', 'Add .github/workflows/dependency-review.yml.');
  }
  if (!hasSecurityMd) {
    addTodo('SEC-05', 'Add SECURITY.md vulnerability reporting policy', 'Medium', 'Documentation', true,
      'Missing SECURITY.md.', 'Add SECURITY.md with responsible disclosure instructions.');
  }
  if (!hasLicense && !stack.isProfileRepo) {
    addTodo('LEG-01', 'Choose and add a repository LICENSE', 'High', 'Documentation', false,
      'No LICENSE file found. Auto-generation is intentionally skipped.', 'Maintainer must select an appropriate license (e.g., MIT, Apache-2.0) and add LICENSE.');
  }
  if (!hasCodeowners) {
    addTodo('GOV-01', 'Add .github/CODEOWNERS', 'Medium', 'Repository Governance', true,
      'Missing CODEOWNERS file.', 'Add .github/CODEOWNERS assigning @Srinivasan-78.');
  }
  if (!hasPrTemplate || !hasIssueTemplates) {
    addTodo('GOV-02', 'Add GitHub issue forms and PR template', 'Medium', 'Repository Governance', true,
      'Missing structured issue templates or pull request template.', 'Add .github/ISSUE_TEMPLATE/* and .github/PULL_REQUEST_TEMPLATE.md.');
  }
  if (!hasContributing && !stack.isProfileRepo) {
    addTodo('DOC-01', 'Add CONTRIBUTING.md guide', 'Low', 'Documentation', true,
      'Missing contributor onboarding documentation.', 'Add CONTRIBUTING.md with local dev and test instructions.');
  }
  if (!stack.hasTests && !stack.isProfileRepo && stack.languages.some(l => l !== 'html')) {
    addTodo('QA-01', 'Add automated unit/integration tests', 'High', 'Testing', false,
      'No test suite or test runner script detected.', 'Add deterministic unit tests for core modules and wire them into CI.');
  }
  if (wfRiskCount > 0) {
    addTodo('SEC-06', 'Harden GitHub Actions workflows', 'High', 'Supply Chain Security', false,
      `${wfRiskCount} workflow security risk(s) detected (e.g., unpinned actions or missing permissions).`, 'Pin third-party actions to 40-char commit SHAs and set least-privilege permissions.');
  }
  if (posture?.branchProtected === false) {
    addTodo('GOV-03', 'Enable branch protection on default branch', 'High', 'Repository Governance', false,
      'Default branch protection is disabled (requires admin/UI or ruleset).', 'Enable PR requirement, status checks, and force-push protection in GitHub Settings -> Branches.');
  }
  if (stack.isPublishable && !hasReleaseWf) {
    addTodo('REL-01', 'Configure automated release & provenance workflow', 'Medium', 'Release Engineering', true,
      'Publishable package/artifact detected without automated release workflow.', 'Add release-please configuration and workflow.');
  }
  if (!has('.editorconfig') || !has('.gitattributes')) {
    addTodo('MNT-01', 'Add .editorconfig and .gitattributes', 'Low', 'Maintainability', true,
      'Missing editor/line-ending standardization files.', 'Add .editorconfig and .gitattributes.');
  }

  const scorecard = [
    {
      category: 'Architecture',
      status: hasReadme && stack.fileCount > 0 ? 'Pass' : 'Needs Work',
      evidence: hasReadme ? `README present; ${stack.fileCount} files across [${stack.languages.join(', ') || 'docs'}]` : 'Missing README.md',
    },
    {
      category: 'Code Quality',
      status: stack.isProfileRepo || stack.linters.length > 0 || workflows.some(w => /lint|ruff|eslint|tsc|mypy/i.test(w.content))
        ? 'Pass' : 'Needs Work',
      evidence: stack.linters.length ? `Configured: ${stack.linters.join(', ')}` : (stack.isProfileRepo ? 'Profile repository' : 'No linter/typecheck config detected'),
    },
    {
      category: 'CI/CD',
      status: stack.isProfileRepo || hasCiWorkflow ? 'Pass' : 'Needs Work',
      evidence: hasCiWorkflow ? `${workflows.length} workflow(s) configured` : (stack.isProfileRepo ? 'Profile repository' : 'No CI workflow found'),
    },
    {
      category: 'CodeQL',
      status: stack.codeqlLanguages.length === 0 || hasCodeql ? 'Pass' : 'Needs Work',
      evidence: hasCodeql ? 'CodeQL workflow active' : (stack.codeqlLanguages.length ? `Supported (${stack.codeqlLanguages.join(', ')}) but not configured` : 'No CodeQL-supported source languages'),
    },
    {
      category: 'SAST',
      status: stack.codeqlLanguages.length === 0 || hasCodeql || stack.linters.includes('ruff') ? 'Pass' : 'Needs Work',
      evidence: hasCodeql ? 'Covered by CodeQL' : 'Missing automated SAST workflow',
    },
    {
      category: 'Secret Scanning',
      status: secretCount > 0 ? 'Needs Work' : (hasSecretScanWf || posture?.pushProtection === true ? 'Pass' : 'Needs Work'),
      evidence: secretCount > 0 ? `${secretCount} secret finding(s) detected` : (hasSecretScanWf ? 'Gitleaks CI workflow present' : 'Missing CI secret-scan workflow'),
    },
    {
      category: 'Dependency Security',
      status: cveCount > 0 ? 'Needs Work' : (stack.ecosystems.length === 0 || (hasDependabot && (hasDepReview || !stack.ecosystems.some(e => e !== 'github-actions'))) ? 'Pass' : 'Needs Work'),
      evidence: cveCount > 0 ? `${cveCount} CVE(s) detected` : (hasDependabot ? 'Dependabot configured' : 'Missing Dependabot or Dependency Review'),
    },
    {
      category: 'Supply Chain Security',
      status: wfRiskCount === 0 && workflows.length > 0 ? 'Pass' : (workflows.length === 0 && stack.isProfileRepo ? 'Pass' : 'Needs Work'),
      evidence: wfRiskCount === 0 && workflows.length > 0 ? 'All workflow actions pinned & least-privilege' : `${wfRiskCount} workflow risk(s)`,
    },
    {
      category: 'Testing',
      status: stack.isProfileRepo || stack.languages.every(l => l === 'html') || stack.hasTests ? 'Pass' : 'Needs Work',
      evidence: stack.hasTests ? `${stack.testFilesCount} test file(s) detected` : 'No automated tests detected',
    },
    {
      category: 'Test Coverage',
      status: stack.isProfileRepo || !stack.hasTests || hasCoverageInCi ? (stack.hasTests && !hasCoverageInCi ? 'Needs Work' : 'Pass') : 'Needs Work',
      evidence: hasCoverageInCi ? 'Coverage reporting enabled in CI' : (stack.hasTests ? 'Coverage reporting not configured in CI' : 'No tests to measure'),
    },
    {
      category: 'Performance',
      status: stack.isProfileRepo || !stack.isPublishable ? 'Pass' : (/bench|perf|timeout-minutes/i.test(allWfText) ? 'Pass' : 'Needs Work'),
      evidence: /timeout-minutes/i.test(allWfText) ? 'CI job timeouts enforced' : 'No CI timeouts or benchmarks configured',
    },
    {
      category: 'Documentation',
      status: hasReadme && hasSecurityMd && (hasLicense || stack.isProfileRepo) ? 'Pass' : 'Needs Work',
      evidence: `README:${hasReadme ? 'yes' : 'no'}, SECURITY:${hasSecurityMd ? 'yes' : 'no'}, LICENSE:${hasLicense ? 'yes' : 'no'}`,
    },
    {
      category: 'Repository Governance',
      status: hasCodeowners && hasPrTemplate && hasIssueTemplates && posture?.branchProtected !== false ? 'Pass' : 'Needs Work',
      evidence: `CODEOWNERS:${hasCodeowners ? 'yes' : 'no'}, PR-tpl:${hasPrTemplate ? 'yes' : 'no'}, Issues-tpl:${hasIssueTemplates ? 'yes' : 'no'}, BranchProt:${posture?.branchProtected ?? 'unknown'}`,
    },
    {
      category: 'Release Engineering',
      status: !stack.isPublishable || hasReleaseWf ? 'Pass' : 'Needs Work',
      evidence: hasReleaseWf ? 'Automated release workflow present' : (stack.isPublishable ? 'Publishable package lacks release automation' : 'Not a published package'),
    },
    {
      category: 'Maintainability',
      status: integrityCount === 0 && has('.gitignore') && has('.editorconfig') ? 'Pass' : 'Needs Work',
      evidence: `Integrity issues:${integrityCount}, .gitignore:${has('.gitignore') ? 'yes' : 'no'}, .editorconfig:${has('.editorconfig') ? 'yes' : 'no'}`,
    },
  ];

  return {
    repo: repoMeta?.name || path.basename(repoDir),
    stack,
    scorecard,
    todos,
    flags: {
      hasCiWorkflow,
      hasCodeql,
      hasDepReview,
      hasSecretScanWf,
      hasReleaseWf,
      hasDependabot,
      hasSecurityMd,
      hasLicense,
      hasReadme,
      hasContributing,
      hasCodeowners,
      hasPrTemplate,
      hasIssueTemplates,
    },
  };
}

export { STANDARD_LABELS, detectStack, auditRepository };
