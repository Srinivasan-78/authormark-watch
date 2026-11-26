const PINNED_ACTIONS = {
  checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1',
  setupNode: 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1  # v7.1.0',
  setupPython: 'actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0  # v7.1.0',
  setupGo: 'actions/setup-go@d8cbb8045d7f43706b9177cceb36c1f91a6644d5  # v7.1.0',
  depReview: 'actions/dependency-review-action@bbc44d14a204704ccc493733616cd1e93a0321ec  # v5.0.1',
  codeqlInit: 'github/codeql-action/init@38112626f97ac1fd7acf3df7ebca51f4677c1b38  # codeql-bundle-v2.27.6',
  codeqlAnalyze: 'github/codeql-action/analyze@38112626f97ac1fd7acf3df7ebca51f4677c1b38  # codeql-bundle-v2.27.6',
  gitleaks: 'gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e  # v3.0.0',
  trivy: 'aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25  # v0.36.0',
  releasePlease: 'googleapis/release-please-action@45996ed1f6d02564a971a2fa1b5860e934307cf7  # v5.0.0',
  attest: 'actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8  # v4.2.2',
};

function renderCiWorkflow(audit) {
  const { stack } = audit;
  const defaultBranch = audit.defaultBranch || 'main';
  const osList = stack.targetsWindowsOrMac ? '[\'ubuntu-latest\', \'windows-latest\']' : null;
  const lines = [
    'name: CI',
    '',
    'on:',
    '  pull_request:',
    '  push:',
    `    branches: [${defaultBranch}]`,
    '  workflow_dispatch:',
    '',
    'concurrency:',
    '  group: ci-${{ github.ref }}',
    '  cancel-in-progress: true',
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
  ];

  if (stack.languages.includes('javascript') || stack.languages.includes('typescript')) {
    const pm = ['npm', 'pnpm', 'yarn'].includes(stack.packageManager) ? stack.packageManager : 'npm';
    const installCmd = pm === 'pnpm'
      ? 'pnpm install --frozen-lockfile'
      : pm === 'yarn'
        ? 'yarn install --frozen-lockfile'
        : 'if [ -f package-lock.json ]; then npm ci; elif [ -f package.json ]; then npm install; fi';
    lines.push(
      '  node:',
      `    runs-on: ${osList ? '${{ matrix.os }}' : 'ubuntu-latest'}`,
      '    timeout-minutes: 15',
      ...(osList ? ['    defaults:', '      run:', '        shell: bash', '    strategy:', '      fail-fast: false', '      matrix:', `        os: ${osList}`] : []),
      '    steps:',
      `      - uses: ${PINNED_ACTIONS.checkout}`,
      `      - uses: ${PINNED_ACTIONS.setupNode}`,
      '        with:',
      "          node-version: '22'",
      ...(stack.hasNodeLockfile ? [`          cache: '${pm}'`] : []),
      '      - name: Install dependencies',
      `        run: ${installCmd}`,
      '      - name: Lint (if configured)',
      '        run: if [ -f package.json ]; then npm run lint --if-present; fi',
      '      - name: Typecheck (if configured)',
      '        run: if [ -f package.json ]; then npm run typecheck --if-present; fi',
      '      - name: Build (if configured)',
      '        run: if [ -f package.json ]; then npm run build --if-present; fi',
      '      - name: Run tests',
      '        run: if [ -f package.json ]; then npm test --if-present; fi',
    );
  } else if (stack.languages.includes('python')) {
    lines.push(
      '  python:',
      '    runs-on: ubuntu-latest',
      '    timeout-minutes: 15',
      '    steps:',
      `      - uses: ${PINNED_ACTIONS.checkout}`,
      `      - uses: ${PINNED_ACTIONS.setupPython}`,
      '        with:',
      "          python-version: '3.12'",
      "          cache: 'pip'",
      '      - name: Install dependencies',
      '        run: |',
      '          python -m pip install --upgrade pip',
      '          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi',
      '          if [ -f pyproject.toml ]; then pip install -e . || true; fi',
      '      - name: Lint with ruff (if available)',
      '        run: |',
      '          pip install ruff pytest',
      '          ruff check .',
      '      - name: Run tests',
      '        run: pytest || python -m unittest discover',
    );
  } else if (stack.languages.includes('go')) {
    lines.push(
      '  go:',
      '    runs-on: ubuntu-latest',
      '    timeout-minutes: 15',
      '    steps:',
      `      - uses: ${PINNED_ACTIONS.checkout}`,
      `      - uses: ${PINNED_ACTIONS.setupGo}`,
      '        with:',
      "          go-version-file: 'go.mod'",
      '          cache: true',
      '      - name: Vet and test',
      '        run: go vet ./... && go test -race ./...',
    );
  } else if (stack.languages.includes('rust')) {
    lines.push(
      '  rust:',
      '    runs-on: ubuntu-latest',
      '    timeout-minutes: 20',
      '    steps:',
      `      - uses: ${PINNED_ACTIONS.checkout}`,
      '      - name: Check formatting, clippy, and tests',
      '        run: cargo fmt --check && cargo clippy -- -D warnings && cargo test',
    );
  } else {
    lines.push(
      '  verify:',
      '    runs-on: ubuntu-latest',
      '    timeout-minutes: 10',
      '    steps:',
      `      - uses: ${PINNED_ACTIONS.checkout}`,
      '      - name: Verify repository files',
      '        run: test -f README.md',
    );
  }

  return lines.join('\n') + '\n';
}

function renderCodeqlWorkflow(codeqlLanguages, defaultBranch = 'main') {
  const langs = JSON.stringify(codeqlLanguages);
  return [
    'name: CodeQL',
    '',
    'on:',
    '  push:',
    `    branches: [${defaultBranch}]`,
    '  pull_request:',
    `    branches: [${defaultBranch}]`,
    '  schedule:',
    "    - cron: '23 4 * * 1'",
    '  workflow_dispatch:',
    '',
    'permissions:',
    '  contents: read',
    '  security-events: write',
    '  actions: read',
    '',
    'jobs:',
    '  analyze:',
    '    name: Analyze (${{ matrix.language }})',
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 30',
    '    strategy:',
    '      fail-fast: false',
    '      matrix:',
    `        language: ${langs}`,
    '    steps:',
    `      - uses: ${PINNED_ACTIONS.checkout}`,
    `      - uses: ${PINNED_ACTIONS.codeqlInit}`,
    '        with:',
    '          languages: ${{ matrix.language }}',
    '          queries: security-extended',
    `      - uses: ${PINNED_ACTIONS.codeqlAnalyze}`,
    '        with:',
    '          category: "/language:${{ matrix.language }}"',
    '',
  ].join('\n');
}

function renderDependencyReviewWorkflow() {
  return [
    'name: Dependency Review',
    '',
    'on:',
    '  pull_request:',
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  dependency-review:',
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 10',
    '    steps:',
    `      - uses: ${PINNED_ACTIONS.checkout}`,
    `      - uses: ${PINNED_ACTIONS.depReview}`,
    '        with:',
    '          fail-on-severity: high',
    '',
  ].join('\n');
}

function renderSecretScanWorkflow(defaultBranch = 'main') {
  return [
    'name: Secret Scan',
    '',
    'on:',
    '  pull_request:',
    '  push:',
    `    branches: [${defaultBranch}]`,
    '  workflow_dispatch:',
    '',
    'permissions:',
    '  contents: read',
    '',
    'jobs:',
    '  gitleaks:',
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 10',
    '    steps:',
    `      - uses: ${PINNED_ACTIONS.checkout}`,
    '        with:',
    '          fetch-depth: 0',
    `      - uses: ${PINNED_ACTIONS.gitleaks}`,
    '        env:',
    '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}',
    '',
  ].join('\n');
}

function renderDependabot(ecosystems) {
  const unique = [...new Set([...ecosystems, 'github-actions'])];
  const lines = ['version: 2', 'updates:'];
  for (const eco of unique) {
    const groupName = `${eco.replace(/[^a-z0-9]/gi, '-')}-dependencies`;
    lines.push(
      `  - package-ecosystem: "${eco}"`,
      '    directory: "/"',
      '    schedule:',
      '      interval: "weekly"',
      '    open-pull-requests-limit: 10',
      '    groups:',
      `      ${groupName}:`,
      '        patterns: ["*"]',
      '        update-types: ["minor", "patch"]',
    );
  }
  return lines.join('\n') + '\n';
}

function renderReleasePleaseWorkflow(defaultBranch = 'main') {
  return [
    'name: Release Please',
    '',
    'on:',
    '  push:',
    `    branches: [${defaultBranch}]`,
    '',
    'permissions:',
    '  contents: write',
    '  pull-requests: write',
    '',
    'jobs:',
    '  release-please:',
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 10',
    '    steps:',
    `      - uses: ${PINNED_ACTIONS.releasePlease}`,
    '        with:',
    '          token: ${{ secrets.GITHUB_TOKEN }}',
    '',
  ].join('\n');
}

function renderSecurityMd(repoName, owner = 'Srinivasan-78') {
  return [
    '# Security Policy',
    '',
    `## Supported Versions`,
    '',
    `Security updates are applied to the latest release and the default branch of \`${owner}/${repoName}\`.`,
    '',
    '## Reporting a Vulnerability',
    '',
    'Please do **not** open a public GitHub issue for security vulnerabilities.',
    '',
    `- Use GitHub Private Vulnerability Reporting on \`https://github.com/${owner}/${repoName}/security/advisories/new\`, or`,
    '- Contact the maintainer directly via the email listed on their GitHub profile.',
    '',
    'Please include reproduction steps, affected versions/commits, and potential impact. We aim to acknowledge reports within 72 hours.',
    '',
  ].join('\n');
}

function renderContributingMd(repoName, stack) {
  const testCmd = stack.packageManager === 'pip' || stack.packageManager === 'uv' || stack.packageManager === 'poetry'
    ? 'pytest'
    : stack.packageManager === 'go'
      ? 'go test ./...'
      : stack.packageManager === 'cargo'
        ? 'cargo test'
        : 'npm test';
  return [
    `# Contributing to ${repoName}`,
    '',
    'Thank you for considering contributing!',
    '',
    '## Development Workflow',
    '',
    '1. Fork the repository and create a feature branch from `main`.',
    '2. Keep changes focused and well-tested.',
    `3. Run the test suite locally before opening a PR: \`${testCmd}\`.`,
    '4. Ensure CI checks (linting, tests, CodeQL, secret scanning, and dependency review) pass.',
    '',
    '## Pull Request Guidelines',
    '',
    '- Describe *what* changed and *why*.',
    '- Link any related issues.',
    '- Do not commit secrets, tokens, or local environment files.',
    '',
  ].join('\n');
}

function renderBugReportTemplate() {
  return [
    'name: Bug Report',
    'description: Report a reproducible bug or unexpected behavior',
    'labels: ["bug"]',
    'body:',
    '  - type: textarea',
    '    id: summary',
    '    attributes:',
    '      label: What happened?',
    '      description: Clear description of the bug.',
    '    validations:',
    '      required: true',
    '  - type: textarea',
    '    id: repro',
    '    attributes:',
    '      label: Steps to reproduce',
    '      description: Minimal steps or commands to reproduce.',
    '    validations:',
    '      required: true',
    '  - type: input',
    '    id: environment',
    '    attributes:',
    '      label: Environment',
    '      placeholder: "OS, runtime version (e.g. Node 22 / Python 3.12)"',
    '',
  ].join('\n');
}

function renderFeatureRequestTemplate() {
  return [
    'name: Feature Request',
    'description: Propose an enhancement or new capability',
    'labels: ["enhancement"]',
    'body:',
    '  - type: textarea',
    '    id: problem',
    '    attributes:',
    '      label: Problem / Motivation',
    '      description: What problem does this solve?',
    '    validations:',
    '      required: true',
    '  - type: textarea',
    '    id: proposal',
    '    attributes:',
    '      label: Proposed Solution',
    '    validations:',
    '      required: true',
    '',
  ].join('\n');
}

function renderIssueTemplateConfig(repoName, owner = 'Srinivasan-78') {
  return [
    'blank_issues_enabled: false',
    'contact_links:',
    '  - name: Security Vulnerability',
    `    url: https://github.com/${owner}/${repoName}/security/advisories/new`,
    '    about: Report security vulnerabilities privately',
    '',
  ].join('\n');
}

function renderPrTemplate() {
  return [
    '## Summary',
    '',
    '<!-- Describe what changed and why. -->',
    '',
    '## Related Issues',
    '',
    '<!-- Closes # -->',
    '',
    '## Checklist',
    '',
    '- [ ] Tests added/updated and passing locally',
    '- [ ] Documentation updated where applicable',
    '- [ ] No secrets, tokens, or unrelated files included',
    '',
  ].join('\n');
}

function renderEditorConfig() {
  return [
    'root = true',
    '',
    '[*]',
    'charset = utf-8',
    'end_of_line = lf',
    'insert_final_newline = true',
    'trim_trailing_whitespace = true',
    'indent_style = space',
    'indent_size = 2',
    '',
    '[*.py]',
    'indent_size = 4',
    '',
    '[*.md]',
    'trim_trailing_whitespace = false',
    '',
  ].join('\n');
}

function renderGitAttributes() {
  return '* text=auto eol=lf\n';
}

function renderGitIgnore(stack) {
  const lines = ['# OS & Editors', '.DS_Store', 'Thumbs.db', '.vscode/', '.idea/', '', '# Environment', '.env', '.env.*', '!.env.example', ''];
  if (stack.languages.includes('javascript') || stack.languages.includes('typescript')) {
    lines.push('# Node.js', 'node_modules/', 'dist/', 'build/', 'coverage/', '');
  }
  if (stack.languages.includes('python')) {
    lines.push('# Python', '__pycache__/', '*.py[cod]', '.venv/', 'venv/', '.pytest_cache/', '.mypy_cache/', '.ruff_cache/', 'dist/', '*.egg-info/', '');
  }
  if (stack.languages.includes('go')) lines.push('# Go', 'bin/', 'coverage.out', '');
  if (stack.languages.includes('rust')) lines.push('# Rust', 'target/', '');
  return lines.join('\n');
}

function generateRepoPatches(audit, { owner = 'Srinivasan-78', defaultBranch = 'main', existingCheck } = {}) {
  const { stack, flags, repo } = audit;
  const patches = [];
  const addIfMissing = (relPath, content, reason) => {
    if (!existingCheck(relPath)) patches.push({ path: relPath, content, reason });
  };

  if (!stack.isProfileRepo) {
    if (!flags.hasCiWorkflow) addIfMissing('.github/workflows/ci.yml', renderCiWorkflow({ ...audit, defaultBranch }), 'Add core CI workflow');
    if (stack.codeqlLanguages.length > 0 && !flags.hasCodeql) {
      addIfMissing('.github/workflows/codeql.yml', renderCodeqlWorkflow(stack.codeqlLanguages, defaultBranch), 'Add CodeQL SAST workflow');
    }
    if (!flags.hasSecretScanWf) {
      addIfMissing('.github/workflows/secret-scan.yml', renderSecretScanWorkflow(defaultBranch), 'Add Gitleaks secret-scan workflow');
    }
    if (!flags.hasDepReview && stack.ecosystems.some(e => e !== 'github-actions')) {
      addIfMissing('.github/workflows/dependency-review.yml', renderDependencyReviewWorkflow(), 'Add Dependency Review PR gate');
    }
    if (!flags.hasDependabot && stack.ecosystems.length > 0) {
      addIfMissing('.github/dependabot.yml', renderDependabot(stack.ecosystems), 'Add grouped Dependabot config');
    }
    if (stack.isPublishable && !flags.hasReleaseWf) {
      addIfMissing('.github/workflows/release-please.yml', renderReleasePleaseWorkflow(defaultBranch), 'Add Release Please automation');
    }
    if (!flags.hasContributing) addIfMissing('CONTRIBUTING.md', renderContributingMd(repo, stack), 'Add contributor guide');
  }

  if (!flags.hasSecurityMd) addIfMissing('SECURITY.md', renderSecurityMd(repo, owner), 'Add security policy');
  if (!flags.hasCodeowners) addIfMissing('.github/CODEOWNERS', `* @${owner}\n`, 'Add CODEOWNERS');
  if (!flags.hasPrTemplate) addIfMissing('.github/PULL_REQUEST_TEMPLATE.md', renderPrTemplate(), 'Add PR template');
  if (!flags.hasIssueTemplates) {
    addIfMissing('.github/ISSUE_TEMPLATE/bug_report.yml', renderBugReportTemplate(), 'Add bug report form');
    addIfMissing('.github/ISSUE_TEMPLATE/feature_request.yml', renderFeatureRequestTemplate(), 'Add feature request form');
    addIfMissing('.github/ISSUE_TEMPLATE/config.yml', renderIssueTemplateConfig(repo, owner), 'Add issue template config');
  }

  addIfMissing('.editorconfig', renderEditorConfig(), 'Add EditorConfig');
  addIfMissing('.gitattributes', renderGitAttributes(), 'Add GitAttributes for LF normalization');
  addIfMissing('.gitignore', renderGitIgnore(stack), 'Add stack-appropriate .gitignore');

  return patches;
}

export {
  PINNED_ACTIONS,
  renderCiWorkflow,
  renderCodeqlWorkflow,
  renderDependencyReviewWorkflow,
  renderSecretScanWorkflow,
  renderDependabot,
  renderReleasePleaseWorkflow,
  renderSecurityMd,
  renderContributingMd,
  generateRepoPatches,
};
