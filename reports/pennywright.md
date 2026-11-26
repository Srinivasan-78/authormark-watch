# Automated DevSecOps, Quality & Governance Audit for `pennywright`

**Detected Stack:** typescript, python (Package manager: `pip`)

## Changes Included in This PR

- `.github/workflows/ci.yml` — Add core CI workflow
- `.github/workflows/codeql.yml` — Add CodeQL SAST workflow
- `.github/workflows/secret-scan.yml` — Add Gitleaks secret-scan workflow
- `CONTRIBUTING.md` — Add contributor guide
- `SECURITY.md` — Add security policy
- `.github/CODEOWNERS` — Add CODEOWNERS
- `.github/PULL_REQUEST_TEMPLATE.md` — Add PR template
- `.github/ISSUE_TEMPLATE/bug_report.yml` — Add bug report form
- `.github/ISSUE_TEMPLATE/feature_request.yml` — Add feature request form
- `.github/ISSUE_TEMPLATE/config.yml` — Add issue template config
- `.editorconfig` — Add EditorConfig

## Repository Health Scorecard (Baseline)

| Category | Status | Evidence |
|---|---|---|
| Architecture | Pass | README present; 175 files across [typescript, python] |
| Code Quality | Needs Work | No linter/typecheck config detected |
| CI/CD | Needs Work | No CI workflow found |
| CodeQL | Needs Work | Supported (javascript-typescript, python) but not configured |
| SAST | Needs Work | Missing automated SAST workflow |
| Secret Scanning | Needs Work | Missing CI secret-scan workflow |
| Dependency Security | Pass | Missing Dependabot or Dependency Review |
| Supply Chain Security | Needs Work | 0 workflow risk(s) |
| Testing | Pass | 1 test file(s) detected |
| Test Coverage | Needs Work | Coverage reporting not configured in CI |
| Performance | Pass | No CI timeouts or benchmarks configured |
| Documentation | Needs Work | README:yes, SECURITY:no, LICENSE:yes |
| Repository Governance | Needs Work | CODEOWNERS:no, PR-tpl:no, Issues-tpl:no, BranchProt:false |
| Release Engineering | Pass | Not a published package |
| Maintainability | Needs Work | Integrity issues:1, .gitignore:yes, .editorconfig:no |

## Remaining TODOs & Manual Admin Checklist

- **[High] CI-01: Add core CI workflow (lint, test, build)** (Auto-addressed in PR) — No CI workflow found for pull requests and default branch pushes. *Resolution:* Add .github/workflows/ci.yml tailored to detected stack.
- **[High] SEC-03: Enable GitHub CodeQL SAST workflow** (Auto-addressed in PR) — CodeQL supports javascript-typescript, python but no CodeQL workflow exists. *Resolution:* Add .github/workflows/codeql.yml with security-extended queries.
- **[High] SEC-04: Add Gitleaks secret scanning workflow** (Auto-addressed in PR) — No automated CI secret-scanning workflow configured. *Resolution:* Add .github/workflows/secret-scan.yml.
- **[Medium] SEC-05: Add SECURITY.md vulnerability reporting policy** (Auto-addressed in PR) — Missing SECURITY.md. *Resolution:* Add SECURITY.md with responsible disclosure instructions.
- **[Medium] GOV-01: Add .github/CODEOWNERS** (Auto-addressed in PR) — Missing CODEOWNERS file. *Resolution:* Add .github/CODEOWNERS assigning @Srinivasan-78.
- **[Medium] GOV-02: Add GitHub issue forms and PR template** (Auto-addressed in PR) — Missing structured issue templates or pull request template. *Resolution:* Add .github/ISSUE_TEMPLATE/* and .github/PULL_REQUEST_TEMPLATE.md.
- **[Low] DOC-01: Add CONTRIBUTING.md guide** (Auto-addressed in PR) — Missing contributor onboarding documentation. *Resolution:* Add CONTRIBUTING.md with local dev and test instructions.
- **[High] GOV-03: Enable branch protection on default branch** (Manual Action Required) — Default branch protection is disabled (requires admin/UI or ruleset). *Resolution:* Enable PR requirement, status checks, and force-push protection in GitHub Settings -> Branches.
- **[Low] MNT-01: Add .editorconfig and .gitattributes** (Auto-addressed in PR) — Missing editor/line-ending standardization files. *Resolution:* Add .editorconfig and .gitattributes.

> [!IMPORTANT]
> Default branch protection is currently disabled. Enable PR reviews, required status checks, and force-push protection in **Settings -> Branches**.

---
*Generated automatically by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*
