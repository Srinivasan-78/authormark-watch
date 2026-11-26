# Automated DevSecOps, Quality & Governance Audit for `devshed`

**Detected Stack:** javascript, python, docker (Package manager: `pip`)

## Changes Included in This PR

- `.github/workflows/codeql.yml` — Add CodeQL SAST workflow
- `.github/workflows/secret-scan.yml` — Add Gitleaks secret-scan workflow
- `.github/workflows/dependency-review.yml` — Add Dependency Review PR gate
- `.github/dependabot.yml` — Add grouped Dependabot config
- `.github/workflows/release-please.yml` — Add Release Please automation
- `CONTRIBUTING.md` — Add contributor guide
- `SECURITY.md` — Add security policy
- `.github/CODEOWNERS` — Add CODEOWNERS
- `.github/PULL_REQUEST_TEMPLATE.md` — Add PR template
- `.github/ISSUE_TEMPLATE/bug_report.yml` — Add bug report form
- `.github/ISSUE_TEMPLATE/feature_request.yml` — Add feature request form
- `.github/ISSUE_TEMPLATE/config.yml` — Add issue template config
- `.editorconfig` — Add EditorConfig
- `.gitattributes` — Add GitAttributes for LF normalization
- `.gitignore` — Add stack-appropriate .gitignore

## Repository Health Scorecard (Baseline)

| Category | Status | Evidence |
|---|---|---|
| Architecture | Pass | README present; 233 files across [javascript, python, docker] |
| Code Quality | Needs Work | No linter/typecheck config detected |
| CI/CD | Pass | 3 workflow(s) configured |
| CodeQL | Needs Work | Supported (javascript-typescript, python) but not configured |
| SAST | Needs Work | Missing automated SAST workflow |
| Secret Scanning | Needs Work | Missing CI secret-scan workflow |
| Dependency Security | Needs Work | Missing Dependabot or Dependency Review |
| Supply Chain Security | Needs Work | 3 workflow risk(s) |
| Testing | Pass | 2 test file(s) detected |
| Test Coverage | Needs Work | Coverage reporting not configured in CI |
| Performance | Pass | CI job timeouts enforced |
| Documentation | Needs Work | README:yes, SECURITY:no, LICENSE:no |
| Repository Governance | Needs Work | CODEOWNERS:no, PR-tpl:no, Issues-tpl:no, BranchProt:false |
| Release Engineering | Needs Work | Publishable package lacks release automation |
| Maintainability | Needs Work | Integrity issues:2, .gitignore:no, .editorconfig:no |

## Remaining TODOs & Manual Admin Checklist

- **[High] SEC-03: Enable GitHub CodeQL SAST workflow** (Auto-addressed in PR) — CodeQL supports javascript-typescript, python but no CodeQL workflow exists. *Resolution:* Add .github/workflows/codeql.yml with security-extended queries.
- **[High] SEC-04: Add Gitleaks secret scanning workflow** (Auto-addressed in PR) — No automated CI secret-scanning workflow configured. *Resolution:* Add .github/workflows/secret-scan.yml.
- **[High] DEP-01: Configure grouped Dependabot updates** (Auto-addressed in PR) — Missing .github/dependabot.yml for ecosystems: docker, github-actions. *Resolution:* Add .github/dependabot.yml with weekly grouped minor/patch updates.
- **[Medium] DEP-02: Add Dependency Review workflow for PRs** (Auto-addressed in PR) — Pull requests are not gated on newly introduced vulnerable dependencies. *Resolution:* Add .github/workflows/dependency-review.yml.
- **[Medium] SEC-05: Add SECURITY.md vulnerability reporting policy** (Auto-addressed in PR) — Missing SECURITY.md. *Resolution:* Add SECURITY.md with responsible disclosure instructions.
- **[High] LEG-01: Choose and add a repository LICENSE** (Manual Action Required) — No LICENSE file found. Auto-generation is intentionally skipped. *Resolution:* Maintainer must select an appropriate license (e.g., MIT, Apache-2.0) and add LICENSE.
- **[Medium] GOV-01: Add .github/CODEOWNERS** (Auto-addressed in PR) — Missing CODEOWNERS file. *Resolution:* Add .github/CODEOWNERS assigning @Srinivasan-78.
- **[Medium] GOV-02: Add GitHub issue forms and PR template** (Auto-addressed in PR) — Missing structured issue templates or pull request template. *Resolution:* Add .github/ISSUE_TEMPLATE/* and .github/PULL_REQUEST_TEMPLATE.md.
- **[Low] DOC-01: Add CONTRIBUTING.md guide** (Auto-addressed in PR) — Missing contributor onboarding documentation. *Resolution:* Add CONTRIBUTING.md with local dev and test instructions.
- **[High] SEC-06: Harden GitHub Actions workflows** (Manual Action Required) — 3 workflow security risk(s) detected (e.g., unpinned actions or missing permissions). *Resolution:* Pin third-party actions to 40-char commit SHAs and set least-privilege permissions.
- **[High] GOV-03: Enable branch protection on default branch** (Manual Action Required) — Default branch protection is disabled (requires admin/UI or ruleset). *Resolution:* Enable PR requirement, status checks, and force-push protection in GitHub Settings -> Branches.
- **[Medium] REL-01: Configure automated release & provenance workflow** (Auto-addressed in PR) — Publishable package/artifact detected without automated release workflow. *Resolution:* Add release-please configuration and workflow.
- **[Low] MNT-01: Add .editorconfig and .gitattributes** (Auto-addressed in PR) — Missing editor/line-ending standardization files. *Resolution:* Add .editorconfig and .gitattributes.

> [!IMPORTANT]
> Default branch protection is currently disabled. Enable PR reviews, required status checks, and force-push protection in **Settings -> Branches**.

---
*Generated automatically by [authormark-watch](https://github.com/Srinivasan-78/authormark-watch)*
