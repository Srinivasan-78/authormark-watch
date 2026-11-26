# Contributing to authormark-watch

Thank you for contributing!

## Development Workflow

1. Fork the repository and create a feature branch from `main`.
2. Keep the project zero-dependency (`dependencies: {}`) and compatible with Node.js >= 18.
3. Run the full test suite locally before opening a PR:
   ```sh
   npm test
   ```
4. Ensure all CI checks (tests, CodeQL, Gitleaks secret scan, dependency review, and self-audit) pass.

## Pull Request Guidelines

- Describe *what* changed and *why*.
- Add unit/integration tests in `test/` for new modules or bug fixes.
- Do not commit secrets, tokens, or `.env` files.
