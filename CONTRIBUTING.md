# Contributing to IronDivi

Thank you for your interest in contributing to IronDivi! This document outlines the process for contributing code and the standards we follow.

## How to Contribute

1. **Fork** the repository on GitHub.
2. **Create a branch** from `main` for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** with clear, focused commits.
4. **Ensure all checks pass** (see below).
5. **Open a Pull Request** against `main` with a clear description of what your changes do and why.

## Code Style

All Rust code must pass formatting and lint checks:

```bash
# Format code
cargo fmt --all

# Check formatting (CI runs this)
cargo fmt --all -- --check

# Run lints (CI runs this with -D warnings)
cargo clippy --workspace -- -D warnings
```

General guidelines:

- Follow standard Rust idioms and naming conventions.
- Prefer explicit error handling over `.unwrap()` in library code.
- Add documentation comments (`///`) for public APIs.
- Keep functions focused and reasonably sized.

## Testing

All tests must pass before a PR will be merged:

```bash
cargo test --workspace
```

When adding new functionality:

- Add unit tests in the same file or a `tests` submodule.
- Add integration tests under `tests/` if the feature spans multiple crates.
- Test edge cases and error paths, not just the happy path.

## Commit Messages

We prefer [Conventional Commits](https://www.conventionalcommits.org/) style:

```
feat: add vault reclaim RPC command
fix: correct BIP34 height encoding for heights > 0x7FFF
refactor: extract stake modifier calculation into helper
test: add property tests for compact target round-trip
docs: update RPC compatibility table
```

The type prefix helps reviewers understand the nature of each change at a glance.

## Pull Request Guidelines

- Keep PRs focused on a single concern. Prefer multiple small PRs over one large one.
- Include a description of *why* the change is needed, not just *what* changed.
- Reference any related issues (e.g., `Fixes #42`).
- Ensure CI passes before requesting review.

## License

By contributing to IronDivi, you agree that your contributions will be licensed under the **AGPL-3.0-only** license, consistent with the project's [LICENSE](LICENSE).

## Security Vulnerabilities

If you discover a security vulnerability, **do not** open a public issue. Instead, follow the responsible disclosure process described in [SECURITY.md](SECURITY.md).

## Questions?

Open a [Discussion](https://github.com/DiviDomains/IronDivi/discussions) on GitHub or reach out to the maintainers.
