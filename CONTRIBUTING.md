# Contributing to OpenSentinel

Thank you for your interest in contributing. This guide covers everything you need to get started.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). All contributors are expected to uphold it.

---

## Ways to Contribute

- **Bug reports** — open an issue with steps to reproduce
- **Feature requests** — open an issue describing the use case
- **Documentation** — fix typos, improve examples, clarify explanations
- **Code** — fix bugs, implement features from the issue tracker
- **Security** — see [Reporting Vulnerabilities](#reporting-vulnerabilities) below

**Before opening a large PR**, please open an issue first so we can discuss the approach. This avoids wasted effort on work that may not align with the project direction.

---

## Getting Started

### Prerequisites

- Rust 1.75+
- PostgreSQL (or set `engine: "sqlite"` in your config to skip it during development)
- A `GITHUB_TOKEN` environment variable is recommended to avoid API rate limits during testing

### Setup

```bash
git clone https://github.com/yourusername/opensentinel
cd opensentinel

# Build the project
cargo build

# Run the binary
cargo run -- --help
```

### Configuration for development

Copy the example config and adjust as needed:

```bash
cp opensentinel.example.json opensentinel.json
# Edit opensentinel.json — it is gitignored by default
```

---

## Development Workflow

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. Make your changes in focused, small commits.

3. Run the checks described in [Testing](#testing) before pushing.

4. Open a pull request against `main`.

### Branch naming

| Prefix | Use |
|--------|-----|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `refactor/` | Refactoring without behavior change |
| `docs/` | Documentation only |
| `test/` | Test additions or fixes |
| `chore/` | Build, CI, or tooling changes |

---

## Code Style

Run these before every commit:

```bash
# Format
cargo fmt

# Lint (warnings are errors)
cargo clippy -- -D warnings
```

A few conventions to follow:

- Keep functions under 50 lines where possible; extract helpers when they grow
- Prefer explicit error handling — avoid `.unwrap()` except in tests
- No `println!` in library code; use `tracing::{info, warn, error}` instead
- New detection patterns go in `src/analyzer/patterns.rs`
- New advisory sources implement the `AdvisorySource` trait in `src/advisory/`

---

## Testing

```bash
# Run all tests
cargo test

# Run a specific test file
cargo test --test osv_client_test

# Run tests for a single module
cargo test analyzer::credential

# Run benchmarks
cargo bench
```

Integration tests in `tests/` require a running database. Set `DATABASE_URL` or use SQLite:

```bash
export DATABASE_URL=sqlite::memory:
cargo test
```

**Coverage target: 80%.** New code should include unit tests. Pull requests that lower coverage will be asked to add tests before merging.

---

## Submitting Changes

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add typosquatting detection for scoped packages
fix: handle missing lockfile gracefully instead of panicking
docs: add NVD rate limit note to README
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

### Pull request checklist

Before marking your PR ready for review:

- [ ] `cargo fmt` — no formatting diff
- [ ] `cargo clippy -- -D warnings` — no warnings
- [ ] `cargo test` — all tests pass
- [ ] New functionality has tests
- [ ] Public-facing changes are reflected in the README if applicable

---

## Reporting Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Send a description to **opensentienel.unbraided990@passinbox.com** with:

- A summary of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

You will receive a response within 72 hours. Once a fix is confirmed, the issue will be disclosed publicly with credit to the reporter.
