# OpenSentinel

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org)

**Supply chain security scanner for Node.js and Bun projects.**

OpenSentinel scans your full dependency tree — including transitive dependencies — for known CVEs, malicious code patterns, and supply chain risks. Results appear in an interactive terminal UI or can be exported as CycloneDX SBOM, JSON, or HTML.

---

## Features

- **Full dependency tree** — parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`
- **Multi-source advisories** — queries OSV, GitHub Security Advisories, and NVD in parallel
- **Code pattern detection** — credential harvesting, crypto mining, network exfiltration, obfuscated `eval`/`require`
- **AST analysis** — Tree-sitter-based deep inspection of JS/TS source (requires `downloadSource: true`)
- **MITRE ATT&CK mapping** — links detections to techniques (T1005, T1071, T1059, …)
- **Install script detection** — flags packages with `preinstall`/`postinstall` hooks
- **Typosquatting detection** — catches packages with names similar to popular libraries
- **Interactive TUI** — navigate packages, drill into each CVE, view code snippets, export on the fly
- **CI/CD friendly** — structured exit codes, non-interactive output formats, severity filters

---

## Demo

```
┌─ Dependencies (231) ────┬─ lodash@4.17.20  —  CRITICAL (9.1) ───────────────┐
│ CRITICAL: lodash@4.17   │ [OSV] CVE-2021-23337    CRITICAL  CVSS 9.1        │
│ HIGH:     axios@0.21    │   Prototype pollution via format string           │
│ MEDIUM:   express@4.18  │────────────────────────────────────────────────── │
│ LOW:      debug@4.3     │ [GitHub] GHSA-35jh-r3h4  HIGH                     │
│ SAFE:     react@18.0    │   ReDoS via string trimming                       │
│           ...           │────────────────────────────────────────────────── │
│                         │ [CODE] Credential access pattern  92% conf.       │
│                         │   src/utils.js:87                                 │
│                         ├─ Vulnerability Detail ────────────────────────────│
│                         │  [OSV] CVE-2021-23337  CRITICAL  CVSS 9.1         │
│                         │                                                   │
│                         │  Description:                                     │
│                         │    Prototype pollution in lodash's merge,         │
│                         │    mergeWith, defaultsDeep, and zipObjectDeep.    │
│                         │                                                   │
│                         │  Affected:  <4.17.21                              │
│                         │  Fixed in:  >=4.17.21                             │
│                         │  Published: 2021-02-15                            │
│                         │  References:                                      │
│                         │    • https://nvd.nist.gov/vuln/detail/CVE-2021-...│
└─────────────────────────┴────────────────────────────────────────────────── ┘
[↑↓] Navigate vulns  [Enter] Detail  [C] Copy  [E] Export  [Tab] Switch  [Q] Quit
Packages: 231  |  Critical: 1  High: 3  Medium: 7  Low: 12  Safe: 208
```

---

## Installation

### Prerequisites

- Rust 1.75+
- PostgreSQL (for advisory caching) — or set `engine: "sqlite"` in config
- `GITHUB_TOKEN` — recommended for higher GitHub Advisory API rate limits
- `NVD_API_KEY` — recommended to avoid NVD rate limiting

### From source

```bash
git clone https://github.com/yourname/opensentinel
cd opensentinel
cargo install --path .
```

The `opse` binary will be available in your `$PATH` after installation.

---

## Quick Start

```bash
# Scan current directory — opens interactive TUI
opse scan

# Scan a specific project
opse scan ~/projects/my-app

# Non-interactive — print JSON to stdout
opse scan --format=json

# Save CycloneDX SBOM to file
opse scan --format=sbom --output=sbom.cdx.json

# Only report high and critical issues
opse scan --severity=high,critical
```

### First-time setup

```bash
# Initialize config in your project
opse init

# Follow the interactive wizard to configure:
#   - Database connection (PostgreSQL / SQLite / MySQL)
#   - Source analysis settings
#   - API credentials
#   - Parallelism tuning
#   - Output preferences
```

---

## TUI Navigation

| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate package list or vulnerability list |
| `Enter` | Open vulnerability list for selected package; then open detail |
| `Esc` | Go back one panel |
| `Tab` | Cycle between panels |
| `/` | Search packages by name |
| `D` | Toggle direct dependencies only |
| `G` | Group by severity |
| `E` | Export current filtered results to `opensentinel-{timestamp}.json` |
| `C` | Copy selected vulnerability ID + fix info to clipboard |
| `Q` | Quit |

Switch between `arrows` (default) and `vim` (`hjkl`) keybindings via `opse init` or the `--keybindings` flag.

### Panel layout

| Panel | Content |
|-------|---------|
| Left (30%) | Full package list with severity labels. Filterable by search, direct deps, severity group. |
| Top-right (30%) | Vulnerability list for the selected package — advisories (`[OSV]`, `[GitHub]`, `[NVD]`) and code detections (`[CODE]`). |
| Bottom-right (70%) | Full detail of the selected vulnerability: description, CVSS score, affected/patched versions, publish date, references, code snippet, MITRE mapping, recommendations. |

---

## Output Formats

```bash
opse scan --format=sbom    # CycloneDX (default for --output)
opse scan --format=json    # Raw JSON — full risk data
opse scan --format=table   # ASCII table in terminal
opse scan --format=html    # HTML report

# Re-render a saved JSON report into another format
opse report --source=scan.json --format=html --output=report.html
```

---

## Configuration

Config is read from `./opensentinel.json` (project-level) or `~/.opensentinel/config.json` (global). Run `opse init` to generate it interactively.

```json
{
  "version": "1.0",
  "database": {
    "engine": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "opensentinel",
    "user": "postgres",
    "password": "${DB_PASSWORD}"
  },
  "sourceAnalysis": {
    "enabled": true,
    "downloadSource": false,
    "analyzeAST": true,
    "cacheDir": ".opensentinel/cache",
    "cacheTTL": 604800
  },
  "parallelism": {
    "packageConcurrency": 4,
    "apiConcurrency": 3,
    "osv":    { "limit": 10, "delay": 100 },
    "github": { "limit": 5,  "delay": 200 },
    "nvd":    { "limit": 5,  "delay": 200 }
  },
  "credentials": {
    "github_token": "${GITHUB_TOKEN}",
    "nvd_api_key":  "${NVD_API_KEY}",
    "storage": "env"
  },
  "ecosystems": ["nodejs", "bun"],
  "severity": ["high", "critical"],
  "keybindings": "arrows"
}
```

> Credential values starting with `${...}` are read from environment variables at runtime. Set `storage: "keyring"` to use the OS keyring instead.

### Source analysis

By default, OpenSentinel only checks advisory databases (no source download). To enable full code analysis:

```json
"sourceAnalysis": {
  "downloadSource": true,
  "analyzeAST": true
}
```

With `downloadSource: true`, OpenSentinel fetches package tarballs from the registry and scans the actual source for malicious patterns and AST-level anomalies. Results appear as `[CODE]` entries in the TUI with file paths and code snippets.

---

## Detection Capabilities

### Advisory databases
- **OSV** — Open Source Vulnerabilities (covers npm, PyPI, Go, Rust, …)
- **GitHub Security Advisories** — curated advisories from the GitHub Advisory Database
- **NVD** — National Vulnerability Database (NIST CVE feed)

### Code pattern detection

| Category | Examples |
|----------|---------|
| Credential harvesting | `process.env` access, hardcoded secrets, SSH key patterns |
| Crypto mining | Mining pool connections (`stratum+tcp://`), CoinHive, XMRig |
| Network exfiltration | HTTP POST to external hosts, base64-encoded URLs |
| Obfuscated code | `eval(Buffer.from(..., 'base64'))`, dynamic `require` via encoded strings |

### AST-level detection (requires `downloadSource: true`)

- `eval` with encoded payloads
- Dynamic `require` with obfuscated paths
- Hardcoded secrets in variable assignments
- Suspicious environment variable access patterns

### Additional checks
- **Install scripts** — `preinstall`/`postinstall`/`prepare` hooks
- **Typosquatting** — names suspiciously similar to well-known packages
- **MITRE ATT&CK** — technique mapping (T1005 Data from Local System, T1071 Application Layer Protocol, T1059 Command and Scripting Interpreter, …)

---

## CI/CD Integration

OpenSentinel returns structured exit codes suitable for use in pipelines:

| Exit code | Meaning |
|-----------|---------|
| `0` | No risks, or only LOW severity |
| `1` | MEDIUM severity risks found |
| `2` | HIGH severity risks found |
| `3` | CRITICAL severity risks found |

### GitHub Actions example

```yaml
- name: Security scan
  run: |
    opse scan \
      --format=json \
      --output=opensentinel-report.json \
      --severity=high,critical
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    NVD_API_KEY: ${{ secrets.NVD_API_KEY }}

- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: opensentinel-report.json
```

### Fail on critical only

```bash
opse scan --format=json --severity=critical --output=/dev/null
# exits 0 unless CRITICAL found
```

---

## Supported Ecosystems

| Ecosystem | Lock files parsed |
|-----------|------------------|
| Node.js | `package-lock.json` (v1/v2/v3), `yarn.lock` (classic + berry), `pnpm-lock.yaml` |
| Bun | `bun.lock`, `bunfig.toml` |

Python, Go, and Rust support is planned for a future release.

---

## Tech Stack

| Component | Library |
|-----------|---------|
| Language | Rust |
| Async runtime | Tokio |
| Terminal UI | Ratatui + Crossterm |
| HTTP client | Reqwest |
| Database | SQLx (PostgreSQL / SQLite / MySQL) |
| AST parsing | Tree-sitter |
| Serialization | Serde |
| SBOM output | CycloneDX |
| Dependency walking | WalkDir |

---

## Contributing

Contributions are welcome. Please open an issue before submitting large changes.

```bash
# Run tests
cargo test

# Check for warnings
cargo clippy -- -D warnings

# Format
cargo fmt
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
