# OpenSentinel

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org)

**Supply chain security scanner for Node.js, Bun, Python, Go, and Rust projects.**

OpenSentinel scans your full dependency tree — including transitive dependencies — for known CVEs, malicious code patterns, and supply chain risks. Results appear in an interactive terminal UI or can be exported as CycloneDX SBOM, JSON, or HTML.

---

## Features

- **Multi-ecosystem** — Node.js, Bun, Python, Go, Rust. Ecosystem auto-detected from project files
- **Full dependency tree** — parses lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `Cargo.lock`, `go.sum`, `poetry.lock`, `Pipfile.lock`)
- **Multi-source advisories** — queries OSV, GitHub Security Advisories, and NVD in parallel
- **Advisory source URL** — each vulnerability links to its canonical page (OSV, NVD, GitHub Advisories)
- **Credential harvesting detection** — env var access, hardcoded secrets, SSH keys, obfuscated `eval`/`require`
- **Behavioral analysis (regex)** — 20 patterns for filesystem access (`/etc/passwd`, `~/.ssh`), network connections (reverse shells, hardcoded IPs, suspicious ports), and syscalls (`execve`, `LD_PRELOAD`, privilege escalation)
- **Behavioral analysis (AST)** — Tree-sitter semantic inspection of JS, TypeScript, Python, and Go source: detects actual function calls (`fs.readFileSync`, `subprocess.run`, `exec.Command`) while ignoring identical patterns inside comments
- **MITRE ATT&CK mapping** — all detections linked to techniques (T1005, T1057, T1059, T1071, T1083, T1106, …)
- **Install script detection** — flags packages with `preinstall`/`postinstall` hooks
- **Typosquatting detection** — catches packages with names similar to popular libraries
- **Version behavior analysis** — detects unexpected changes between package releases
- **Maintainer reputation scoring** — GitHub activity, commit cadence, open issues
- **Interactive TUI** — dependency tree view, drill into each CVE, view code snippets, export on the fly
- **Scan history** — every scan persisted to PostgreSQL; re-open any past scan with `opse view`
- **Watch mode** — re-scans automatically when lockfiles change
- **CI/CD ready** — structured exit codes, non-interactive formats, auto-generated GitHub Actions workflow

---

## Screenshot

![OpenSentinel](images/image.png?raw=true)

---

## Installation

### Prerequisites

- Rust 1.75+
- PostgreSQL (optional, for advisory caching and scan history) — the scanner works fully without a database
- `GITHUB_TOKEN` — recommended for higher GitHub Advisory API rate limits
- `NVD_API_KEY` — recommended to avoid NVD rate limiting

### From source

(I Recommend fork it first)

```bash
git clone https://github.com/yourname/opensentinel
cd opensentinel
cargo install --path .
```

The `opse` binary will be available in your `$PATH` after installation.

---

## Quick Start

```bash
# Scan current directory — ecosystem auto-detected, opens interactive TUI
opse scan

# Scan a specific project
opse scan ~/projects/my-app

# Force a specific ecosystem
opse scan --ecosystem rust
opse scan --ecosystem golang
opse scan --ecosystem python
opse scan --ecosystem nodejs,bun

# Non-interactive — print table to stdout
opse scan --format table

# Save CycloneDX SBOM to file
opse scan --format sbom --output sbom.cdx.json

# Only report high and critical issues
opse scan --severity high,critical

# Skip dev dependencies
opse scan --exclude devDependencies

# Watch mode — re-scan when lockfiles change
opse scan --watch
```

### First-time setup

```bash
# Initialize config in your project (ecosystem auto-detected)
opse init

# Also generate a GitHub Actions workflow
opse init --ci
```

The wizard detects your project's ecosystem automatically and offers it as the default option. Choosing **Auto-detect** omits the `ecosystems` key from the config so detection runs on every scan.

### Scan history

Each scan is saved to PostgreSQL automatically. Review previous results without re-scanning:

```bash
# List scans for the current project
opse history

# List scans across all projects
opse history --all

# Limit results
opse history --all --limit 50

# Re-open a previous scan in the TUI
opse view 3f2a1b4c
```

The scan ID is shown at the end of every scan. Use the first 8 characters or the full UUID.

### Security badge

Generate a Shields.io badge reflecting the worst severity of the last scan:

```bash
opse badge                       # prints markdown
opse badge --style flat-square   # custom badge style
opse badge --output badge.md     # save to file
```

Paste the output into your README:

```markdown
[![Security](https://img.shields.io/badge/security-passing-success?style=flat&logo=rust)](https://github.com/yourname/opensentinel)
```

---

## TUI Navigation

| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate package list or vulnerability list |
| `Enter` | Open vulnerability list for selected package; then open detail |
| `Esc` | Go back one panel |
| `Tab` | Cycle between panels |
| `?` | Toggle help overlay |
| `I` | Ignore / restore selected package (dimmed at bottom of list) |
| `/` | Search packages by name |
| `D` | Toggle direct dependencies only |
| `G` | Group by severity |
| `E` | Export current filtered results to `opensentinel-{timestamp}.json` |
| `C` | Copy selected vulnerability ID + fix info to clipboard |
| `Q` | Quit |

Switch between `arrows` (default) and `vim` (`hjkl`) keybindings via `opse init` or the `--keybindings` flag.

The scanning screen shows real-time database connection status. If the database is unreachable, OpenSentinel continues without cache and scan results are not persisted.

### Panel layout

| Panel | Content |
|-------|---------|
| Left (30%) | Dependency tree with severity labels. Direct deps at root, transitive deps indented with `└─`. Filterable by search, direct-only, severity group. |
| Top-right (30%) | Vulnerability list for the selected package — advisories (`[OSV]`, `[GitHub]`, `[NVD]`) and code detections (`[CODE]`). |
| Bottom-right (70%) | Full detail: description, CVSS score, source URL, affected/patched versions, publish date, references, code snippet, MITRE mapping, recommendations. |

---

## Output Formats

```bash
opse scan --format sbom    # CycloneDX (default for --output)
opse scan --format json    # Raw JSON — full risk data
opse scan --format table   # ASCII table in terminal
opse scan --format html    # HTML report

# Re-render a saved JSON report into another format
opse report --source scan.json --format html --output report.html
```

---

## Configuration

Config is read from `./opensentinel.json` (project-level) or `~/.opensentinel/config.json` (global). Run `opse init` to generate it interactively.

### Ecosystem auto-detection

If neither `--ecosystem` nor an `"ecosystems"` key in any config file is present, OpenSentinel detects ecosystems automatically by looking for manifest files in the project root:

| File found | Ecosystem activated |
|------------|---------------------|
| `package.json` | `nodejs` |
| `bun.lockb`, `bunfig.toml` | `bun` |
| `Cargo.toml` | `rust` |
| `go.mod` | `golang` |
| `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock` | `python` |

To pin the ecosystems explicitly, add the key to `opensentinel.json`:

```json
{ "ecosystems": ["rust"] }
```

### Full config reference

```json
{
  "version": "1.0",
  "database": {
    "engine": "postgresql",
    "url": "${DATABASE_URL}",
    "poolSize": 5
  },
  "sourceAnalysis": {
    "enabled": true,
    "downloadSource": false,
    "analyzeAst": true,
    "cacheDir": ".opensentinel/cache",
    "cacheTtl": 86400,
    "maxSourceSizeMb": 100
  },
  "parallelism": {
    "packageConcurrency": 4,
    "apiConcurrency": 3,
    "osv":    { "limit": 10, "delayMs": 50 },
    "github": { "limit": 3,  "delayMs": 100 },
    "nvd":    { "limit": 3,  "delayMs": 100 },
    "mitre":  { "limit": 3,  "delayMs": 300 }
  },
  "credentials": {
    "githubToken": "${GITHUB_TOKEN}",
    "nvdApiKey":   "${NVD_API_KEY}",
    "storage": "env",
    "keyringSupport": false
  },
  "ecosystems": ["nodejs", "bun"],
  "severity": ["high", "critical"],
  "excludeDevDeps": false,
  "keybindings": "arrows",
  "outputFormat": "sbom"
}
```

For local PostgreSQL (individual connection fields):

```json
"database": {
  "engine": "postgresql",
  "host": "localhost",
  "port": 5432,
  "database": "opensentinel",
  "user": "postgres",
  "password": "${DB_PASSWORD}",
  "ssl": false,
  "poolSize": 5
}
```

> Credential values starting with `${...}` are read from environment variables at runtime. Set `storage: "keyring"` to use the OS keyring instead.

### Cloud databases (Neon, Vercel, Railway)

Use the `url` field for managed PostgreSQL providers:

```json
{
  "database": {
    "url": "${DATABASE_URL}"
  }
}
```

When `url` is set it takes precedence over `host`, `port`, `user`, and `password`.

### Source analysis

By default, OpenSentinel only checks advisory databases (no source download). To enable full code analysis:

```json
"sourceAnalysis": {
  "downloadSource": true,
  "analyzeAst": true
}
```

With `downloadSource: true`, OpenSentinel fetches package tarballs and scans the actual source code. Results appear as `[CODE]` entries in the TUI with file paths, line numbers, and code snippets.

`analyzeAst: true` activates both detection layers:

| Layer | What it does |
|-------|-------------|
| Regex (Phase 2A) | Line-by-line pattern matching across all supported file types. Fast, works on shell scripts, YAML, and any text file. |
| AST semantic (Phase 2B) | Tree-sitter parses JS/TS/Python/Go source into an AST. Detects actual function calls with suspicious arguments. Code in comments never triggers a finding. AST findings carry higher confidence than regex findings for the same pattern. |

Both layers run in every scan; AST is additive. A finding from AST and regex for the same line appears once, with the higher confidence score taking precedence.

---

## Detection Capabilities

### Advisory databases

- **OSV** — Open Source Vulnerabilities (covers npm, PyPI, Go, Rust, …)
- **GitHub Security Advisories** — curated advisories from the GitHub Advisory Database
- **NVD** — National Vulnerability Database (NIST CVE feed)

Each advisory shows its canonical URL (`osv.dev`, `nvd.nist.gov`, `github.com/advisories`) directly in the TUI detail panel.

### Code pattern detection

Detections appear as `[CODE]` entries in the TUI with the exact file path, line number, and a 120-character code snippet.

#### Credential and obfuscation patterns

| Category | Examples | Confidence |
|----------|---------|------------|
| Credential harvesting | `process.env["API_KEY"]`, hardcoded secrets, SSH key patterns, AWS access keys | 0.60–0.99 |
| Crypto mining | Mining pool connections (`stratum+tcp://`), CoinHive, XMRig | 0.75–0.98 |
| Network exfiltration | HTTP POST to external hosts, DNS lookup with env var | 0.65–0.90 |
| Obfuscated code | `eval(Buffer.from(..., 'base64'))`, dynamic `require` via encoded strings | 0.92–0.98 |

#### Behavioral patterns — regex (all languages)

| Category | Examples | Confidence |
|----------|---------|------------|
| Filesystem access | `/etc/passwd`, `/etc/shadow`, `/proc/self`, `~/.ssh`, `~/.aws`, writes to `/etc/`/`/boot/` | 0.70–0.95 |
| Network connection | `bash -i >& /dev/tcp/`, `nc -e /bin/bash`, hardcoded IPs, ports 4444/6667/31337 | 0.50–0.98 |
| System call | `execve /bin/bash`, `sudo chmod 4000`, `setuid`, `LD_PRELOAD`, `ptrace`, `fork()` | 0.70–0.95 |

#### Behavioral patterns — AST semantic (JS/TS/Python/Go)

AST detection uses Tree-sitter to parse source files. Code inside comments is ignored; only actual function calls are evaluated. AST findings carry higher confidence than regex findings for the same pattern.

| Language | Filesystem | System call | Network |
|----------|-----------|-------------|---------|
| JavaScript / TypeScript | `fs.readFile/Sync()`, `fs.open()`, `fs.createReadStream()` with sensitive path | `child_process.exec/spawn/execFile[Sync]()` | `net.createConnection()`, `http.request()` on suspicious port |
| Python | `open()`, `os.open()` with sensitive path | `subprocess.run/Popen/call()`, `os.system/popen/execv()` | `socket.connect()` on suspicious port |
| Go | `os.Open/ReadFile()`, `ioutil.ReadFile()` with sensitive path | `exec.Command/CommandContext()` | `net.Dial/DialTCP()` on suspicious port |

```js
// This comment is ignored by AST analysis:
// fs.readFileSync('/etc/passwd')

// This is detected (actual call):
const data = fs.readFileSync('/etc/passwd', 'utf8');  // confidence 0.96
```

### Additional checks

- **Install scripts** — `preinstall`/`postinstall`/`prepare` hooks
- **Typosquatting** — names suspiciously similar to well-known packages
- **Version behavior** — unexpected changes between releases (file removals, license changes, new dependencies)
- **Maintainer reputation** — GitHub commit cadence, open issues, contributor count

### MITRE ATT&CK mapping

Every detection is automatically mapped to one or more [MITRE ATT&CK](https://attack.mitre.org) techniques. Technique IDs and names appear in the TUI detail panel alongside each finding, with a direct link to `attack.mitre.org`.

| Detection category | Tactic | Techniques |
|-------------------|--------|-----------|
| Credential Harvesting | Credential Access | [T1552](https://attack.mitre.org/techniques/T1552/) · [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Credentials In Files |
| Crypto Mining | Impact | [T1496](https://attack.mitre.org/techniques/T1496/) Resource Hijacking |
| Network Exfiltration | Exfiltration / C2 | [T1041](https://attack.mitre.org/techniques/T1041/) · [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Web Protocols |
| Obfuscated Code | Defense Evasion | [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information |
| Install Hook | Initial Access | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) Compromise Software Dependencies |
| Typosquatting | Initial Access | [T1195](https://attack.mitre.org/techniques/T1195/) Supply Chain Compromise |
| Reverse Shell | Execution / C2 | [T1059](https://attack.mitre.org/techniques/T1059/) · [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer |
| Filesystem Access | Discovery / Exfiltration | [T1005](https://attack.mitre.org/techniques/T1005/) Data Staging · [T1057](https://attack.mitre.org/techniques/T1057/) Process Discovery · [T1083](https://attack.mitre.org/techniques/T1083/) File & Directory Discovery |
| Network Connection | Command and Control | [T1071](https://attack.mitre.org/techniques/T1071/) App Layer Protocol · [T1090](https://attack.mitre.org/techniques/T1090/) Proxy · [T1095](https://attack.mitre.org/techniques/T1095/) Non-App Layer Protocol |
| System Call | Execution | [T1059](https://attack.mitre.org/techniques/T1059/) Command Interpreter · [T1106](https://attack.mitre.org/techniques/T1106/) Native API |

---

## CI/CD Integration

OpenSentinel returns structured exit codes suitable for use in pipelines:

| Exit code | Meaning |
|-----------|---------|
| `0` | No risks, or only LOW severity |
| `1` | MEDIUM severity risks found |
| `2` | HIGH severity risks found |
| `3` | CRITICAL severity risks found |

### Auto-generated GitHub Actions workflow

```bash
opse init --ci
```

This creates `.github/workflows/opensentinel.yml` with:
- Scan on every push and pull request to `main`/`master`
- Weekly scheduled scan (Mondays 06:00 UTC)
- JSON report uploaded as a build artifact
- Pipeline failure on CRITICAL vulnerabilities

Add these secrets to your repository:

| Secret | Required | Notes |
|--------|----------|-------|
| `GITHUB_TOKEN` | No | Already available in Actions |
| `DATABASE_URL` | No | Enables scan history persistence |
| `NVD_API_KEY` | No | Faster NVD lookups, avoids rate limits |

### Manual pipeline snippet

```yaml
- name: Security scan
  run: opse analyze --format json --output report.json
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
    DATABASE_URL: ${{ secrets.DATABASE_URL }}

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: opensentinel-report
    path: report.json
```

---

## Supported Ecosystems

| Ecosystem | Manifest / lock files parsed | OSV registry name |
|-----------|------------------------------|-------------------|
| Node.js | `package.json`, `package-lock.json` (v1/v2/v3), `yarn.lock` (classic + berry), `pnpm-lock.yaml` | `npm` |
| Bun | `bun.lock`, `bunfig.toml` | `npm` |
| Rust | `Cargo.toml`, `Cargo.lock` | `crates.io` |
| Go | `go.mod`, `go.sum` | `Go` |
| Python | `requirements.txt`, `pyproject.toml` (PEP 621 + Poetry), `poetry.lock`, `Pipfile.lock` | `PyPI` |

---

## Tech Stack

| Component | Library |
|-----------|---------|
| Language | Rust |
| Async runtime | Tokio |
| Terminal UI | Ratatui + Crossterm |
| HTTP client | Reqwest |
| Database | SQLx (PostgreSQL) |
| AST parsing | Tree-sitter |
| Serialization | Serde |
| SBOM output | CycloneDX |
| File watching | Notify |

---

## Contributing

Contributions are welcome. Please open an issue before submitting large changes.

```bash
# Run all tests (208 tests — 158 unit + 50 integration)
cargo test

# Run only unit tests
cargo test --lib

# Run a specific integration suite
cargo test --test behavioral_integration_test
cargo test --test behavioral_ast_integration_test

# Check for warnings (treated as errors)
cargo clippy -- -D warnings

# Format
cargo fmt
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
