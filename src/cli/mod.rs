use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub mod handlers;

#[derive(Parser, Debug)]
#[command(
	name = "opse",
	version = "0.1.0",
	about = "Supply Chain Security Scanner - Analyze dependencies for vulnerabilities and malicious patterns",
	long_about = "OpenSentinel scans your project dependencies for security vulnerabilities, \
								malicious patterns, and supply chain risks. Supports Node.js and Bun ecosystems.",
	after_help = "Examples:
  opse scan                          Scan current directory (interactive TUI)
  opse scan ~/projects/myapp         Scan a specific project
  opse scan -e nodejs                Scan only Node.js packages
  opse scan -s high,critical         Show only high and critical risks
  opse scan --format json            Output JSON without launching TUI
  opse analyze --format table        Print a risk table to stdout
  opse history                       List previous scans for current project
  opse history --all                 List scans across all projects
  opse view 3f2a1b4c                 Re-open a previous scan in the TUI
  opse init                          Create opensentinel.json interactively"
)]
pub struct Cli {
	#[command(subcommand)]
	pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
	#[command(about = "Scan a project for vulnerabilities and security risks")]
	Scan(ScanOptions),

	#[command(about = "Analyze dependencies without launching interactive TUI")]
	Analyze(AnalyzeOptions),

	#[command(about = "Generate reports from cached scan data")]
	Report(ReportOptions),

	#[command(about = "Clear cached data")]
	CacheClear,

	#[command(about = "Initialize a project config file (opensentinel.json)")]
	Init(InitOptions),

	#[command(about = "Community malicious package database commands")]
	Community(CommunityOptions),

	#[command(about = "List previous scans stored in the database")]
	History(HistoryOptions),

	#[command(about = "Open a previous scan in the interactive TUI")]
	View(ViewOptions),
}

#[derive(Parser, Debug)]
pub struct CommunityOptions {
	#[command(subcommand)]
	pub command: CommunityCommands,
}

#[derive(Subcommand, Debug)]
pub enum CommunityCommands {
	#[command(about = "List all known malicious packages in the bundled database")]
	List {
		#[arg(
			short,
			long,
			help = "Filter by ecosystem (npm, pypi, cargo, ...)"
		)]
		ecosystem: Option<String>,

		#[arg(
			short,
			long,
			help = "Filter by severity (critical, high, medium, low)"
		)]
		severity: Option<String>,
	},

	#[command(about = "Show the bundled database version and entry count")]
	Info,
}

#[derive(Parser, Debug)]
pub struct InitOptions {
	#[arg(
		default_value = ".",
		help = "Path to project directory where opensentinel.json will be created"
	)]
	pub path: PathBuf,

	#[arg(
		short,
		long,
		help = "Overwrite existing opensentinel.json without prompting"
	)]
	pub force: bool,
}

#[derive(Parser, Debug)]
#[command(
	after_help = "Examples:
  opse scan                              Scan current directory (launches TUI)
  opse scan ~/projects/myapp            Scan a specific project
  opse scan -e nodejs                   Only scan Node.js packages
  opse scan -e nodejs,bun               Scan Node.js and Bun packages
  opse scan -s high,critical            Show only high and critical risks
  opse scan --format json               Output JSON, no TUI
  opse scan --format table              Print risk table to stdout
  opse scan --format json -o out.json   Save JSON report to file
  opse scan --exclude devDependencies   Skip dev dependencies
  opse scan --depth 3                   Limit transitive depth to 3 levels
  opse scan --no-cache                  Skip cached advisory data"
)]
pub struct ScanOptions {
	#[arg(
		default_value = ".",
		help = "Path to project directory containing package.json or bunfig.toml"
	)]
	pub path: PathBuf,

	#[arg(
		short,
		long,
		value_delimiter = ',',
		help = "Filter by severity levels: high, critical, medium, low"
	)]
	pub severity: Option<Vec<String>>,

	#[arg(
		short,
		long,
		value_delimiter = ',',
		help = "Ecosystems to scan: nodejs, bun"
	)]
	pub ecosystem: Option<Vec<String>>,

	#[arg(
		short,
		long,
		help = "Path to advisories ignore file"
	)]
	pub ignore_advisories: Option<PathBuf>,

	#[arg(
		long,
		help = "Limit dependency tree depth"
	)]
	pub depth: Option<u32>,

	#[arg(
		long,
		value_delimiter = ',',
		help = "Exclude dependency types: devDependencies, optionalDependencies"
	)]
	pub exclude: Option<Vec<String>>,

	#[arg(
		long,
		help = "Disable cache usage"
	)]
	pub no_cache: bool,

	#[arg(
		long,
		help = "Custom cache directory"
	)]
	pub cache_dir: Option<PathBuf>,

	#[arg(
		long,
		value_name = "FORMAT",
		help = "Output format for non-interactive mode: sbom, json, table, html. Omit to use TUI."
	)]
	pub format: Option<String>,

	#[arg(
		short,
		long,
		help = "Save output to file (implies non-interactive)"
	)]
	pub output: Option<PathBuf>,

	#[arg(
		long,
		value_name = "KEYBINDINGS",
		default_value = "arrows",
		help = "TUI keybindings: arrows or vim"
	)]
	pub keybindings: String,
}

#[derive(Parser, Debug)]
#[command(
	after_help = "Examples:
  opse analyze                        Analyze current directory (JSON output)
  opse analyze --format table         Print risk table to stdout
  opse analyze --format html -o r.html  Save HTML report
  opse analyze -s critical            Only critical risks
  opse analyze -e nodejs              Only Node.js packages"
)]
pub struct AnalyzeOptions {
	#[arg(default_value = ".")]
	pub path: PathBuf,

	#[arg(short, long)]
	pub severity: Option<Vec<String>>,

	#[arg(short, long)]
	pub ecosystem: Option<Vec<String>>,

	#[arg(long)]
	pub depth: Option<u32>,

	#[arg(long)]
	pub exclude: Option<Vec<String>>,

	#[arg(long)]
	pub no_cache: bool,

	#[arg(long)]
	pub cache_dir: Option<PathBuf>,

	#[arg(
		short,
		long,
		value_name = "FORMAT",
		default_value = "json"
	)]
	pub format: String,

	#[arg(short, long)]
	pub output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(
	after_help = "Examples:
  opse history                        Scans for the current project
  opse history --all                  All projects in the database
  opse history --all --limit 50       Last 50 scans across all projects
  opse history --path ~/projects/app  Scans for a specific project"
)]
pub struct HistoryOptions {
	#[arg(
		short,
		long,
		help = "Filter by project path (defaults to current directory)"
	)]
	pub path: Option<PathBuf>,

	#[arg(
		short,
		long,
		help = "Show scans from all projects"
	)]
	pub all: bool,

	#[arg(
		short,
		long,
		default_value = "20",
		help = "Maximum number of scans to show"
	)]
	pub limit: i64,
}

#[derive(Parser, Debug)]
#[command(
	after_help = "Examples:
  opse view 3f2a1b4c                  Open scan by short ID (from `opse history`)
  opse view 3f2a1b4c --keybindings vim"
)]
pub struct ViewOptions {
	#[arg(help = "Scan ID to view (full UUID or first 8 characters)")]
	pub scan_id: String,

	#[arg(
		long,
		value_name = "KEYBINDINGS",
		default_value = "arrows",
		help = "TUI keybindings: arrows or vim"
	)]
	pub keybindings: String,
}

#[derive(Parser, Debug)]
pub struct ReportOptions {
	#[arg(help = "Source scan data file")]
	pub source: PathBuf,

	#[arg(
		short,
		long,
		value_name = "FORMAT",
		default_value = "html"
	)]
	pub format: String,

	#[arg(short, long)]
	pub output: Option<PathBuf>,
}
