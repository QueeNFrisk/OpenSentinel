use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub mod handlers;

#[derive(Parser, Debug)]
#[command(
	name = "opse",
	version = "0.1.0",
	about = "Supply Chain Security Scanner - Analyze dependencies for vulnerabilities and malicious patterns",
	long_about = "OpenSentinel scans your project dependencies for security vulnerabilities, \
								malicious patterns, and supply chain risks. Supports Node.js and Bun ecosystems."
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
