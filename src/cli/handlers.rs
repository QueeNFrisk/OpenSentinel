use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process;

use crate::community::CommunityChecker;
use crate::config::{ConfigLoader, KeybindingsMode, OutputFormat};
use crate::database::pool::DatabasePool;
use crate::report::{HtmlReporter, JsonReporter, Reporter, SbomReporter, TableReporter};
use crate::tui::app::TuiApp;
use crate::tui::InitWizard;

use super::{AnalyzeOptions, CommunityCommands, CommunityOptions, HistoryOptions, InitOptions, ReportOptions, ScanOptions, ViewOptions};

pub async fn handle_scan(opts: ScanOptions) -> Result<()> {
	let project_path = opts.path.canonicalize()
		.with_context(|| format!("path not found: {}", opts.path.display()))?;

	let config = ConfigLoader::load(&project_path)?;
	let output_path = opts.output.as_deref();
	let keybindings = resolve_keybindings(&opts.keybindings, &config);

	if let Some(fmt_flag) = &opts.format {
		let format = resolve_output_format(fmt_flag, &config);
		let progress = crate::pipeline::ScanProgress::new();
		let orchestrator = build_orchestrator(
			&config, &project_path,
			opts.depth, &opts.exclude, &opts.ecosystem, opts.no_cache, opts.cache_dir.clone(),
		).await;
		let mut risks = orchestrator.run(&progress).await?;
		apply_severity_filter(&mut risks, &opts.severity, &config.severity);
		let exit_code = crate::pipeline::ScanOrchestrator::exit_code(&risks);
		match format {
			OutputFormat::Json  => JsonReporter.generate(&risks, output_path)?,
			OutputFormat::Table => TableReporter.generate(&risks, output_path)?,
			OutputFormat::Html  => HtmlReporter.generate(&risks, output_path)?,
			OutputFormat::Sbom  => SbomReporter.generate(&risks, output_path)?,
		}
		process::exit(exit_code);
	}

	if output_path.is_some() {
		let format = resolve_output_format("sbom", &config);
		let progress = crate::pipeline::ScanProgress::new();
		let orchestrator = build_orchestrator(
			&config, &project_path,
			opts.depth, &opts.exclude, &opts.ecosystem, opts.no_cache, opts.cache_dir.clone(),
		).await;
		let mut risks = orchestrator.run(&progress).await?;
		apply_severity_filter(&mut risks, &opts.severity, &config.severity);
		let exit_code = crate::pipeline::ScanOrchestrator::exit_code(&risks);
		match format {
			OutputFormat::Json  => JsonReporter.generate(&risks, output_path)?,
			OutputFormat::Table => TableReporter.generate(&risks, output_path)?,
			OutputFormat::Html  => HtmlReporter.generate(&risks, output_path)?,
			OutputFormat::Sbom  => SbomReporter.generate(&risks, output_path)?,
		}
		process::exit(exit_code);
	}

	let mut tui_config = config.clone();
	if let Some(ref eco) = opts.ecosystem {
		if !eco.is_empty() { tui_config.ecosystems = eco.clone(); }
	} else if !ConfigLoader::has_explicit_ecosystems(&project_path) {
		let detected = crate::parser::detector::detect_ecosystems(&project_path);
		if !detected.is_empty() { tui_config.ecosystems = detected; }
	}

	if opts.watch {
		return run_watch_mode(tui_config, project_path, opts).await;
	}

	let (mut app, _handle) = TuiApp::new_scanning(&tui_config, project_path, keybindings);
	let mut renderer = crate::tui::renderer::Renderer::new()?;

	// Render loop runs on blocking thread pool — frees tokio workers for the scan
	let app = tokio::task::spawn_blocking(move || -> anyhow::Result<TuiApp> {
		renderer.run(&mut app)?;
		Ok(app)
	})
	.await??;

	if let crate::tui::app::AppState::Results(ref state) = app.state {
		let exit_code = crate::pipeline::ScanOrchestrator::exit_code(&state.risks);
		process::exit(exit_code);
	}

	Ok(())
}

async fn run_watch_mode(
	config: crate::config::OpenSentinelConfig,
	project_path: std::path::PathBuf,
	opts: ScanOptions,
) -> Result<()> {
	use notify::{RecursiveMode, Watcher, recommended_watcher};
	use std::sync::mpsc;
	use std::time::Duration;

	const LOCKFILES: &[&str] = &[
		"Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"bun.lockb", "go.sum", "poetry.lock", "Pipfile.lock",
	];

	println!("Watching {} for lockfile changes  (Ctrl+C to stop)", project_path.display());
	println!("{}", "─".repeat(60));

	let (tx, rx) = mpsc::channel();
	let mut watcher = recommended_watcher(move |event| {
		let _ = tx.send(event);
	})?;
	watcher.watch(&project_path, RecursiveMode::NonRecursive)?;

	loop {
		let progress = crate::pipeline::ScanProgress::new();
		let orchestrator = build_orchestrator(
			&config, &project_path,
			opts.depth, &opts.exclude, &opts.ecosystem, opts.no_cache, opts.cache_dir.clone(),
		).await;

		match orchestrator.run(&progress).await {
			Ok(mut risks) => {
				apply_severity_filter(&mut risks, &opts.severity, &config.severity);
				TableReporter.generate(&risks, None)?;
				let worst = crate::pipeline::ScanOrchestrator::worst_severity(&risks);
				println!("\nWatching for changes…  (worst: {:?})", worst);
			}
			Err(e) => eprintln!("Scan error: {e}"),
		}

		loop {
			match rx.recv_timeout(Duration::from_millis(500)) {
				Ok(Ok(event)) => {
					let is_lockfile = event.paths.iter().any(|p| {
						p.file_name()
							.and_then(|n| n.to_str())
							.map_or(false, |name| LOCKFILES.contains(&name))
					});
					if is_lockfile {
						println!("\nChange detected — rescanning…");
						break;
					}
				}
				Ok(Err(e)) => {
					eprintln!("Watch error: {e}");
					break;
				}
				Err(mpsc::RecvTimeoutError::Timeout) => continue,
				Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
			}
		}
	}
}

pub async fn handle_analyze(opts: AnalyzeOptions) -> Result<()> {
	let project_path = opts.path.canonicalize()
		.with_context(|| format!("path not found: {}", opts.path.display()))?;

	let config = ConfigLoader::load(&project_path)?;

	let progress = crate::pipeline::ScanProgress::new();
	let orchestrator = build_orchestrator(
		&config, &project_path,
		opts.depth, &opts.exclude, &opts.ecosystem, opts.no_cache, opts.cache_dir.clone(),
	).await;
	let mut risks = orchestrator.run(&progress).await?;

	apply_severity_filter(&mut risks, &opts.severity, &config.severity);

	let exit_code = crate::pipeline::ScanOrchestrator::exit_code(&risks);

	let format = resolve_output_format(&opts.format, &config);
	let output_path = opts.output.as_deref();

	match format {
		OutputFormat::Json => JsonReporter.generate(&risks, output_path)?,
		OutputFormat::Table => TableReporter.generate(&risks, output_path)?,
		OutputFormat::Html => HtmlReporter.generate(&risks, output_path)?,
		OutputFormat::Sbom => SbomReporter.generate(&risks, output_path)?,
	}

	process::exit(exit_code);
}

pub async fn handle_report(opts: ReportOptions) -> Result<()> {
	let content = std::fs::read_to_string(&opts.source)
		.with_context(|| format!("failed to read {}", opts.source.display()))?;

	let risks: Vec<crate::scoring::models::PackageRisk> = serde_json::from_str(&content)
		.with_context(|| "failed to parse scan data — must be a JSON report from opse analyze")?;

	let output_path = opts.output.as_deref();

	match opts.format.as_str() {
		"json" => JsonReporter.generate(&risks, output_path)?,
		"table" => TableReporter.generate(&risks, output_path)?,
		"html" => HtmlReporter.generate(&risks, output_path)?,
		_ => SbomReporter.generate(&risks, output_path)?,
	}

	Ok(())
}

pub async fn handle_init(opts: InitOptions) -> Result<()> {
    let project_path = if opts.path.as_os_str() == "." {
        std::env::current_dir().context("failed to get current directory")?
    } else {
        opts.path
            .canonicalize()
            .with_context(|| format!("path not found: {}", opts.path.display()))?
    };

    let config_path = project_path.join("opensentinel.json");

    if config_path.exists() && !opts.force {
        bail!(
            "{} already exists. Use --force to overwrite.",
            config_path.display()
        );
    }

    let Some(mut cfg) = InitWizard::new().run()? else {
        println!("Cancelled.");
        return Ok(());
    };

    // "auto" means don't write ecosystems key → auto-detection kicks in at scan time
    if cfg.get("ecosystems").and_then(|v| v.as_array())
        .map_or(false, |arr| arr.len() == 1 && arr[0].as_str() == Some("auto"))
    {
        if let Some(obj) = cfg.as_object_mut() {
            obj.remove("ecosystems");
        }
    }

    let pretty = serde_json::to_string_pretty(&cfg).expect("failed to serialize config");
    std::fs::write(&config_path, &pretty)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    println!("Created {}", config_path.display());

    if opts.ci {
        generate_ci_workflow(&project_path)?;
    }

    Ok(())
}

fn generate_ci_workflow(project_path: &std::path::Path) -> Result<()> {
    let workflows_dir = project_path.join(".github").join("workflows");
    std::fs::create_dir_all(&workflows_dir)
        .with_context(|| format!("failed to create {}", workflows_dir.display()))?;

    let workflow_path = workflows_dir.join("opensentinel.yml");
    std::fs::write(&workflow_path, CI_WORKFLOW_TEMPLATE)
        .with_context(|| format!("failed to write {}", workflow_path.display()))?;

    println!("Created {}", workflow_path.display());
    println!("Add these secrets to your repository:");
    println!("  GITHUB_TOKEN    — already available in Actions");
    println!("  DATABASE_URL    — your OpenSentinel PostgreSQL URL (optional)");
    println!("  NVD_API_KEY     — NVD API key for faster lookups (optional)");
    Ok(())
}

const CI_WORKFLOW_TEMPLATE: &str = r#"name: OpenSentinel Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Mondays at 06:00 UTC

jobs:
  security-scan:
    name: Supply Chain Security
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install OpenSentinel
        run: |
          curl -fsSL https://github.com/yourusername/opensentinel/releases/latest/download/opse-linux-x86_64.tar.gz \
            | tar -xz -C /usr/local/bin

      - name: Run security scan
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: |
          opse analyze --format json --output opensentinel-report.json || true
          opse analyze --format table

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: opensentinel-report
          path: opensentinel-report.json
          retention-days: 30

      - name: Fail on critical vulnerabilities
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: opse analyze --severity critical
        # Exit code 3 = CRITICAL found, 2 = HIGH, 1 = MEDIUM, 0 = safe
"#;

pub async fn handle_community(opts: CommunityOptions) -> Result<()> {
	match opts.command {
		CommunityCommands::Info => {
			let checker = CommunityChecker::new();
			println!("OpenSentinel Community Malicious Package Database");
			println!("  Version : {}", checker.db_version());
			println!("  Entries : {}", checker.entry_count());
		}
		CommunityCommands::List { ecosystem, severity } => {
			let checker = CommunityChecker::new();
			let entries = checker.all_entries();

			let filtered: Vec<_> = entries
				.iter()
				.filter(|e| {
					if let Some(eco) = &ecosystem {
						if !e.ecosystem.eq_ignore_ascii_case(eco) { return false; }
					}
					if let Some(sev) = &severity {
						if !e.severity.label().eq_ignore_ascii_case(sev) { return false; }
					}
					true
				})
				.collect();

			if filtered.is_empty() {
				println!("No entries match the given filters.");
				return Ok(());
			}

			println!("{:<35} {:<8} {:<10} {}", "PACKAGE", "ECO", "SEVERITY", "REASON");
			println!("{}", "-".repeat(100));

			for e in &filtered {
				let versions = e.affected_versions
					.as_ref()
					.map(|v| v.join(", "))
					.unwrap_or_else(|| "all versions".to_string());
				let reason: String = e.reason.chars().take(55).collect();
				let reason = if e.reason.len() > 55 { format!("{reason}…") } else { reason };
				println!(
					"{:<35} {:<8} {:<10} {}",
					format!("{} ({})", e.package_name, versions),
					e.ecosystem,
					e.severity.label(),
					reason,
				);
			}

			println!("\n{} entries", filtered.len());
		}
	}
	Ok(())
}

pub async fn handle_cache_clear() -> Result<()> {
	let cache_dir = dirs::home_dir()
		.unwrap_or_else(|| PathBuf::from("."))
		.join(".opensentinel")
		.join("cache");

	let manager = crate::cache::CacheManager::new(cache_dir.clone(), 0);
	manager.clear()?;
	println!("File cache cleared: {}", cache_dir.display());

	let config = crate::config::OpenSentinelConfig::default();
	match DatabasePool::connect(&config.database).await {
		Ok(db) => {
			let pool = db.inner();
			let ttl = config.source_analysis.cache_ttl as i64;
			match crate::database::queries::AdvisoryQueries::delete_all_stale(pool, ttl).await {
				Ok(n) => println!("DB advisories removed: {n} stale records (older than {ttl}s)"),
				Err(e) => println!("DB advisory cleanup skipped: {e}"),
			}
			match crate::database::queries::delete_stale_maintainer_metrics(pool, ttl).await {
				Ok(n) => println!("DB maintainer metrics removed: {n} stale records"),
				Err(e) => println!("DB maintainer cleanup skipped: {e}"),
			}
		}
		Err(_) => println!("Database unavailable — skipping DB cleanup"),
	}

	Ok(())
}

async fn build_orchestrator(
	config: &crate::config::OpenSentinelConfig,
	project_path: &std::path::Path,
	depth: Option<u32>,
	exclude: &Option<Vec<String>>,
	ecosystem: &Option<Vec<String>>,
	no_cache: bool,
	cache_dir: Option<std::path::PathBuf>,
) -> crate::pipeline::ScanOrchestrator {
	let exclude_dev = config.exclude_dev_deps
		|| exclude
			.as_deref()
			.map_or(false, |v| v.iter().any(|e| e.eq_ignore_ascii_case("devDependencies")));

	let ecosystem_override = {
		let explicit = ecosystem.clone().filter(|v| !v.is_empty());
		if explicit.is_some() {
			explicit
		} else if !ConfigLoader::has_explicit_ecosystems(project_path) {
			let detected = crate::parser::detector::detect_ecosystems(project_path);
			if detected.is_empty() { None } else { Some(detected) }
		} else {
			None
		}
	};

	let base = crate::pipeline::ScanOrchestrator::new(config, project_path)
		.with_depth(depth)
		.with_exclude_dev(exclude_dev)
		.with_no_cache(no_cache)
		.with_cache_dir(cache_dir)
		.with_ecosystems(ecosystem_override);

	match DatabasePool::connect(&config.database).await {
		Ok(db) => base.with_db(db.inner().clone()),
		Err(_) => base,
	}
}

fn apply_severity_filter(
	risks: &mut Vec<crate::scoring::models::PackageRisk>,
	cli_filter: &Option<Vec<String>>,
	config_filter: &[String],
) {
	let levels: Vec<&String> = match cli_filter {
		Some(v) if !v.is_empty() => v.iter().collect(),
		_ if !config_filter.is_empty() => config_filter.iter().collect(),
		_ => return,
	};
	risks.retain(|r| {
		levels.iter().any(|l| l.eq_ignore_ascii_case(r.severity_label()))
	});
}

fn resolve_output_format(flag: &str, config: &crate::config::OpenSentinelConfig) -> OutputFormat {
	match flag {
		"json" => OutputFormat::Json,
		"table" => OutputFormat::Table,
		"html" => OutputFormat::Html,
		"sbom" => OutputFormat::Sbom,
		_ => config.output_format.clone(),
	}
}

fn resolve_keybindings(flag: &str, config: &crate::config::OpenSentinelConfig) -> KeybindingsMode {
	match flag {
		"vim" => KeybindingsMode::Vim,
		"arrows" => KeybindingsMode::Arrows,
		_ => config.keybindings.clone(),
	}
}

pub async fn handle_history(opts: HistoryOptions) -> Result<()> {
	let config = load_any_config()?;

	let pool = DatabasePool::connect(&config.database).await
		.context("could not connect to database — check your opensentinel.json")?;

	let project_filter = if opts.all {
		None
	} else if let Some(p) = &opts.path {
		let abs = p.canonicalize().unwrap_or_else(|_| p.clone());
		Some(abs.to_string_lossy().into_owned())
	} else {
		let cwd = std::env::current_dir()?;
		Some(cwd.to_string_lossy().into_owned())
	};

	let scans = crate::database::queries::ScanQueries::list_recent(
		pool.inner(),
		project_filter.as_deref(),
		opts.limit,
	).await?;

	if scans.is_empty() {
		println!("No scans found. Run `opse scan` first.");
		return Ok(());
	}

	println!(
		"{:<10}  {:<20}  {:<6}  {:>4}C {:>4}H {:>4}M {:>4}L  {}",
		"ID", "Date", "Pkgs", "", "", "", "", "Path"
	);
	println!("{}", "─".repeat(90));

	for s in &scans {
		let short_id = &s.id.to_string()[..8];
		let date = s.scanned_at.format("%Y-%m-%d %H:%M").to_string();
		println!(
			"{:<10}  {:<20}  {:<6}  {:>4} {:>4} {:>4} {:>4}  {}",
			short_id, date, s.total_packages,
			s.critical_count, s.high_count, s.medium_count, s.low_count,
			s.project_path,
		);
	}

	println!("\nUse `opse view <id>` to open any scan in the TUI.");
	Ok(())
}

pub async fn handle_view(opts: ViewOptions) -> Result<()> {
	let config = load_any_config()?;
	let keybindings = resolve_keybindings(&opts.keybindings, &config);

	let pool = DatabasePool::connect(&config.database).await
		.context("could not connect to database — check your opensentinel.json")?;

	let scan_id = resolve_scan_id(pool.inner(), &opts.scan_id).await?;

	let scan = crate::database::queries::ScanQueries::load_by_id(pool.inner(), scan_id)
		.await?
		.with_context(|| format!("scan '{}' not found", opts.scan_id))?;

	let json = scan.results_json
		.with_context(|| "scan has no stored results — it may have been saved by an older version")?;

	let risks: Vec<crate::scoring::models::PackageRisk> = serde_json::from_value(json)
		.context("could not deserialize scan results")?;

	let mut app = TuiApp::from_results(risks, keybindings);
	let mut renderer = crate::tui::renderer::Renderer::new()?;
	tokio::task::spawn_blocking(move || renderer.run(&mut app)).await??;
	Ok(())
}

pub async fn handle_badge(opts: super::BadgeOptions) -> Result<()> {
	use crate::database::models::SeverityLevel;

	let project_path = opts.path.canonicalize()
		.with_context(|| format!("path not found: {}", opts.path.display()))?;

	let config = ConfigLoader::load(&project_path)?;
	let progress = crate::pipeline::ScanProgress::new();
	let orchestrator = build_orchestrator(
		&config, &project_path,
		None, &None, &None, false, None,
	).await;

	let risks = orchestrator.run(&progress).await?;
	let worst = crate::pipeline::ScanOrchestrator::worst_severity(&risks);

	let (label, color) = match worst {
		SeverityLevel::Critical => ("critical", "critical"),
		SeverityLevel::High     => ("high",     "important"),
		SeverityLevel::Medium   => ("medium",   "yellow"),
		SeverityLevel::Low      => ("low",      "informational"),
		SeverityLevel::Safe     => ("passing",  "success"),
	};

	let style = &opts.style;
	let badge_url = format!(
		"https://img.shields.io/badge/security-{label}-{color}?style={style}&logo=rust"
	);
	let markdown = format!("[![Security]({badge_url})](https://github.com/yourusername/opensentinel)");

	match &opts.output {
		Some(path) => {
			std::fs::write(path, &markdown)
				.with_context(|| format!("failed to write {}", path.display()))?;
			println!("Badge saved to {}", path.display());
		}
		None => {
			println!("{markdown}");
			println!();
			println!("Worst severity : {worst:?}");
			println!("Packages       : {}", risks.len());
		}
	}

	Ok(())
}

fn load_any_config() -> Result<crate::config::OpenSentinelConfig> {
	let cwd = std::env::current_dir()?;
	ConfigLoader::load(&cwd)
}

async fn resolve_scan_id(pool: &sqlx::PgPool, input: &str) -> Result<uuid::Uuid> {
	if let Ok(id) = input.parse::<uuid::Uuid>() {
		return Ok(id);
	}
	let prefix = input.to_lowercase();
	let scans = crate::database::queries::ScanQueries::list_recent(pool, None, 100).await?;
	scans.into_iter()
		.find(|s| s.id.to_string().starts_with(&prefix))
		.map(|s| s.id)
		.with_context(|| format!("no scan found with id starting with '{input}'"))
}
