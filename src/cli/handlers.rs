use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process;

use crate::config::{ConfigLoader, KeybindingsMode, OutputFormat};
use crate::report::{HtmlReporter, JsonReporter, Reporter, SbomReporter, TableReporter};
use crate::tui::app::TuiApp;
use crate::tui::InitWizard;

use super::{AnalyzeOptions, InitOptions, ReportOptions, ScanOptions};

pub async fn handle_scan(opts: ScanOptions) -> Result<()> {
	let project_path = opts.path.canonicalize()
		.with_context(|| format!("path not found: {}", opts.path.display()))?;

	let config = ConfigLoader::load(&project_path)?;
	let output_path = opts.output.as_deref();
	let keybindings = resolve_keybindings(&opts.keybindings, &config);

	if let Some(fmt_flag) = &opts.format {
		let format = resolve_output_format(fmt_flag, &config);
		let progress = crate::pipeline::ScanProgress::new();
		let orchestrator = crate::pipeline::ScanOrchestrator::new(&config, &project_path);
		let mut risks = orchestrator.run(&progress).await?;
		apply_severity_filter(&mut risks, &opts.severity);
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
		let orchestrator = crate::pipeline::ScanOrchestrator::new(&config, &project_path);
		let mut risks = orchestrator.run(&progress).await?;
		apply_severity_filter(&mut risks, &opts.severity);
		let exit_code = crate::pipeline::ScanOrchestrator::exit_code(&risks);
		match format {
			OutputFormat::Json  => JsonReporter.generate(&risks, output_path)?,
			OutputFormat::Table => TableReporter.generate(&risks, output_path)?,
			OutputFormat::Html  => HtmlReporter.generate(&risks, output_path)?,
			OutputFormat::Sbom  => SbomReporter.generate(&risks, output_path)?,
		}
		process::exit(exit_code);
	}

	let (mut app, _handle) = TuiApp::new_scanning(&config, project_path, keybindings);
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

pub async fn handle_analyze(opts: AnalyzeOptions) -> Result<()> {
	let project_path = opts.path.canonicalize()
		.with_context(|| format!("path not found: {}", opts.path.display()))?;

	let config = ConfigLoader::load(&project_path)?;

	let progress = crate::pipeline::ScanProgress::new();
	let orchestrator = crate::pipeline::ScanOrchestrator::new(&config, &project_path);
	let mut risks = orchestrator.run(&progress).await?;

	apply_severity_filter(&mut risks, &opts.severity);

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

    let Some(cfg) = InitWizard::new().run()? else {
        println!("Cancelled.");
        return Ok(());
    };

    let pretty = serde_json::to_string_pretty(&cfg).expect("failed to serialize config");
    std::fs::write(&config_path, &pretty)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("Created {}", config_path.display());
    Ok(())
}

pub async fn handle_cache_clear() -> Result<()> {
	let cache_dir = dirs::home_dir()
		.unwrap_or_else(|| PathBuf::from("."))
		.join(".opensentinel")
		.join("cache");

	let manager = crate::cache::CacheManager::new(cache_dir.clone(), 0);
	manager.clear()?;

	println!("Cache cleared: {}", cache_dir.display());

	Ok(())
}

fn apply_severity_filter(
	risks: &mut Vec<crate::scoring::models::PackageRisk>,
	filter: &Option<Vec<String>>,
) {
	if let Some(levels) = filter {
		if !levels.is_empty() {
			risks.retain(|r| {
				levels.iter().any(|l| l.eq_ignore_ascii_case(r.severity_label()))
			});
		}
	}
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
