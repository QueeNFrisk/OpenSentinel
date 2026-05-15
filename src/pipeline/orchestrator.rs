use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::path::{Path, PathBuf};

use crate::advisory::fetcher::AdvisoryFetcher;
use crate::analyzer::credential::CredentialHarvestingDetector;
use crate::analyzer::install_hook::InstallHookAnalyzer;
use crate::analyzer::typosquatting::TyposquattingDetector;
use crate::analyzer::models::AnalysisResult;
use crate::cache::manager::CacheManager;
use crate::config::{CredentialResolver, OpenSentinelConfig};
use crate::database::models::SeverityLevel;
use crate::parser::models::ParsedPackage;
use crate::parser::resolver::DependencyResolver;
use crate::scoring::engine::RiskScorer;
use crate::scoring::models::PackageRisk;
use super::progress::ScanReporter;

pub struct ScanOrchestrator {
	config: OpenSentinelConfig,
	project_path: PathBuf,
}

impl ScanOrchestrator {
	pub fn new(config: &OpenSentinelConfig, project_path: &Path) -> Self {
		Self { config: config.clone(), project_path: project_path.to_path_buf() }
	}

	pub async fn run(&self, progress: &dyn ScanReporter) -> Result<Vec<PackageRisk>> {
		let trees = DependencyResolver::resolve(
			&self.project_path,
			&self.config.ecosystems,
		)
		.await?;

		let all_packages: Vec<ParsedPackage> = trees
			.into_iter()
			.flat_map(|t| t.packages.into_values())
			.collect();

		let total = all_packages.len() as u64;

		if total == 0 {
			return Ok(Vec::new());
		}

		progress.set_total(total);

		let credentials = CredentialResolver::resolve_credentials(&self.config.credentials)?;
		let fetcher = AdvisoryFetcher::new(&credentials, self.config.parallelism.clone());
		let concurrency = self.config.parallelism.package_concurrency;

		let cache_manager = self.build_cache_manager();
		let download_source = self.config.source_analysis.download_source;
		let analyze_ast = self.config.source_analysis.analyze_ast;
		let project_path = self.project_path.clone();

		let risks = stream::iter(all_packages.into_iter())
			.map(|package| {
				let fetcher = &fetcher;
				let progress = &progress;
				let cache_manager = &cache_manager;
				let project_path = project_path.clone();

				async move {
					progress.tick_package(&package.name);

					let advisories = fetcher
						.fetch_for_package(&package)
						.await
						.unwrap_or_default();

					progress.tick_advisory();

					let scan_path = Self::resolve_scan_path(
						&package,
						&project_path,
						download_source,
						cache_manager,
					)
					.await;

					let mut detections = if analyze_ast {
						CredentialHarvestingDetector::scan_directory_with_ast(&scan_path).await
					} else {
						CredentialHarvestingDetector::scan_directory(&scan_path).await
					}
					.unwrap_or_default();

					detections.extend(InstallHookAnalyzer::analyze(&package));

					if let Some(typo) = TyposquattingDetector::check(&package.name) {
						detections.push(typo);
					}

					progress.tick_analysis();

					let analysis = AnalysisResult {
						package_name: package.name.clone(),
						package_version: package.version.clone(),
						matches: detections,
						has_install_scripts: !package.install_scripts.is_empty(),
					};

					RiskScorer::score(&package, advisories, analysis)
				}
			})
			.buffer_unordered(concurrency)
			.collect::<Vec<_>>()
			.await;

		progress.finish();

		Ok(risks)
	}

	async fn resolve_scan_path(
		package: &ParsedPackage,
		project_path: &Path,
		download_source: bool,
		cache: &CacheManager,
	) -> PathBuf {
		if !download_source {
			return project_path.to_path_buf();
		}

		match cache.ensure_source(&package.name, &package.version).await {
			Ok(cached_path) => cached_path,
			Err(_) => project_path.to_path_buf(),
		}
	}

	fn build_cache_manager(&self) -> CacheManager {
		let cache_dir = dirs::home_dir()
			.unwrap_or_default()
			.join(".opensentinel")
			.join("cache");

		let ttl = self.config.source_analysis.cache_ttl;
		CacheManager::new(cache_dir, ttl)
	}

	pub fn worst_severity(risks: &[PackageRisk]) -> SeverityLevel {
		risks
			.iter()
			.map(|r| &r.overall_severity)
			.max_by(|a, b| {
				Self::severity_rank(a).cmp(&Self::severity_rank(b))
			})
			.cloned()
			.unwrap_or(SeverityLevel::Safe)
	}

	pub fn exit_code(risks: &[PackageRisk]) -> i32 {
		match Self::worst_severity(risks) {
			SeverityLevel::Safe => 0,
			SeverityLevel::Low => 0,
			SeverityLevel::Medium => 1,
			SeverityLevel::High => 2,
			SeverityLevel::Critical => 3,
		}
	}

	fn severity_rank(s: &SeverityLevel) -> u8 {
		match s {
			SeverityLevel::Safe => 0,
			SeverityLevel::Low => 1,
			SeverityLevel::Medium => 2,
			SeverityLevel::High => 3,
			SeverityLevel::Critical => 4,
		}
	}
}
