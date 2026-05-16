use anyhow::Result;
use futures::stream::{self, StreamExt};
use sqlx::PgPool;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::advisory::fetcher::AdvisoryFetcher;
use crate::advisory::github_meta::{GithubMetaClient, parse_github_owner_repo};
use crate::analyzer::credential::CredentialHarvestingDetector;
use crate::analyzer::install_hook::InstallHookAnalyzer;
use crate::analyzer::typosquatting::TyposquattingDetector;
use crate::analyzer::models::AnalysisResult;
use crate::analyzer::version_resolver::VersionDiffResolver;
use crate::cache::manager::CacheManager;
use crate::community::CommunityChecker;
use crate::config::{CredentialResolver, OpenSentinelConfig};
use crate::database::models::{MaintainerMetrics, SeverityLevel};
use crate::database::queries::{upsert_maintainer_metrics, upsert_version_diff};
use crate::parser::models::ParsedPackage;
use crate::parser::resolver::DependencyResolver;
use crate::scoring::engine::RiskScorer;
use crate::scoring::maintainer::MaintainerScorer;
use crate::scoring::models::PackageRisk;
use super::progress::ScanReporter;

pub struct ScanOrchestrator {
	config: OpenSentinelConfig,
	project_path: PathBuf,
	db_pool: Option<Arc<PgPool>>,
	max_depth: Option<u32>,
	exclude_dev: bool,
	no_cache: bool,
	cache_dir: Option<PathBuf>,
	ecosystem_override: Option<Vec<String>>,
}

impl ScanOrchestrator {
	pub fn new(config: &OpenSentinelConfig, project_path: &Path) -> Self {
		Self {
			config: config.clone(),
			project_path: project_path.to_path_buf(),
			db_pool: None,
			max_depth: None,
			exclude_dev: false,
			no_cache: false,
			cache_dir: None,
			ecosystem_override: None,
		}
	}

	pub fn with_db(mut self, pool: PgPool) -> Self {
		self.db_pool = Some(Arc::new(pool));
		self
	}

	pub fn with_depth(mut self, depth: Option<u32>) -> Self {
		self.max_depth = depth;
		self
	}

	pub fn with_exclude_dev(mut self, exclude: bool) -> Self {
		self.exclude_dev = exclude;
		self
	}

	pub fn with_no_cache(mut self, no_cache: bool) -> Self {
		self.no_cache = no_cache;
		self
	}

	pub fn with_cache_dir(mut self, dir: Option<PathBuf>) -> Self {
		self.cache_dir = dir;
		self
	}

	pub fn with_ecosystems(mut self, ecosystems: Option<Vec<String>>) -> Self {
		self.ecosystem_override = ecosystems;
		self
	}

	pub async fn run(&self, progress: &dyn ScanReporter) -> Result<Vec<PackageRisk>> {
		let ecosystems = self.ecosystem_override.as_deref()
			.unwrap_or(&self.config.ecosystems);

		let trees = DependencyResolver::resolve(
			&self.project_path,
			ecosystems,
		)
		.await?;

		let max_depth = self.max_depth;
		let exclude_dev = self.exclude_dev;

		let all_packages: Vec<ParsedPackage> = trees
			.into_iter()
			.flat_map(|t| t.packages.into_values())
			.filter(|p| max_depth.map_or(true, |d| p.depth <= d))
			.filter(|p| !exclude_dev || p.dev_dependencies.is_empty())
			.collect();

		let total = all_packages.len() as u64;

		if total == 0 {
			progress.log("No packages found — check ecosystems config");
			return Ok(Vec::new());
		}

		progress.log(&format!("Resolved {total} packages"));
		progress.set_total(total);
		progress.log("Fetching advisories  ·  OSV / GitHub / NVD");

		let credentials = CredentialResolver::resolve_credentials(&self.config.credentials)?;
		let fetcher = AdvisoryFetcher::new(&credentials, self.config.parallelism.clone());
		let version_resolver = VersionDiffResolver::new();
		let github_client = GithubMetaClient::new(credentials.github_token.clone());
		let community_checker = CommunityChecker::new();
		let concurrency = self.config.parallelism.package_concurrency;

		let cache_manager = self.build_cache_manager();
		let download_source = self.config.source_analysis.download_source;
		let analyze_ast = self.config.source_analysis.analyze_ast;
		let project_path = self.project_path.clone();
		let db_pool = self.db_pool.clone();

		let risks = stream::iter(all_packages.into_iter())
			.map(|package| {
				let fetcher = &fetcher;
				let progress = &progress;
				let cache_manager = &cache_manager;
				let version_resolver = &version_resolver;
				let github_client = &github_client;
				let community_checker = &community_checker;
				let db_pool = db_pool.clone();
				let project_path = project_path.clone();

				async move {
					progress.tick_package(&package.name);

					let package_id = uuid::Uuid::new_v4();

					let (advisories, version_changes, repo_url) = tokio::join!(
						fetcher.fetch_for_package(&package),
						version_resolver.resolve_diffs(package_id, &package.name, &package.version),
						github_client.fetch_repo_url_from_npm(&package.name),
					);
					let advisories = advisories.unwrap_or_default();

					if let Some(pool) = &db_pool {
						for diff in &version_changes {
							let _ = upsert_version_diff(pool, diff).await;
						}
					}

					progress.tick_advisory();

					let maintainer = Self::fetch_maintainer_metrics(
						&package,
						repo_url,
						github_client,
						db_pool.as_deref(),
					)
					.await;

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

					let community_reports = community_checker.check(
						&package.name,
						&package.version,
						&package.ecosystem,
					);

					let analysis = AnalysisResult {
						package_name: package.name.clone(),
						package_version: package.version.clone(),
						matches: detections,
						has_install_scripts: !package.install_scripts.is_empty(),
					};

					RiskScorer::score(&package, advisories, analysis, version_changes, maintainer, community_reports)
				}
			})
			.buffer_unordered(concurrency)
			.collect::<Vec<_>>()
			.await;

		progress.finish();

		Ok(risks)
	}

	async fn fetch_maintainer_metrics(
		package: &ParsedPackage,
		repo_url: Option<String>,
		github_client: &GithubMetaClient,
		db_pool: Option<&sqlx::PgPool>,
	) -> Option<MaintainerMetrics> {
		let url = repo_url?;
		let (owner, repo) = parse_github_owner_repo(&url)?;

		let gh_metrics = github_client
			.fetch_repo_metrics(&owner, &repo)
			.await
			.ok()?;

		let health = {
			let tmp = MaintainerMetrics {
				id: uuid::Uuid::new_v4(),
				package_name: package.name.clone(),
				ecosystem: package.ecosystem.clone(),
				repo_url: Some(url.clone()),
				days_since_push: gh_metrics.days_since_push,
				releases_last_year: gh_metrics.releases_last_year,
				open_issues: gh_metrics.open_issues,
				stars: gh_metrics.stars,
				forks: gh_metrics.forks,
				contributor_count: gh_metrics.contributor_count,
				reputation_score: 0.5,
				fetched_at: chrono::Utc::now(),
			};
			MaintainerScorer::health_score(&tmp)
		};

		let metrics = MaintainerMetrics {
			id: uuid::Uuid::new_v4(),
			package_name: package.name.clone(),
			ecosystem: package.ecosystem.clone(),
			repo_url: Some(url),
			days_since_push: gh_metrics.days_since_push,
			releases_last_year: gh_metrics.releases_last_year,
			open_issues: gh_metrics.open_issues,
			stars: gh_metrics.stars,
			forks: gh_metrics.forks,
			contributor_count: gh_metrics.contributor_count,
			reputation_score: health,
			fetched_at: chrono::Utc::now(),
		};

		if let Some(pool) = db_pool {
			let _ = upsert_maintainer_metrics(pool, &metrics).await;
		}

		Some(metrics)
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
		let ttl = if self.no_cache { 0 } else { self.config.source_analysis.cache_ttl };

		let cache_dir = self.cache_dir.clone().unwrap_or_else(|| {
			dirs::home_dir()
				.unwrap_or_default()
				.join(".opensentinel")
				.join("cache")
		});

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
