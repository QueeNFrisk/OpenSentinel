#![allow(dead_code)]
use anyhow::Result;
use futures::future::join_all;

use crate::config::{ParallelismConfig, ResolvedCredentials};
use crate::parser::models::ParsedPackage;
use super::models::AdvisoryData;
use super::{github::GitHubAdvisoryClient, nvd::NvdClient, osv::OsvClient};

pub struct AdvisoryFetcher {
	osv: OsvClient,
	github: GitHubAdvisoryClient,
	nvd: NvdClient,
	parallelism: ParallelismConfig,
}

impl AdvisoryFetcher {
	pub fn new(credentials: &ResolvedCredentials, parallelism: ParallelismConfig) -> Self {
		Self {
			osv: OsvClient::new(),
			github: GitHubAdvisoryClient::new(credentials.github_token.clone()),
			nvd: NvdClient::new(credentials.nvd_api_key.clone()),
			parallelism,
		}
	}

	pub async fn fetch_for_package(&self, package: &ParsedPackage) -> Result<Vec<AdvisoryData>> {
		let osv_fut = self.osv.query(&package.name, &package.version, &package.ecosystem);
		let github_fut = self.github.query(&package.name, &package.version);
		let nvd_fut = self.nvd.query(&package.name, &package.version);

		let results = join_all(vec![
			Box::pin(async { osv_fut.await }) as std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<AdvisoryData>>> + Send>>,
			Box::pin(async { github_fut.await }),
			Box::pin(async { nvd_fut.await }),
		])
		.await;

		let mut all_advisories = Vec::new();
		for result in results {
			match result {
				Ok(advisories) => all_advisories.extend(advisories),
				Err(e) => tracing::warn!("advisory fetch error: {e}"),
			}
		}

		Ok(all_advisories)
	}

	pub async fn fetch_batch(&self, packages: &[ParsedPackage]) -> Result<Vec<(String, Vec<AdvisoryData>)>> {
		use futures::stream::{self, StreamExt};

		let concurrency = self.parallelism.api_concurrency;

		let results = stream::iter(packages)
			.map(|pkg| async move {
				let advisories = self.fetch_for_package(pkg).await?;
				Ok::<_, anyhow::Error>((pkg.name.clone(), advisories))
			})
			.buffer_unordered(concurrency)
			.collect::<Vec<_>>()
			.await;

		results.into_iter().collect()
	}
}
