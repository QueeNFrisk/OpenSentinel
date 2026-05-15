use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

use crate::database::models::{AdvisorySource, SeverityLevel};
use super::models::AdvisoryData;

const GITHUB_GRAPHQL_URL: &str = "https://api.github.com/graphql";

pub struct GitHubAdvisoryClient {
	http: Client,
	token: Option<String>,
}

impl GitHubAdvisoryClient {
	pub fn new(token: Option<String>) -> Self {
		Self { http: Client::new(), token }
	}

	pub async fn query(&self, name: &str, _version: &str) -> Result<Vec<AdvisoryData>> {
		let token = match &self.token {
			Some(t) => t.clone(),
			None => {
				tracing::debug!("no GitHub token configured, skipping GitHub advisories");
				return Ok(Vec::new());
			}
		};

		let query = format!(
			r#"{{ "query": "{{ securityVulnerabilities(ecosystem: NPM, package: \"{name}\", first: 10) {{ nodes {{ advisory {{ ghsaId summary description publishedAt severity }} vulnerableVersionRange patchedVersions }} }} }}" }}"#
		);

		let response = self.http
			.post(GITHUB_GRAPHQL_URL)
			.header("Authorization", format!("Bearer {token}"))
			.header("User-Agent", "OpenSentinel/0.1.0")
			.header("Content-Type", "application/json")
			.body(query)
			.send()
			.await?
			.json::<GithubResponse>()
			.await?;

		let advisories = response
			.data
			.security_vulnerabilities
			.nodes
			.into_iter()
			.map(|node| AdvisoryData {
				source: AdvisorySource::Github,
				external_id: node.advisory.ghsa_id.clone(),
				title: node.advisory.summary.clone().unwrap_or_else(|| node.advisory.ghsa_id.clone()),
				description: node.advisory.description.clone().unwrap_or_default(),
				severity: Self::map_severity(&node.advisory.severity),
				cvss_score: None,
				affected_versions: node.vulnerable_version_range.unwrap_or_default(),
				patched_versions: node.patched_versions,
				published_at: node.advisory.published_at.and_then(|d| d.parse().ok()),
				references: Vec::new(),
			})
			.collect();

		Ok(advisories)
	}

	fn map_severity(severity: &Option<String>) -> SeverityLevel {
		match severity.as_deref() {
			Some("CRITICAL") => SeverityLevel::Critical,
			Some("HIGH") => SeverityLevel::High,
			Some("MODERATE") => SeverityLevel::Medium,
			Some("LOW") => SeverityLevel::Low,
			_ => SeverityLevel::Medium,
		}
	}
}

#[derive(Deserialize)]
struct GithubResponse {
	data: GithubData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubData {
	security_vulnerabilities: GithubVulnConnection,
}

#[derive(Deserialize)]
struct GithubVulnConnection {
	nodes: Vec<GithubVulnNode>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubVulnNode {
	advisory: GithubAdvisory,
	vulnerable_version_range: Option<String>,
	patched_versions: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubAdvisory {
	ghsa_id: String,
	summary: Option<String>,
	description: Option<String>,
	published_at: Option<String>,
	severity: Option<String>,
}
