use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::database::models::{AdvisorySource, SeverityLevel};
use super::models::AdvisoryData;

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

pub struct OsvClient {
	http: Client,
	query_url: String,
}

impl OsvClient {
	pub fn new() -> Self {
		Self {
			http: Client::new(),
			query_url: OSV_API_URL.to_string(),
		}
	}

	#[doc(hidden)]
	#[allow(dead_code)]
	pub fn with_base_url(base_url: &str) -> Self {
		Self {
			http: Client::new(),
			query_url: format!("{base_url}/v1/query"),
		}
	}

	pub async fn query(&self, name: &str, version: &str, ecosystem: &str) -> Result<Vec<AdvisoryData>> {
		let ecosystem_mapped = Self::map_ecosystem(ecosystem);

		let body = OsvQueryRequest {
			version: version.to_string(),
			package: OsvPackage {
				name: name.to_string(),
				ecosystem: ecosystem_mapped.to_string(),
			},
		};

		let response = self.http
			.post(&self.query_url)
			.json(&body)
			.send()
			.await?
			.json::<OsvQueryResponse>()
			.await?;

		let advisories = response
			.vulns
			.into_iter()
			.map(|v| AdvisoryData {
				source: AdvisorySource::Osv,
				external_id: v.id.clone(),
				title: v.summary.clone().unwrap_or_else(|| v.id.clone()),
				description: v.details.clone().unwrap_or_default(),
				severity: Self::map_severity(&v.severity),
				cvss_score: Self::extract_cvss(&v.severity),
				affected_versions: Self::extract_affected_versions(&v.affected),
				patched_versions: None,
				published_at: v.published.parse().ok(),
				references: v.references.iter().map(|r| r.url.clone()).collect(),
			})
			.collect();

		Ok(advisories)
	}

	fn map_ecosystem(ecosystem: &str) -> &str {
		match ecosystem {
			"nodejs" | "bun" => "npm",
			other => other,
		}
	}

	fn map_severity(severities: &[OsvSeverity]) -> SeverityLevel {
		severities.first()
			.map(|s| match s.score.as_deref() {
				Some(score) => {
					let val: f32 = score.parse().unwrap_or(0.0);
					if val >= 9.0 { SeverityLevel::Critical }
					else if val >= 7.0 { SeverityLevel::High }
					else if val >= 4.0 { SeverityLevel::Medium }
					else { SeverityLevel::Low }
				}
				None => SeverityLevel::Medium,
			})
			.unwrap_or(SeverityLevel::Medium)
	}

	fn extract_cvss(severities: &[OsvSeverity]) -> Option<f32> {
		severities.first()
			.and_then(|s| s.score.as_deref())
			.and_then(|s| s.parse().ok())
	}

	fn extract_affected_versions(affected: &[OsvAffected]) -> String {
		affected.iter()
			.flat_map(|a| a.ranges.iter())
			.flat_map(|r| r.events.iter())
			.filter_map(|e| e.introduced.as_deref())
			.collect::<Vec<_>>()
			.join(", ")
	}
}

#[derive(Serialize)]
struct OsvQueryRequest {
	version: String,
	package: OsvPackage,
}

#[derive(Serialize)]
struct OsvPackage {
	name: String,
	ecosystem: String,
}

#[derive(Deserialize)]
struct OsvQueryResponse {
	#[serde(default)]
	vulns: Vec<OsvVulnerability>,
}

#[derive(Deserialize)]
struct OsvVulnerability {
	id: String,
	summary: Option<String>,
	details: Option<String>,
	published: String,
	#[serde(default)]
	severity: Vec<OsvSeverity>,
	#[serde(default)]
	affected: Vec<OsvAffected>,
	#[serde(default)]
	references: Vec<OsvReference>,
}

#[derive(Deserialize)]
struct OsvSeverity {
	score: Option<String>,
}

#[derive(Deserialize)]
struct OsvAffected {
	#[serde(default)]
	ranges: Vec<OsvRange>,
}

#[derive(Deserialize)]
struct OsvRange {
	#[serde(default)]
	events: Vec<OsvEvent>,
}

#[derive(Deserialize)]
struct OsvEvent {
	introduced: Option<String>,
}

#[derive(Deserialize)]
struct OsvReference {
	url: String,
}
