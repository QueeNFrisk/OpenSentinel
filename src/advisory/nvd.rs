use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

use crate::database::models::{AdvisorySource, SeverityLevel};
use super::models::AdvisoryData;

const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub struct NvdClient {
	http: Client,
	api_key: Option<String>,
}

impl NvdClient {
	pub fn new(api_key: Option<String>) -> Self {
		Self { http: Client::new(), api_key }
	}

	pub async fn query(&self, name: &str, _version: &str) -> Result<Vec<AdvisoryData>> {
		let mut request = self.http
			.get(NVD_API_URL)
			.header("User-Agent", "OpenSentinel/0.1.0")
			.query(&[("keywordSearch", name), ("resultsPerPage", "20")]);

		if let Some(key) = &self.api_key {
			request = request.header("apiKey", key);
		}

		let response = request
			.send()
			.await?
			.json::<NvdResponse>()
			.await?;

		let advisories = response
			.vulnerabilities
			.into_iter()
			.filter_map(|wrapper| {
				let cve = wrapper.cve;
				let description = cve.descriptions.iter()
					.find(|d| d.lang == "en")
					.map(|d| d.value.clone())
					.unwrap_or_default();

				if !description.to_lowercase().contains(name) {
					return None;
				}

				Some(AdvisoryData {
					source: AdvisorySource::Nvd,
					external_id: cve.id.clone(),
					title: cve.id.clone(),
					description,
					severity: Self::map_severity(&cve.metrics),
					cvss_score: Self::extract_cvss(&cve.metrics),
					affected_versions: String::new(),
					patched_versions: None,
					published_at: cve.published.parse().ok(),
					references: cve.references.iter().map(|r| r.url.clone()).collect(),
				})
			})
			.collect();

		Ok(advisories)
	}

	fn map_severity(metrics: &NvdMetrics) -> SeverityLevel {
		let base_score = Self::extract_cvss(metrics).unwrap_or(0.0);
		if base_score >= 9.0 { SeverityLevel::Critical }
		else if base_score >= 7.0 { SeverityLevel::High }
		else if base_score >= 4.0 { SeverityLevel::Medium }
		else if base_score > 0.0 { SeverityLevel::Low }
		else { SeverityLevel::Medium }
	}

	fn extract_cvss(metrics: &NvdMetrics) -> Option<f32> {
		metrics.cvss_metric_v31.first()
			.map(|m| m.cvss_data.base_score)
			.or_else(|| metrics.cvss_metric_v30.first().map(|m| m.cvss_data.base_score))
			.or_else(|| metrics.cvss_metric_v2.first().map(|m| m.cvss_data.base_score))
	}
}

#[derive(Deserialize)]
struct NvdResponse {
	#[serde(default)]
	vulnerabilities: Vec<NvdVulnWrapper>,
}

#[derive(Deserialize)]
struct NvdVulnWrapper {
	cve: NvdCve,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
	id: String,
	published: String,
	#[serde(default)]
	descriptions: Vec<NvdDescription>,
	#[serde(default)]
	metrics: NvdMetrics,
	#[serde(default)]
	references: Vec<NvdReference>,
}

#[derive(Deserialize)]
struct NvdDescription {
	lang: String,
	value: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
	#[serde(default)]
	cvss_metric_v31: Vec<NvdCvssMetric>,
	#[serde(default)]
	cvss_metric_v30: Vec<NvdCvssMetric>,
	#[serde(default)]
	cvss_metric_v2: Vec<NvdCvssMetric>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssMetric {
	cvss_data: NvdCvssData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCvssData {
	base_score: f32,
}

#[derive(Deserialize)]
struct NvdReference {
	url: String,
}
