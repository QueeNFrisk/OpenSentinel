use std::collections::HashMap;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NpmPackageMetadata {
	pub versions: HashMap<String, NpmVersionMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NpmVersionMetadata {
	pub license: Option<serde_json::Value>,
	pub dependencies: Option<HashMap<String, String>>,
	#[serde(rename = "devDependencies")]
	pub dev_dependencies: Option<HashMap<String, String>>,
	pub dist: Option<NpmDist>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NpmDist {
	#[serde(rename = "fileCount")]
	pub file_count: Option<u32>,
}

impl NpmVersionMetadata {
	pub fn license_string(&self) -> Option<String> {
		self.license.as_ref().map(|l| match l {
			serde_json::Value::String(s) => s.clone(),
			serde_json::Value::Object(obj) => obj
				.get("type")
				.and_then(|t| t.as_str())
				.unwrap_or("unknown")
				.to_string(),
			_ => "unknown".to_string(),
		})
	}

	pub fn all_dependencies(&self) -> HashMap<String, String> {
		let mut deps = self.dependencies.clone().unwrap_or_default();
		deps.extend(self.dev_dependencies.clone().unwrap_or_default());
		deps
	}
}

pub struct NpmVersionsClient {
	client: Client,
}

impl NpmVersionsClient {
	pub fn new() -> Self {
		Self {
			client: Client::builder()
				.user_agent("opensentinel/0.1.0")
				.timeout(std::time::Duration::from_secs(10))
				.build()
				.expect("failed to build HTTP client"),
		}
	}

	pub async fn fetch_package_metadata(&self, name: &str) -> Result<NpmPackageMetadata> {
		let url = if name.starts_with('@') {
			let encoded = name.replace('/', "%2F");
			format!("https://registry.npmjs.org/{encoded}")
		} else {
			format!("https://registry.npmjs.org/{name}")
		};

		let metadata = self
			.client
			.get(&url)
			.send()
			.await
			.with_context(|| format!("failed to reach npm registry for {name}"))?
			.json::<NpmPackageMetadata>()
			.await
			.with_context(|| format!("failed to parse npm metadata for {name}"))?;

		Ok(metadata)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn license_string_from_plain_string() {
		let meta = NpmVersionMetadata {
			license: Some(serde_json::Value::String("MIT".to_string())),
			dependencies: None,
			dev_dependencies: None,
			dist: None,
		};
		assert_eq!(meta.license_string(), Some("MIT".to_string()));
	}

	#[test]
	fn license_string_from_object() {
		let obj = serde_json::json!({ "type": "Apache-2.0", "url": "https://example.com" });
		let meta = NpmVersionMetadata {
			license: Some(obj),
			dependencies: None,
			dev_dependencies: None,
			dist: None,
		};
		assert_eq!(meta.license_string(), Some("Apache-2.0".to_string()));
	}

	#[test]
	fn license_string_absent() {
		let meta = NpmVersionMetadata {
			license: None,
			dependencies: None,
			dev_dependencies: None,
			dist: None,
		};
		assert_eq!(meta.license_string(), None);
	}

	#[test]
	fn all_dependencies_merges_prod_and_dev() {
		let meta = NpmVersionMetadata {
			license: None,
			dependencies: Some(HashMap::from([
				("lodash".to_string(), "4.17.21".to_string()),
			])),
			dev_dependencies: Some(HashMap::from([
				("jest".to_string(), "29.0.0".to_string()),
			])),
			dist: None,
		};
		let all = meta.all_dependencies();
		assert_eq!(all.len(), 2);
		assert!(all.contains_key("lodash"));
		assert!(all.contains_key("jest"));
	}

	#[test]
	fn all_dependencies_empty_when_none() {
		let meta = NpmVersionMetadata {
			license: None,
			dependencies: None,
			dev_dependencies: None,
			dist: None,
		};
		assert!(meta.all_dependencies().is_empty());
	}
}
