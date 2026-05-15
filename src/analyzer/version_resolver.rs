use std::collections::HashMap;

use semver::Version;
use uuid::Uuid;

use crate::advisory::npm_versions::{NpmVersionMetadata, NpmVersionsClient};
use crate::database::models::VersionDiff;
use super::version_behavior::{VersionBehaviorAnalyzer, VersionSnapshot};

pub struct VersionDiffResolver {
	client: NpmVersionsClient,
}

impl VersionDiffResolver {
	pub fn new() -> Self {
		Self { client: NpmVersionsClient::new() }
	}

	pub async fn resolve_diffs(
		&self,
		package_id: Uuid,
		name: &str,
		current_version: &str,
	) -> Vec<VersionDiff> {
		match self.try_resolve_diffs(package_id, name, current_version).await {
			Ok(diffs) => diffs,
			Err(_) => vec![],
		}
	}

	async fn try_resolve_diffs(
		&self,
		package_id: Uuid,
		name: &str,
		current_version: &str,
	) -> anyhow::Result<Vec<VersionDiff>> {
		let metadata = self.client.fetch_package_metadata(name).await?;

		let previous = Self::find_previous_version(current_version, &metadata.versions);
		let Some(prev_version) = previous else {
			return Ok(vec![]);
		};

		let current_meta = metadata.versions.get(current_version).cloned();
		let prev_meta = metadata.versions.get(&prev_version).cloned();

		let (Some(curr), Some(prev)) = (current_meta, prev_meta) else {
			return Ok(vec![]);
		};

		let from = Self::build_snapshot(&prev_version, &prev);
		let to = Self::build_snapshot(current_version, &curr);

		Ok(VersionBehaviorAnalyzer::analyze(package_id, &from, &to))
	}

	fn find_previous_version(
		current: &str,
		versions: &HashMap<String, NpmVersionMetadata>,
	) -> Option<String> {
		let current_semver = Version::parse(current).ok()?;

		let mut published: Vec<Version> = versions
			.keys()
			.filter_map(|v| Version::parse(v).ok())
			.filter(|v| v < &current_semver && v.pre.is_empty())
			.collect();

		published.sort();
		published.last().map(|v| v.to_string())
	}

	fn build_snapshot(version: &str, meta: &NpmVersionMetadata) -> VersionSnapshot {
		let files = match &meta.dist {
			Some(dist) => dist
				.file_count
				.map(|n| (0..n).map(|i| format!("file_{i}")).collect())
				.unwrap_or_default(),
			None => vec![],
		};

		VersionSnapshot {
			version: version.to_string(),
			files,
			license: meta.license_string(),
			dependencies: meta.all_dependencies(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::advisory::npm_versions::{NpmDist, NpmVersionMetadata};

	fn make_versions(entries: &[(&str, Option<&str>, u32)]) -> HashMap<String, NpmVersionMetadata> {
		entries
			.iter()
			.map(|(v, license, file_count)| {
				(
					v.to_string(),
					NpmVersionMetadata {
						license: license.map(|l| serde_json::Value::String(l.to_string())),
						dependencies: None,
						dev_dependencies: None,
						dist: Some(NpmDist { file_count: Some(*file_count) }),
					},
				)
			})
			.collect()
	}

	#[test]
	fn finds_previous_stable_version() {
		let versions = make_versions(&[
			("1.0.0", Some("MIT"), 10),
			("1.0.1", Some("MIT"), 10),
			("1.1.0", Some("MIT"), 10),
		]);
		let prev = VersionDiffResolver::find_previous_version("1.1.0", &versions);
		assert_eq!(prev, Some("1.0.1".to_string()));
	}

	#[test]
	fn skips_prerelease_versions() {
		let mut versions = make_versions(&[
			("1.0.0", Some("MIT"), 10),
			("1.1.0", Some("MIT"), 10),
		]);
		versions.insert(
			"1.0.1-beta.1".to_string(),
			NpmVersionMetadata {
				license: None,
				dependencies: None,
				dev_dependencies: None,
				dist: None,
			},
		);
		let prev = VersionDiffResolver::find_previous_version("1.1.0", &versions);
		assert_eq!(prev, Some("1.0.0".to_string()));
	}

	#[test]
	fn returns_none_when_no_previous_exists() {
		let versions = make_versions(&[("1.0.0", Some("MIT"), 10)]);
		let prev = VersionDiffResolver::find_previous_version("1.0.0", &versions);
		assert_eq!(prev, None);
	}

	#[test]
	fn returns_none_for_invalid_current_version() {
		let versions = make_versions(&[("1.0.0", Some("MIT"), 10)]);
		let prev = VersionDiffResolver::find_previous_version("not-a-semver", &versions);
		assert_eq!(prev, None);
	}

	#[test]
	fn ignores_versions_higher_than_current() {
		let versions = make_versions(&[
			("1.0.0", Some("MIT"), 10),
			("1.0.1", Some("MIT"), 10),
			("2.0.0", Some("MIT"), 10),
		]);
		let prev = VersionDiffResolver::find_previous_version("1.0.1", &versions);
		assert_eq!(prev, Some("1.0.0".to_string()));
	}

	#[test]
	fn build_snapshot_uses_license_from_metadata() {
		let meta = NpmVersionMetadata {
			license: Some(serde_json::Value::String("Apache-2.0".to_string())),
			dependencies: Some(HashMap::from([("react".to_string(), "18.0.0".to_string())])),
			dev_dependencies: None,
			dist: Some(NpmDist { file_count: Some(5) }),
		};
		let snapshot = VersionDiffResolver::build_snapshot("2.0.0", &meta);
		assert_eq!(snapshot.version, "2.0.0");
		assert_eq!(snapshot.license, Some("Apache-2.0".to_string()));
		assert!(snapshot.dependencies.contains_key("react"));
	}

	#[test]
	fn build_snapshot_file_count_generates_placeholder_files() {
		let meta = NpmVersionMetadata {
			license: None,
			dependencies: None,
			dev_dependencies: None,
			dist: Some(NpmDist { file_count: Some(3) }),
		};
		let snapshot = VersionDiffResolver::build_snapshot("1.0.0", &meta);
		assert_eq!(snapshot.files.len(), 3);
	}

	#[test]
	fn build_snapshot_no_dist_gives_empty_files() {
		let meta = NpmVersionMetadata {
			license: None,
			dependencies: None,
			dev_dependencies: None,
			dist: None,
		};
		let snapshot = VersionDiffResolver::build_snapshot("1.0.0", &meta);
		assert!(snapshot.files.is_empty());
	}
}
