use std::collections::{HashMap, HashSet};

use chrono::Utc;
use uuid::Uuid;

use crate::database::models::{SeverityLevel, VersionChangeType, VersionDiff};

#[derive(Debug, Clone)]
pub struct VersionSnapshot {
	pub version: String,
	pub files: Vec<String>,
	pub license: Option<String>,
	pub dependencies: HashMap<String, String>,
}

pub struct VersionBehaviorAnalyzer;

impl VersionBehaviorAnalyzer {
	pub fn analyze(
		package_id: Uuid,
		from: &VersionSnapshot,
		to: &VersionSnapshot,
	) -> Vec<VersionDiff> {
		let mut diffs = Vec::new();

		diffs.extend(Self::detect_removed_files(package_id, from, to));
		diffs.extend(Self::detect_license_change(package_id, from, to));
		diffs.extend(Self::detect_dependency_changes(package_id, from, to));

		diffs
	}

	fn detect_removed_files(
		package_id: Uuid,
		from: &VersionSnapshot,
		to: &VersionSnapshot,
	) -> Vec<VersionDiff> {
		let from_set: HashSet<&String> = from.files.iter().collect();
		let to_set: HashSet<&String> = to.files.iter().collect();

		let removed: Vec<&String> = from_set.difference(&to_set).copied().collect();
		if removed.is_empty() {
			return vec![];
		}

		let mut sorted = removed.clone();
		sorted.sort();

		vec![VersionDiff {
			id: Uuid::new_v4(),
			package_id,
			from_version: from.version.clone(),
			to_version: to.version.clone(),
			change_type: VersionChangeType::FilesRemoved,
			description: format!(
				"Files removed between {} and {}: {}",
				from.version,
				to.version,
				sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
			),
			severity: SeverityLevel::Medium,
			detected_at: Utc::now(),
		}]
	}

	fn detect_license_change(
		package_id: Uuid,
		from: &VersionSnapshot,
		to: &VersionSnapshot,
	) -> Vec<VersionDiff> {
		match (&from.license, &to.license) {
			(Some(f), Some(t)) if f != t => vec![VersionDiff {
				id: Uuid::new_v4(),
				package_id,
				from_version: from.version.clone(),
				to_version: to.version.clone(),
				change_type: VersionChangeType::LicenseChanged,
				description: format!(
					"License changed from {} to {} between versions {} and {}",
					f, t, from.version, to.version
				),
				severity: SeverityLevel::Low,
				detected_at: Utc::now(),
			}],
			_ => vec![],
		}
	}

	fn detect_dependency_changes(
		package_id: Uuid,
		from: &VersionSnapshot,
		to: &VersionSnapshot,
	) -> Vec<VersionDiff> {
		let from_keys: HashSet<&String> = from.dependencies.keys().collect();
		let to_keys: HashSet<&String> = to.dependencies.keys().collect();

		let mut added: Vec<&String> = to_keys.difference(&from_keys).copied().collect();
		let mut removed: Vec<&String> = from_keys.difference(&to_keys).copied().collect();

		added.sort();
		removed.sort();

		if added.is_empty() && removed.is_empty() {
			return vec![];
		}

		let mut parts = Vec::new();
		if !added.is_empty() {
			parts.push(format!(
				"added: {}",
				added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
			));
		}
		if !removed.is_empty() {
			parts.push(format!(
				"removed: {}",
				removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
			));
		}

		vec![VersionDiff {
			id: Uuid::new_v4(),
			package_id,
			from_version: from.version.clone(),
			to_version: to.version.clone(),
			change_type: VersionChangeType::DependenciesChanged,
			description: format!(
				"Dependencies changed between {} and {}: {}",
				from.version,
				to.version,
				parts.join("; ")
			),
			severity: SeverityLevel::Medium,
			detected_at: Utc::now(),
		}]
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pkg_id() -> Uuid {
		Uuid::new_v4()
	}

	fn snapshot(version: &str, files: &[&str]) -> VersionSnapshot {
		VersionSnapshot {
			version: version.to_string(),
			files: files.iter().map(|s| s.to_string()).collect(),
			license: None,
			dependencies: HashMap::new(),
		}
	}

	fn snapshot_with_license(version: &str, license: &str) -> VersionSnapshot {
		VersionSnapshot {
			version: version.to_string(),
			files: vec![],
			license: Some(license.to_string()),
			dependencies: HashMap::new(),
		}
	}

	fn snapshot_with_deps(version: &str, deps: &[(&str, &str)]) -> VersionSnapshot {
		VersionSnapshot {
			version: version.to_string(),
			files: vec![],
			license: None,
			dependencies: deps
				.iter()
				.map(|(k, v)| (k.to_string(), v.to_string()))
				.collect(),
		}
	}

	#[test]
	fn no_diffs_when_versions_identical() {
		let v1 = snapshot("1.0.0", &["index.js", "package.json"]);
		let v2 = snapshot("1.0.1", &["index.js", "package.json"]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert!(diffs.is_empty());
	}

	#[test]
	fn detects_removed_files() {
		let v1 = snapshot("1.0.0", &["index.js", "package.json", "README.md"]);
		let v2 = snapshot("1.0.1", &["index.js", "package.json"]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert_eq!(diffs.len(), 1);
		assert_eq!(diffs[0].change_type, VersionChangeType::FilesRemoved);
		assert!(diffs[0].description.contains("README.md"));
	}

	#[test]
	fn removed_files_have_medium_severity() {
		let v1 = snapshot("1.0.0", &["index.js", "secret.key"]);
		let v2 = snapshot("1.0.1", &["index.js"]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert_eq!(diffs[0].severity, SeverityLevel::Medium);
	}

	#[test]
	fn added_files_do_not_trigger_diff() {
		let v1 = snapshot("1.0.0", &["index.js"]);
		let v2 = snapshot("1.0.1", &["index.js", "newfile.js"]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert!(diffs.is_empty());
	}

	#[test]
	fn detects_license_change() {
		let v1 = snapshot_with_license("1.0.0", "MIT");
		let v2 = snapshot_with_license("1.0.1", "GPL-3.0");
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert_eq!(diffs.len(), 1);
		assert_eq!(diffs[0].change_type, VersionChangeType::LicenseChanged);
		assert!(diffs[0].description.contains("MIT"));
		assert!(diffs[0].description.contains("GPL-3.0"));
	}

	#[test]
	fn license_change_has_low_severity() {
		let v1 = snapshot_with_license("1.0.0", "MIT");
		let v2 = snapshot_with_license("1.0.1", "Apache-2.0");
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert_eq!(diffs[0].severity, SeverityLevel::Low);
	}

	#[test]
	fn no_diff_when_license_unchanged() {
		let v1 = snapshot_with_license("1.0.0", "MIT");
		let v2 = snapshot_with_license("1.0.1", "MIT");
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert!(diffs.is_empty());
	}

	#[test]
	fn no_diff_when_both_licenses_absent() {
		let v1 = snapshot("1.0.0", &[]);
		let v2 = snapshot("1.0.1", &[]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert!(diffs.is_empty());
	}

	#[test]
	fn detects_new_dependency_added() {
		let v1 = snapshot_with_deps("1.0.0", &[("lodash", "4.17.20")]);
		let v2 = snapshot_with_deps("1.0.1", &[("lodash", "4.17.20"), ("malware", "1.0.0")]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert_eq!(diffs.len(), 1);
		assert_eq!(diffs[0].change_type, VersionChangeType::DependenciesChanged);
		assert!(diffs[0].description.contains("malware"));
	}

	#[test]
	fn detects_dependency_removed() {
		let v1 = snapshot_with_deps("1.0.0", &[("lodash", "4.17.20"), ("axios", "1.0.0")]);
		let v2 = snapshot_with_deps("1.0.1", &[("lodash", "4.17.20")]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert_eq!(diffs.len(), 1);
		assert_eq!(diffs[0].change_type, VersionChangeType::DependenciesChanged);
		assert!(diffs[0].description.contains("removed: axios"));
	}

	#[test]
	fn no_diff_when_dependencies_unchanged() {
		let v1 = snapshot_with_deps("1.0.0", &[("lodash", "4.17.20")]);
		let v2 = snapshot_with_deps("1.0.1", &[("lodash", "4.17.20")]);
		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert!(diffs.is_empty());
	}

	#[test]
	fn multiple_change_types_detected_independently() {
		let v1 = VersionSnapshot {
			version: "1.0.0".to_string(),
			files: vec!["index.js".to_string(), "README.md".to_string()],
			license: Some("MIT".to_string()),
			dependencies: HashMap::from([("lodash".to_string(), "4.17.20".to_string())]),
		};
		let v2 = VersionSnapshot {
			version: "1.0.1".to_string(),
			files: vec!["index.js".to_string()],
			license: Some("GPL-3.0".to_string()),
			dependencies: HashMap::from([
				("lodash".to_string(), "4.17.20".to_string()),
				("spyware".to_string(), "1.0.0".to_string()),
			]),
		};

		let diffs = VersionBehaviorAnalyzer::analyze(pkg_id(), &v1, &v2);
		assert_eq!(diffs.len(), 3);

		let types: Vec<&VersionChangeType> = diffs.iter().map(|d| &d.change_type).collect();
		assert!(types.contains(&&VersionChangeType::FilesRemoved));
		assert!(types.contains(&&VersionChangeType::LicenseChanged));
		assert!(types.contains(&&VersionChangeType::DependenciesChanged));
	}

	#[test]
	fn diff_versions_are_recorded_correctly() {
		let v1 = snapshot("2.3.1", &["index.js", "lib.js"]);
		let v2 = snapshot("2.4.0", &["index.js"]);
		let id = pkg_id();
		let diffs = VersionBehaviorAnalyzer::analyze(id, &v1, &v2);
		assert_eq!(diffs[0].from_version, "2.3.1");
		assert_eq!(diffs[0].to_version, "2.4.0");
		assert_eq!(diffs[0].package_id, id);
	}
}
