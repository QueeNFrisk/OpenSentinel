use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use super::models::{DependencyTree, ParsedPackage};

const BUN_LOCK: &str = "bun.lockb";
const BUN_LOCK_TEXT: &str = "bun.lock";
const PACKAGE_JSON: &str = "package.json";
const BUNFIG: &str = "bunfig.toml";

pub struct BunParser;

impl BunParser {
	pub async fn detect_and_parse(project_path: &Path) -> Result<Option<DependencyTree>> {
		let has_bun_lock = project_path.join(BUN_LOCK).exists()
			|| project_path.join(BUN_LOCK_TEXT).exists();

		let has_bunfig = project_path.join(BUNFIG).exists();

		if !has_bun_lock && !has_bunfig {
			return Ok(None);
		}

		let manifest_path = project_path.join(PACKAGE_JSON);
		let manifest = Self::parse_manifest(&manifest_path)?;

		let tree = if project_path.join(BUN_LOCK_TEXT).exists() {
			let lock_path = project_path.join(BUN_LOCK_TEXT);
			Self::parse_text_lock(&manifest, &lock_path)?
		} else {
			Self::parse_manifest_only(&manifest)?
		};

		Ok(Some(tree))
	}

	fn parse_manifest(path: &Path) -> Result<BunManifest> {
		let content = std::fs::read_to_string(path)
			.with_context(|| format!("failed to read {}", path.display()))?;
		serde_json::from_str(&content)
			.with_context(|| format!("failed to parse {}", path.display()))
	}

	fn parse_text_lock(manifest: &BunManifest, lock_path: &Path) -> Result<DependencyTree> {
		let content = std::fs::read_to_string(lock_path)
			.with_context(|| format!("failed to read {}", lock_path.display()))?;

		let mut tree = DependencyTree::new(
			manifest.name.as_deref().unwrap_or("unknown"),
			"bun",
		);

		let direct_names: std::collections::HashSet<&str> = manifest
			.dependencies
			.keys()
			.chain(manifest.dev_dependencies.keys())
			.map(String::as_str)
			.collect();

		for line in content.lines() {
			let trimmed = line.trim();

			if trimmed.starts_with('"') && trimmed.contains('@') {
				if let Some((name, version)) = Self::parse_lock_line(trimmed) {
					let package = ParsedPackage {
						name: name.clone(),
						version,
						ecosystem: "bun".to_string(),
						registry_url: None,
						checksum: None,
						is_direct: direct_names.contains(name.as_str()),
						depth: 1,
						dependencies: Vec::new(),
						dev_dependencies: Vec::new(),
						install_scripts: Vec::new(),
					};
					tree.add_package(name, package);
				}
			}
		}

		Ok(tree)
	}

	fn parse_manifest_only(manifest: &BunManifest) -> Result<DependencyTree> {
		let mut tree = DependencyTree::new(
			manifest.name.as_deref().unwrap_or("unknown"),
			"bun",
		);

		for (name, version) in manifest.dependencies.iter().chain(manifest.dev_dependencies.iter()) {
			let package = ParsedPackage {
				name: name.clone(),
				version: version.trim_start_matches('^').trim_start_matches('~').to_string(),
				ecosystem: "bun".to_string(),
				registry_url: None,
				checksum: None,
				is_direct: true,
				depth: 1,
				dependencies: Vec::new(),
				dev_dependencies: Vec::new(),
				install_scripts: Vec::new(),
			};
			tree.add_package(name.clone(), package);
		}

		Ok(tree)
	}

	fn parse_lock_line(line: &str) -> Option<(String, String)> {
		let inner = line.trim_end_matches(':').trim_matches('"');

		if let Some(at_pos) = inner.rfind('@') {
			if at_pos > 0 {
				let name = inner[..at_pos].to_string();
				let version = inner[at_pos + 1..].to_string();
				return Some((name, version));
			}
		}

		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_lock_line_standard_package() {
		let result = BunParser::parse_lock_line(r#""lodash@4.17.21":"#);
		assert!(result.is_some());
		let (name, version) = result.unwrap();
		assert_eq!(name, "lodash");
		assert_eq!(version, "4.17.21");
	}

	#[test]
	fn parse_lock_line_scoped_package() {
		let result = BunParser::parse_lock_line(r#""@babel/core@7.24.0":"#);
		assert!(result.is_some());
		let (name, version) = result.unwrap();
		assert_eq!(name, "@babel/core");
		assert_eq!(version, "7.24.0");
	}

	#[test]
	fn parse_lock_line_no_at_sign_returns_none() {
		let result = BunParser::parse_lock_line(r#""nodeps":"#);
		assert!(result.is_none());
	}

	#[test]
	fn parse_manifest_only_strips_semver_prefixes() {
		let manifest = BunManifest {
			name: Some("test-app".to_string()),
			dependencies: [
				("lodash".to_string(), "^4.17.21".to_string()),
				("express".to_string(), "~4.18.0".to_string()),
			]
			.into_iter()
			.collect(),
			dev_dependencies: Default::default(),
		};

		let tree = BunParser::parse_manifest_only(&manifest).unwrap();
		let lodash = tree.packages.get("lodash").unwrap();
		let express = tree.packages.get("express").unwrap();

		assert_eq!(lodash.version, "4.17.21");
		assert_eq!(express.version, "4.18.0");
		assert!(lodash.is_direct);
	}

	#[test]
	fn parse_manifest_only_marks_all_as_direct() {
		let manifest = BunManifest {
			name: Some("app".to_string()),
			dependencies: [("react".to_string(), "18.0.0".to_string())]
				.into_iter()
				.collect(),
			dev_dependencies: Default::default(),
		};
		let tree = BunParser::parse_manifest_only(&manifest).unwrap();
		assert!(tree.packages.values().all(|p| p.is_direct));
	}
}

#[derive(Debug, Deserialize)]
struct BunManifest {
	name: Option<String>,
	#[serde(default)]
	dependencies: HashMap<String, String>,
	#[serde(rename = "devDependencies", default)]
	dev_dependencies: HashMap<String, String>,
}
