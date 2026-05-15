use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use super::models::{DependencyEdge, DependencyTree, ParsedPackage};

const PACKAGE_JSON: &str = "package.json";
const PACKAGE_LOCK_V3: &str = "package-lock.json";
const YARN_LOCK: &str = "yarn.lock";
const PNPM_LOCK: &str = "pnpm-lock.yaml";

pub struct NodejsParser;

impl NodejsParser {
	pub async fn detect_and_parse(project_path: &Path) -> Result<Option<DependencyTree>> {
		let package_json_path = project_path.join(PACKAGE_JSON);

		if !package_json_path.exists() {
			return Ok(None);
		}

		let lock_format = Self::detect_lock_format(project_path);
		let manifest = Self::parse_manifest(&package_json_path)?;

		let tree = match lock_format {
			LockFormat::NpmV3 => {
				let lock_path = project_path.join(PACKAGE_LOCK_V3);
				Self::parse_npm_lock(&manifest, &lock_path)?
			}
			LockFormat::Yarn => {
				let lock_path = project_path.join(YARN_LOCK);
				Self::parse_yarn_lock(&manifest, &lock_path)?
			}
			LockFormat::Pnpm => {
				let lock_path = project_path.join(PNPM_LOCK);
				Self::parse_pnpm_lock(&manifest, &lock_path)?
			}
			LockFormat::None => Self::parse_manifest_only(&manifest)?,
		};

		Ok(Some(tree))
	}

	fn detect_lock_format(project_path: &Path) -> LockFormat {
		if project_path.join(PACKAGE_LOCK_V3).exists() {
			LockFormat::NpmV3
		} else if project_path.join(YARN_LOCK).exists() {
			LockFormat::Yarn
		} else if project_path.join(PNPM_LOCK).exists() {
			LockFormat::Pnpm
		} else {
			LockFormat::None
		}
	}

	fn parse_manifest(path: &Path) -> Result<PackageJsonManifest> {
		let content = std::fs::read_to_string(path)
			.with_context(|| format!("failed to read {}", path.display()))?;
		serde_json::from_str(&content)
			.with_context(|| format!("failed to parse {}", path.display()))
	}

	fn parse_npm_lock(manifest: &PackageJsonManifest, lock_path: &Path) -> Result<DependencyTree> {
		let content = std::fs::read_to_string(lock_path)
			.with_context(|| format!("failed to read {}", lock_path.display()))?;

		let lock: NpmLockV3 = serde_json::from_str(&content)
			.with_context(|| format!("failed to parse {}", lock_path.display()))?;

		let mut tree = DependencyTree::new(
			manifest.name.as_deref().unwrap_or("unknown"),
			"nodejs",
		);

		let direct_names: std::collections::HashSet<&str> = manifest
			.dependencies
			.keys()
			.chain(manifest.dev_dependencies.keys())
			.chain(manifest.optional_dependencies.keys())
			.map(String::as_str)
			.collect();

		for (pkg_key, pkg_data) in &lock.packages {
			if pkg_key.is_empty() {
				continue;
			}

			let name = pkg_data
				.name
				.clone()
				.unwrap_or_else(|| Self::extract_name_from_key(pkg_key));

			let package = ParsedPackage {
				name: name.clone(),
				version: pkg_data.version.clone().unwrap_or_default(),
				ecosystem: "nodejs".to_string(),
				registry_url: pkg_data.resolved.clone(),
				checksum: pkg_data.integrity.clone(),
				is_direct: direct_names.contains(name.as_str()),
				depth: Self::calculate_depth(pkg_key),
				dependencies: pkg_data.dependencies.keys().cloned().collect(),
				dev_dependencies: Vec::new(),
				install_scripts: Self::extract_install_scripts(&pkg_data.scripts),
			};

			tree.add_package(pkg_key.clone(), package);

			for (dep_name, dep_version) in &pkg_data.dependencies {
				tree.add_edge(DependencyEdge {
					parent: pkg_key.clone(),
					child: dep_name.clone(),
					version_constraint: dep_version.clone(),
					is_dev: false,
					is_optional: false,
				});
			}
		}

		Ok(tree)
	}

	fn parse_yarn_lock(manifest: &PackageJsonManifest, _lock_path: &Path) -> Result<DependencyTree> {
		Ok(Self::parse_manifest_only(manifest)?)
	}

	fn parse_pnpm_lock(manifest: &PackageJsonManifest, _lock_path: &Path) -> Result<DependencyTree> {
		Ok(Self::parse_manifest_only(manifest)?)
	}

	fn parse_manifest_only(manifest: &PackageJsonManifest) -> Result<DependencyTree> {
		let mut tree = DependencyTree::new(
			manifest.name.as_deref().unwrap_or("unknown"),
			"nodejs",
		);

		for (name, version) in &manifest.dependencies {
			let package = ParsedPackage {
				name: name.clone(),
				version: version.trim_start_matches('^').trim_start_matches('~').to_string(),
				ecosystem: "nodejs".to_string(),
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

	fn extract_name_from_key(key: &str) -> String {
		let stripped = key.trim_start_matches("node_modules/");
		stripped.split('/').last().unwrap_or(stripped).to_string()
	}

	fn calculate_depth(key: &str) -> u32 {
		key.matches("node_modules/").count() as u32
	}

	fn extract_install_scripts(scripts: &HashMap<String, String>) -> Vec<String> {
		["preinstall", "install", "postinstall"]
			.iter()
			.filter_map(|&key| scripts.get(key).cloned())
			.collect()
	}
}

#[derive(Debug, Deserialize)]
struct PackageJsonManifest {
	name: Option<String>,
	#[serde(default)]
	dependencies: HashMap<String, String>,
	#[serde(rename = "devDependencies", default)]
	dev_dependencies: HashMap<String, String>,
	#[serde(rename = "optionalDependencies", default)]
	optional_dependencies: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct NpmLockV3 {
	#[serde(default)]
	packages: HashMap<String, NpmLockPackage>,
}

#[derive(Debug, Deserialize)]
struct NpmLockPackage {
	name: Option<String>,
	version: Option<String>,
	resolved: Option<String>,
	integrity: Option<String>,
	#[serde(default)]
	dependencies: HashMap<String, String>,
	#[serde(default)]
	scripts: HashMap<String, String>,
}

enum LockFormat {
	NpmV3,
	Yarn,
	Pnpm,
	None,
}
