use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

use super::models::{DependencyTree, ParsedPackage};

const CARGO_TOML: &str = "Cargo.toml";
const CARGO_LOCK: &str = "Cargo.lock";

pub struct RustCargoParser;

impl RustCargoParser {
	pub async fn detect_and_parse(project_path: &Path) -> Result<Option<DependencyTree>> {
		let toml_path = project_path.join(CARGO_TOML);
		if !toml_path.exists() {
			return Ok(None);
		}

		let lock_path = project_path.join(CARGO_LOCK);
		let tree = if lock_path.exists() {
			let directs = parse_cargo_toml_directs(&toml_path)?;
			parse_cargo_lock(&directs, &toml_path, &lock_path)?
		} else {
			parse_cargo_toml_only(&toml_path)?
		};

		Ok(Some(tree))
	}
}

fn make_package(
	name: &str,
	version: &str,
	is_direct: bool,
	depth: u32,
	checksum: Option<String>,
) -> ParsedPackage {
	let reg = format!("https://crates.io/crates/{name}/{version}");
	ParsedPackage {
		name: name.to_string(),
		version: version.to_string(),
		ecosystem: "crates.io".to_string(),
		registry_url: Some(reg),
		checksum,
		is_direct,
		depth,
		dependencies: vec![],
		dev_dependencies: vec![],
		install_scripts: vec![],
	}
}

fn parse_cargo_toml_directs(path: &Path) -> Result<HashMap<String, bool>> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let doc: toml::Value = toml::from_str(&content)
		.with_context(|| format!("failed to parse {}", path.display()))?;

	let mut directs: HashMap<String, bool> = HashMap::new();

	if let Some(deps) = doc.get("dependencies").and_then(|d| d.as_table()) {
		for name in deps.keys() {
			directs.insert(name.clone(), false);
		}
	}

	if let Some(dev_deps) = doc.get("dev-dependencies").and_then(|d| d.as_table()) {
		for name in dev_deps.keys() {
			directs.insert(name.clone(), true);
		}
	}

	if let Some(build_deps) = doc.get("build-dependencies").and_then(|d| d.as_table()) {
		for name in build_deps.keys() {
			directs.entry(name.clone()).or_insert(false);
		}
	}

	Ok(directs)
}

fn parse_cargo_toml_only(path: &Path) -> Result<DependencyTree> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let doc: toml::Value = toml::from_str(&content)
		.with_context(|| format!("failed to parse {}", path.display()))?;

	let package_name = doc
		.get("package")
		.and_then(|p| p.get("name"))
		.and_then(|n| n.as_str())
		.unwrap_or("unknown");

	let mut tree = DependencyTree::new(package_name, "crates.io");

	let sections = [
		("dependencies", false),
		("dev-dependencies", true),
		("build-dependencies", false),
	];

	for (section, is_dev) in sections {
		if let Some(deps) = doc.get(section).and_then(|d| d.as_table()) {
			for (name, spec) in deps {
				let version = extract_version_from_spec(spec).unwrap_or_else(|| "0.0.0".to_string());
				let pkg = make_package(name, &version, true, 0, None);
				let mut pkg = pkg;
				if is_dev {
					pkg.dev_dependencies.push(name.clone());
				}
				tree.add_package(name.clone(), pkg);
			}
		}
	}

	Ok(tree)
}

fn extract_version_from_spec(spec: &toml::Value) -> Option<String> {
	match spec {
		toml::Value::String(v) => {
			let v = v.trim_start_matches('^')
				.trim_start_matches('~')
				.trim_start_matches('=')
				.trim_start_matches(">=")
				.trim_start_matches("<=")
				.trim_start_matches('>')
				.trim_start_matches('<');
			let v = v.split(',').next().unwrap_or("").trim();
			if v.is_empty() { None } else { Some(v.to_string()) }
		}
		toml::Value::Table(t) => {
			t.get("version")
				.and_then(|v| v.as_str())
				.map(|v| {
					v.trim_start_matches('^')
						.trim_start_matches('~')
						.trim_start_matches('=')
						.to_string()
				})
		}
		_ => None,
	}
}

fn parse_cargo_lock(
	directs: &HashMap<String, bool>,
	toml_path: &Path,
	lock_path: &Path,
) -> Result<DependencyTree> {
	let toml_content = std::fs::read_to_string(toml_path)
		.with_context(|| format!("failed to read {}", toml_path.display()))?;
	let toml_doc: toml::Value = toml::from_str(&toml_content)
		.with_context(|| format!("failed to parse {}", toml_path.display()))?;
	let package_name = toml_doc
		.get("package")
		.and_then(|p| p.get("name"))
		.and_then(|n| n.as_str())
		.unwrap_or("unknown");

	let lock_content = std::fs::read_to_string(lock_path)
		.with_context(|| format!("failed to read {}", lock_path.display()))?;
	let lock_doc: toml::Value = toml::from_str(&lock_content)
		.with_context(|| format!("failed to parse {}", lock_path.display()))?;

	let mut tree = DependencyTree::new(package_name, "crates.io");

	let packages = match lock_doc.get("package").and_then(|p| p.as_array()) {
		Some(pkgs) => pkgs,
		None => return Ok(tree),
	};

	let root_name = package_name;

	for pkg in packages {
		let name = match pkg.get("name").and_then(|n| n.as_str()) {
			Some(n) => n,
			None => continue,
		};

		if name == root_name {
			continue;
		}

		let version = pkg
			.get("version")
			.and_then(|v| v.as_str())
			.unwrap_or("0.0.0");

		let checksum = pkg
			.get("checksum")
			.and_then(|c| c.as_str())
			.map(|c| c.to_string());

		let is_direct = directs.contains_key(name);
		let depth = if is_direct { 0 } else { 1 };

		let mut parsed = make_package(name, version, is_direct, depth, checksum);

		if let Some(true) = directs.get(name) {
			parsed.dev_dependencies.push(name.to_string());
		}

		let key = format!("{name}@{version}");
		tree.add_package(key, parsed);
	}

	Ok(tree)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;
	use tempfile::NamedTempFile;

	#[test]
	fn parses_cargo_toml_direct_deps() {
		let mut f = NamedTempFile::with_suffix(".toml").unwrap();
		writeln!(f, "[package]").unwrap();
		writeln!(f, r#"name = "myapp""#).unwrap();
		writeln!(f, r#"version = "0.1.0""#).unwrap();
		writeln!(f, "").unwrap();
		writeln!(f, "[dependencies]").unwrap();
		writeln!(f, r#"serde = "1.0""#).unwrap();
		writeln!(f, r#"tokio = {{ version = "1.35", features = ["full"] }}"#).unwrap();
		writeln!(f, "").unwrap();
		writeln!(f, "[dev-dependencies]").unwrap();
		writeln!(f, r#"tempfile = "3""#).unwrap();

		let tree = parse_cargo_toml_only(f.path()).unwrap();
		assert!(tree.packages.contains_key("serde"));
		assert!(tree.packages.contains_key("tokio"));
		assert!(tree.packages.contains_key("tempfile"));
		assert_eq!(tree.packages["serde"].version, "1.0");
		assert_eq!(tree.packages["tokio"].version, "1.35");
	}

	#[test]
	fn extract_version_from_string_spec() {
		let v = toml::Value::String("^1.2.3".to_string());
		assert_eq!(extract_version_from_spec(&v), Some("1.2.3".to_string()));

		let v = toml::Value::String("~0.5".to_string());
		assert_eq!(extract_version_from_spec(&v), Some("0.5".to_string()));
	}
}
