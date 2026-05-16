use anyhow::{Context, Result};
use std::path::Path;

use super::models::{DependencyTree, ParsedPackage};

const GO_MOD: &str = "go.mod";
const GO_SUM: &str = "go.sum";

pub struct GolangParser;

impl GolangParser {
	pub async fn detect_and_parse(project_path: &Path) -> Result<Option<DependencyTree>> {
		let mod_path = project_path.join(GO_MOD);
		if !mod_path.exists() {
			return Ok(None);
		}

		let sum_path = project_path.join(GO_SUM);
		let tree = if sum_path.exists() {
			let directs = parse_go_mod_directs(&mod_path)?;
			parse_go_sum(&directs, &mod_path, &sum_path)?
		} else {
			parse_go_mod_only(&mod_path)?
		};

		Ok(Some(tree))
	}
}

fn module_to_registry_url(module: &str, version: &str) -> String {
	format!("https://pkg.go.dev/{module}@{version}")
}

fn make_package(
	name: &str,
	version: &str,
	is_direct: bool,
	depth: u32,
) -> ParsedPackage {
	ParsedPackage {
		name: name.to_string(),
		version: version.to_string(),
		ecosystem: "Go".to_string(),
		registry_url: Some(module_to_registry_url(name, version)),
		checksum: None,
		is_direct,
		depth,
		dependencies: vec![],
		dev_dependencies: vec![],
		install_scripts: vec![],
	}
}

fn parse_go_mod_directs(path: &Path) -> Result<std::collections::HashSet<String>> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let mut directs = std::collections::HashSet::new();
	let mut in_require_block = false;
	let mut indirect_markers = std::collections::HashSet::new();

	for line in content.lines() {
		let line = line.trim();

		if line == "require (" {
			in_require_block = true;
			continue;
		}
		if in_require_block && line == ")" {
			in_require_block = false;
			continue;
		}

		if in_require_block || line.starts_with("require ") {
			let entry = if in_require_block {
				line
			} else {
				line.trim_start_matches("require").trim()
			};

			let entry = entry.split("//").next().unwrap_or("").trim();
			let parts: Vec<&str> = entry.split_whitespace().collect();
			if parts.len() >= 2 {
				let module = parts[0];
				let comment = entry;
				if comment.contains("// indirect") {
					indirect_markers.insert(module.to_string());
				} else {
					directs.insert(module.to_string());
				}
			}
		}
	}

	for indirect in &indirect_markers {
		directs.remove(indirect);
	}

	Ok(directs)
}

fn parse_go_mod_only(path: &Path) -> Result<DependencyTree> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let module_name = parse_module_name(&content);
	let mut tree = DependencyTree::new(module_name, "Go");

	let mut in_require_block = false;

	for line in content.lines() {
		let line = line.trim();

		if line == "require (" {
			in_require_block = true;
			continue;
		}
		if in_require_block && line == ")" {
			in_require_block = false;
			continue;
		}

		if in_require_block || line.starts_with("require ") {
			let entry = if in_require_block {
				line
			} else {
				line.trim_start_matches("require").trim()
			};

			let entry = entry.split("//").next().unwrap_or("").trim();
			let parts: Vec<&str> = entry.split_whitespace().collect();
			if parts.len() >= 2 {
				let name = parts[0];
				let version = parts[1].trim_start_matches('v');
				let is_indirect = line.contains("// indirect");
				let depth = if is_indirect { 1 } else { 0 };
				let key = name.to_string();
				let pkg = make_package(name, version, !is_indirect, depth);
				tree.add_package(key, pkg);
			}
		}
	}

	Ok(tree)
}

fn parse_go_sum(
	directs: &std::collections::HashSet<String>,
	mod_path: &Path,
	sum_path: &Path,
) -> Result<DependencyTree> {
	let mod_content = std::fs::read_to_string(mod_path)
		.with_context(|| format!("failed to read {}", mod_path.display()))?;
	let module_name = parse_module_name(&mod_content);
	let mut tree = DependencyTree::new(module_name, "Go");

	let sum_content = std::fs::read_to_string(sum_path)
		.with_context(|| format!("failed to read {}", sum_path.display()))?;

	let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();

	for line in sum_content.lines() {
		let line = line.trim();
		if line.is_empty() {
			continue;
		}

		let parts: Vec<&str> = line.split_whitespace().collect();
		if parts.len() < 3 {
			continue;
		}

		let module = parts[0];
		let version_field = parts[1];

		if version_field.ends_with("/go.mod") {
			continue;
		}

		let version = version_field.trim_start_matches('v');

		if seen.contains_key(module) {
			continue;
		}
		seen.insert(module.to_string(), version.to_string());

		let is_direct = directs.contains(module);
		let depth = if is_direct { 0 } else { 1 };
		let key = module.to_string();
		let pkg = make_package(module, version, is_direct, depth);
		tree.add_package(key, pkg);
	}

	Ok(tree)
}

fn parse_module_name(content: &str) -> String {
	for line in content.lines() {
		let line = line.trim();
		if line.starts_with("module ") {
			return line[7..].trim().to_string();
		}
	}
	"unknown".to_string()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;
	use tempfile::NamedTempFile;

	#[test]
	fn parses_module_name() {
		let content = "module github.com/example/app\n\ngo 1.21\n";
		assert_eq!(parse_module_name(content), "github.com/example/app");
	}

	#[test]
	fn parses_go_mod_direct_deps() {
		let mut f = NamedTempFile::new().unwrap();
		writeln!(f, "module example.com/app").unwrap();
		writeln!(f, "").unwrap();
		writeln!(f, "require (").unwrap();
		writeln!(f, "    github.com/gin-gonic/gin v1.9.1").unwrap();
		writeln!(f, "    github.com/pkg/errors v0.9.1 // indirect").unwrap();
		writeln!(f, ")").unwrap();

		let tree = parse_go_mod_only(f.path()).unwrap();
		let gin = tree.packages.get("github.com/gin-gonic/gin").unwrap();
		assert!(gin.is_direct);
		assert_eq!(gin.depth, 0);

		let errors = tree.packages.get("github.com/pkg/errors").unwrap();
		assert!(!errors.is_direct);
		assert_eq!(errors.depth, 1);
	}

	#[test]
	fn strips_v_prefix_from_version() {
		let mut f = NamedTempFile::new().unwrap();
		writeln!(f, "module example.com/app").unwrap();
		writeln!(f, "require github.com/foo/bar v1.2.3").unwrap();

		let tree = parse_go_mod_only(f.path()).unwrap();
		let pkg = tree.packages.get("github.com/foo/bar").unwrap();
		assert_eq!(pkg.version, "1.2.3");
	}
}
