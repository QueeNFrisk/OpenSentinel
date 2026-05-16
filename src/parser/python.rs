use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

use super::models::{DependencyTree, ParsedPackage};

const REQUIREMENTS_TXT: &str = "requirements.txt";
const PYPROJECT_TOML: &str = "pyproject.toml";
const POETRY_LOCK: &str = "poetry.lock";
const PIPFILE_LOCK: &str = "Pipfile.lock";

pub struct PythonParser;

impl PythonParser {
	pub async fn detect_and_parse(project_path: &Path) -> Result<Option<DependencyTree>> {
		let has_pyproject = project_path.join(PYPROJECT_TOML).exists();
		let has_poetry_lock = project_path.join(POETRY_LOCK).exists();
		let has_pipfile_lock = project_path.join(PIPFILE_LOCK).exists();
		let has_requirements = project_path.join(REQUIREMENTS_TXT).exists();

		if !has_pyproject && !has_requirements && !has_pipfile_lock {
			return Ok(None);
		}

		let tree = if has_poetry_lock {
			let direct = if has_pyproject {
				parse_pyproject_direct(&project_path.join(PYPROJECT_TOML))?
			} else {
				HashMap::new()
			};
			parse_poetry_lock(&direct, &project_path.join(POETRY_LOCK))?
		} else if has_pipfile_lock {
			parse_pipfile_lock(&project_path.join(PIPFILE_LOCK))?
		} else if has_requirements {
			parse_requirements_txt(&project_path.join(REQUIREMENTS_TXT))?
		} else if has_pyproject {
			parse_pyproject_only(&project_path.join(PYPROJECT_TOML))?
		} else {
			return Ok(None);
		};

		Ok(Some(tree))
	}
}

fn normalize_name(name: &str) -> String {
	name.to_lowercase().replace('-', "_").replace('.', "_")
}

fn strip_extras(spec: &str) -> &str {
	spec.split('[').next().unwrap_or(spec).trim()
}

fn parse_version_spec(spec: &str) -> Option<String> {
	let spec = spec.trim();
	if spec.is_empty() || spec == "*" {
		return None;
	}
	for prefix in ["==", ">=", "<=", "~=", "!=", ">", "<", "^"] {
		if spec.starts_with(prefix) {
			let ver = spec[prefix.len()..].trim().split(',').next().unwrap_or("").trim();
			if !ver.is_empty() {
				return Some(ver.to_string());
			}
		}
	}
	None
}

fn make_package(
	name: &str,
	version: &str,
	ecosystem: &str,
	is_direct: bool,
	depth: u32,
	dev: bool,
) -> ParsedPackage {
	let reg = format!("https://pypi.org/project/{name}/{version}/");
	ParsedPackage {
		name: name.to_string(),
		version: version.to_string(),
		ecosystem: ecosystem.to_string(),
		registry_url: Some(reg),
		checksum: None,
		is_direct,
		depth,
		dependencies: vec![],
		dev_dependencies: if dev { vec![name.to_string()] } else { vec![] },
		install_scripts: vec![],
	}
}

fn parse_requirements_txt(path: &Path) -> Result<DependencyTree> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let mut tree = DependencyTree::new("python-project", "PyPI");

	for line in content.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
			continue;
		}
		let (name_spec, _comment) = line.split_once('#').unwrap_or((line, ""));
		let name_spec = name_spec.trim();
		if name_spec.is_empty() {
			continue;
		}

		let (raw_name, version_part) = if let Some(pos) =
			name_spec.find(|c: char| c == '=' || c == '>' || c == '<' || c == '!' || c == '~' || c == '^')
		{
			(&name_spec[..pos], &name_spec[pos..])
		} else {
			(name_spec, "")
		};

		let name = strip_extras(raw_name).trim();
		if name.is_empty() {
			continue;
		}

		let version = parse_version_spec(version_part)
			.unwrap_or_else(|| "0.0.0".to_string());

		let key = normalize_name(name);
		let pkg = make_package(name, &version, "PyPI", true, 0, false);
		tree.add_package(key, pkg);
	}

	Ok(tree)
}

fn parse_pyproject_direct(path: &Path) -> Result<HashMap<String, bool>> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let doc: toml::Value = toml::from_str(&content)
		.with_context(|| format!("failed to parse {}", path.display()))?;

	let mut direct: HashMap<String, bool> = HashMap::new();

	if let Some(deps) = doc
		.get("tool")
		.and_then(|t| t.get("poetry"))
		.and_then(|p| p.get("dependencies"))
		.and_then(|d| d.as_table())
	{
		for name in deps.keys() {
			if name.to_lowercase() != "python" {
				direct.insert(normalize_name(name), false);
			}
		}
	}

	if let Some(dev_deps) = doc
		.get("tool")
		.and_then(|t| t.get("poetry"))
		.and_then(|p| p.get("dev-dependencies"))
		.and_then(|d| d.as_table())
	{
		for name in dev_deps.keys() {
			direct.insert(normalize_name(name), true);
		}
	}

	if let Some(dev_deps) = doc
		.get("tool")
		.and_then(|t| t.get("poetry"))
		.and_then(|p| p.get("group"))
		.and_then(|g| g.get("dev"))
		.and_then(|g| g.get("dependencies"))
		.and_then(|d| d.as_table())
	{
		for name in dev_deps.keys() {
			direct.insert(normalize_name(name), true);
		}
	}

	if let Some(deps) = doc
		.get("project")
		.and_then(|p| p.get("dependencies"))
		.and_then(|d| d.as_array())
	{
		for dep in deps {
			if let Some(s) = dep.as_str() {
				let name = strip_extras(s.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.').next().unwrap_or(s)).trim();
				if !name.is_empty() {
					direct.insert(normalize_name(name), false);
				}
			}
		}
	}

	Ok(direct)
}

fn parse_pyproject_only(path: &Path) -> Result<DependencyTree> {
	let direct = parse_pyproject_direct(path)?;
	let mut tree = DependencyTree::new("python-project", "PyPI");

	for (key, is_dev) in &direct {
		let pkg = make_package(key, "0.0.0", "PyPI", true, 0, *is_dev);
		tree.add_package(key.clone(), pkg);
	}

	Ok(tree)
}

fn parse_poetry_lock(direct: &HashMap<String, bool>, path: &Path) -> Result<DependencyTree> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let doc: toml::Value = toml::from_str(&content)
		.with_context(|| format!("failed to parse {}", path.display()))?;

	let mut tree = DependencyTree::new("python-project", "PyPI");

	let packages = match doc.get("package").and_then(|p| p.as_array()) {
		Some(pkgs) => pkgs,
		None => return Ok(tree),
	};

	for pkg in packages {
		let name = match pkg.get("name").and_then(|n| n.as_str()) {
			Some(n) => n,
			None => continue,
		};
		let version = pkg
			.get("version")
			.and_then(|v| v.as_str())
			.unwrap_or("0.0.0");

		let key = normalize_name(name);
		let is_dev = direct.get(&key).copied().unwrap_or(false);
		let is_direct = direct.contains_key(&key);

		let depth = if is_direct { 0 } else { 1 };
		let parsed = make_package(name, version, "PyPI", is_direct, depth, is_dev);
		tree.add_package(key, parsed);
	}

	Ok(tree)
}

fn parse_pipfile_lock(path: &Path) -> Result<DependencyTree> {
	let content = std::fs::read_to_string(path)
		.with_context(|| format!("failed to read {}", path.display()))?;

	let doc: serde_json::Value = serde_json::from_str(&content)
		.with_context(|| format!("failed to parse {}", path.display()))?;

	let mut tree = DependencyTree::new("python-project", "PyPI");

	let sections = [("default", false), ("develop", true)];

	for (section, is_dev) in sections {
		if let Some(pkgs) = doc.get(section).and_then(|s| s.as_object()) {
			for (name, meta) in pkgs {
				if name == "_meta" {
					continue;
				}
				let version = meta
					.get("version")
					.and_then(|v| v.as_str())
					.and_then(|v| parse_version_spec(v))
					.unwrap_or_else(|| "0.0.0".to_string());

				let key = normalize_name(name);
				let pkg = make_package(name, &version, "PyPI", true, 0, is_dev);
				tree.add_package(key, pkg);
			}
		}
	}

	Ok(tree)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;
	use tempfile::NamedTempFile;

	#[test]
	fn parses_requirements_txt_pinned() {
		let mut f = NamedTempFile::new().unwrap();
		writeln!(f, "requests==2.28.0").unwrap();
		writeln!(f, "flask>=2.0.0").unwrap();
		writeln!(f, "# comment").unwrap();
		writeln!(f, "").unwrap();

		let tree = parse_requirements_txt(f.path()).unwrap();
		assert!(tree.packages.contains_key("requests"));
		assert_eq!(tree.packages["requests"].version, "2.28.0");
		assert!(tree.packages.contains_key("flask"));
	}

	#[test]
	fn skips_comments_and_flags_in_requirements() {
		let mut f = NamedTempFile::new().unwrap();
		writeln!(f, "-r other.txt").unwrap();
		writeln!(f, "--index-url https://example.com").unwrap();
		writeln!(f, "boto3==1.26.0").unwrap();

		let tree = parse_requirements_txt(f.path()).unwrap();
		assert_eq!(tree.packages.len(), 1);
		assert!(tree.packages.contains_key("boto3"));
	}

	#[test]
	fn normalize_name_lowercases_and_replaces_separators() {
		assert_eq!(normalize_name("Pillow"), "pillow");
		assert_eq!(normalize_name("my-package"), "my_package");
		assert_eq!(normalize_name("My.Package"), "my_package");
	}
}
