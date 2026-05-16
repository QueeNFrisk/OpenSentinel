use std::path::Path;

pub fn detect_ecosystems(project_path: &Path) -> Vec<String> {
	let mut ecosystems = Vec::new();

	let checks: &[(&[&str], &str)] = &[
		(&["package.json"],                          "nodejs"),
		(&["bun.lockb", "bunfig.toml"],              "bun"),
		(&["requirements.txt", "pyproject.toml",
		   "Pipfile.lock", "poetry.lock"],           "python"),
		(&["go.mod"],                                "golang"),
		(&["Cargo.toml"],                            "rust"),
	];

	for (files, ecosystem) in checks {
		if files.iter().any(|f| project_path.join(f).exists()) {
			ecosystems.push(ecosystem.to_string());
		}
	}

	ecosystems
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempfile::TempDir;
	use std::fs;

	#[test]
	fn detects_nodejs_from_package_json() {
		let dir = TempDir::new().unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();
		let ecosystems = detect_ecosystems(dir.path());
		assert!(ecosystems.contains(&"nodejs".to_string()));
		assert!(!ecosystems.contains(&"rust".to_string()));
	}

	#[test]
	fn detects_rust_from_cargo_toml() {
		let dir = TempDir::new().unwrap();
		fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
		let ecosystems = detect_ecosystems(dir.path());
		assert!(ecosystems.contains(&"rust".to_string()));
	}

	#[test]
	fn detects_multiple_ecosystems() {
		let dir = TempDir::new().unwrap();
		fs::write(dir.path().join("package.json"), "{}").unwrap();
		fs::write(dir.path().join("requirements.txt"), "flask==2.0").unwrap();
		let ecosystems = detect_ecosystems(dir.path());
		assert!(ecosystems.contains(&"nodejs".to_string()));
		assert!(ecosystems.contains(&"python".to_string()));
	}

	#[test]
	fn returns_empty_for_unknown_project() {
		let dir = TempDir::new().unwrap();
		let ecosystems = detect_ecosystems(dir.path());
		assert!(ecosystems.is_empty());
	}
}
