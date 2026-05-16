use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use super::models::OpenSentinelConfig;

const PROJECT_CONFIG_FILE: &str = "opensentinel.json";
const GLOBAL_CONFIG_DIR: &str = ".opensentinel";
const GLOBAL_CONFIG_FILE: &str = "config.json";

pub struct ConfigLoader;

impl ConfigLoader {
	pub fn load(project_path: &Path) -> Result<OpenSentinelConfig> {
		let project_json = Self::load_project_json(project_path)?;
		let global_json = Self::load_global_json().ok();

		let merged = match (project_json, global_json) {
			(Some(project), Some(global)) => Self::merge_json(global, project),
			(Some(project), None) => project,
			(None, Some(global)) => global,
			(None, None) => serde_json::from_str(DEFAULT_CONFIG).expect("invalid default config"),
		};

		serde_json::from_value(merged).context("failed to deserialize merged config")
	}

	fn load_project_json(project_path: &Path) -> Result<Option<Value>> {
		let config_path = project_path.join(PROJECT_CONFIG_FILE);
		if !config_path.exists() {
			return Ok(None);
		}
		let content = fs::read_to_string(&config_path)
			.with_context(|| format!("failed to read {}", config_path.display()))?;
		let value: Value = serde_json::from_str(&content)
			.with_context(|| format!("failed to parse {}", config_path.display()))?;
		Ok(Some(value))
	}

	fn load_global_json() -> Result<Value> {
		let config_path = Self::global_config_path();
		let content = fs::read_to_string(&config_path)
			.with_context(|| format!("failed to read global config at {}", config_path.display()))?;
		serde_json::from_str(&content).context("failed to parse global config")
	}

	fn global_config_path() -> PathBuf {
		dirs::home_dir()
			.unwrap_or_default()
			.join(GLOBAL_CONFIG_DIR)
			.join(GLOBAL_CONFIG_FILE)
	}

	pub fn config_path(project_path: &Path) -> PathBuf {
		project_path.join(PROJECT_CONFIG_FILE)
	}

	/// Returns true only when an explicit `ecosystems` key exists in a
	/// project-local or global config file.  Falls back to false (→ auto-detect)
	/// when neither file exists or neither has the key.
	pub fn has_explicit_ecosystems(project_path: &Path) -> bool {
		let project_has = Self::load_project_json(project_path)
			.ok()
			.flatten()
			.and_then(|v| v.get("ecosystems").cloned())
			.is_some();

		if project_has {
			return true;
		}

		Self::load_global_json()
			.ok()
			.and_then(|v| v.get("ecosystems").cloned())
			.is_some()
	}

	pub fn save_ignored(project_path: &Path, ignored: &[String]) -> Result<()> {
		let config_path = Self::config_path(project_path);
		if !config_path.exists() {
			return Ok(());
		}
		let content = fs::read_to_string(&config_path)
			.with_context(|| format!("failed to read {}", config_path.display()))?;
		let mut json: Value = serde_json::from_str(&content)
			.with_context(|| format!("failed to parse {}", config_path.display()))?;

		if let Value::Object(ref mut map) = json {
			if ignored.is_empty() {
				map.remove("ignoredPackages");
			} else {
				map.insert(
					"ignoredPackages".to_string(),
					Value::Array(ignored.iter().map(|s| Value::String(s.clone())).collect()),
				);
			}
		}

		let out = serde_json::to_string_pretty(&json).context("failed to serialize config")?;
		fs::write(&config_path, out)
			.with_context(|| format!("failed to write {}", config_path.display()))?;
		Ok(())
	}

	fn merge_json(mut base: Value, override_val: Value) -> Value {
		match (&mut base, override_val) {
			(Value::Object(base_map), Value::Object(override_map)) => {
				for (key, val) in override_map {
					let merged = match base_map.remove(&key) {
						Some(base_val) => Self::merge_json(base_val, val),
						None => val,
					};
					base_map.insert(key, merged);
				}
				base
			}
			(_, override_val) => override_val,
		}
	}

}

impl Default for OpenSentinelConfig {
	fn default() -> Self {
		serde_json::from_str(DEFAULT_CONFIG).expect("invalid default config")
	}
}

pub const DEFAULT_CONFIG: &str = r#"
{
	"version": "1.0",
	"database": {
		"engine": "postgresql",
		"host": "localhost",
		"port": 5432,
		"database": "opensentinel",
		"user": "postgres",
		"password": "${DB_PASSWORD}",
		"ssl": false,
		"poolSize": 10
	},
	"sourceAnalysis": {
		"enabled": true,
		"downloadSource": true,
		"analyzeAst": true,
		"cacheDir": ".opensentinel/cache",
		"cacheTtl": 604800,
		"maxSourceSizeMb": 100
	},
	"parallelism": {
		"packageConcurrency": 4,
		"apiConcurrency": 3,
		"osv": { "limit": 10, "delayMs": 100 },
		"github": { "limit": 5, "delayMs": 200 },
		"nvd": { "limit": 5, "delayMs": 200 },
		"mitre": { "limit": 3, "delayMs": 300 }
	},
	"credentials": {
		"githubToken": "${GITHUB_TOKEN}",
		"nvdApiKey": "${NVD_API_KEY}",
		"storage": "env",
		"keyringSupport": false
	},
	"ecosystems": ["nodejs", "bun"],
	"severity": ["high", "critical"],
	"excludeDevDeps": false,
	"keybindings": "arrows",
	"outputFormat": "sbom"
}
"#;

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn merge_overrides_scalar_field() {
		let base = json!({ "a": 1, "b": 2 });
		let over = json!({ "b": 99 });
		let result = ConfigLoader::merge_json(base, over);
		assert_eq!(result["a"], 1);
		assert_eq!(result["b"], 99);
	}

	#[test]
	fn merge_adds_missing_key() {
		let base = json!({ "a": 1 });
		let over = json!({ "b": 2 });
		let result = ConfigLoader::merge_json(base, over);
		assert_eq!(result["a"], 1);
		assert_eq!(result["b"], 2);
	}

	#[test]
	fn merge_nested_objects() {
		let base = json!({ "db": { "host": "localhost", "port": 5432 } });
		let over = json!({ "db": { "host": "prod.db" } });
		let result = ConfigLoader::merge_json(base, over);
		assert_eq!(result["db"]["host"], "prod.db");
		assert_eq!(result["db"]["port"], 5432);
	}

	#[test]
	fn merge_array_override_replaces_entirely() {
		let base = json!({ "ecosystems": ["nodejs"] });
		let over = json!({ "ecosystems": ["bun", "nodejs"] });
		let result = ConfigLoader::merge_json(base, over);
		assert_eq!(result["ecosystems"], json!(["bun", "nodejs"]));
	}

	#[test]
	fn default_config_deserializes() {
		let cfg = OpenSentinelConfig::default();
		assert_eq!(cfg.version, "1.0");
		assert!(!cfg.ecosystems.is_empty());
	}

	#[test]
	fn project_config_overrides_global_field() {
		let global = serde_json::from_str::<Value>(DEFAULT_CONFIG).unwrap();
		let project = json!({ "keybindings": "vim" });
		let merged = ConfigLoader::merge_json(global, project);
		let cfg: OpenSentinelConfig = serde_json::from_value(merged).unwrap();
		assert_eq!(cfg.keybindings, crate::config::models::KeybindingsMode::Vim);
	}
}
