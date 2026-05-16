use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenSentinelConfig {
	pub version: String,
	pub database: DatabaseConfig,
	pub source_analysis: SourceAnalysisConfig,
	pub parallelism: ParallelismConfig,
	pub credentials: CredentialsConfig,
	pub ecosystems: Vec<String>,
	pub severity: Vec<String>,
	#[serde(default)]
	pub exclude_dev_deps: bool,
	#[serde(default = "default_keybindings")]
	pub keybindings: KeybindingsMode,
	#[serde(default = "default_output_format")]
	pub output_format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConfig {
	#[serde(default = "default_db_engine")]
	pub engine: DatabaseEngine,
	/// PostgreSQL / MySQL: full connection URL, overrides individual fields.
	/// Supports ${ENV_VAR} syntax. Example: "${DATABASE_URL}"
	#[serde(default)]
	pub url: Option<EnvOrValue>,
	/// SQLite: path to the database file. Defaults to "opensentinel.db".
	#[serde(default)]
	pub sqlite_path: Option<String>,
	#[serde(default = "default_db_host")]
	pub host: String,
	#[serde(default = "default_db_port")]
	pub port: u16,
	#[serde(default = "default_db_name")]
	pub database: String,
	#[serde(default = "default_db_user")]
	pub user: String,
	#[serde(default = "default_db_password")]
	pub password: EnvOrValue,
	#[serde(default)]
	pub ssl: bool,
	#[serde(default = "default_pool_size")]
	pub pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseEngine {
	PostgreSQL,
	SQLite,
	MySQL,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceAnalysisConfig {
	pub enabled: bool,
	pub download_source: bool,
	pub analyze_ast: bool,
	pub cache_dir: PathBuf,
	pub cache_ttl: u64,
	#[serde(default = "default_max_source_size")]
	pub max_source_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParallelismConfig {
	#[serde(default = "default_pkg_concurrency")]
	pub package_concurrency: usize,
	#[serde(default = "default_api_concurrency")]
	pub api_concurrency: usize,
	pub osv: ApiRateLimitConfig,
	pub github: ApiRateLimitConfig,
	pub nvd: ApiRateLimitConfig,
	pub mitre: ApiRateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiRateLimitConfig {
	pub limit: usize,
	pub delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsConfig {
	pub github_token: EnvOrValue,
	pub nvd_api_key: EnvOrValue,
	pub storage: CredentialStorage,
	#[serde(default)]
	pub keyring_support: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStorage {
	Env,
	File,
	Keyring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvOrValue {
	EnvVar(String),
	Literal(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeybindingsMode {
	Arrows,
	Vim,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
	Sbom,
	Json,
	Table,
	Html,
}

fn default_keybindings() -> KeybindingsMode {
	KeybindingsMode::Arrows
}

fn default_output_format() -> OutputFormat {
	OutputFormat::Sbom
}

fn default_db_engine() -> DatabaseEngine {
	DatabaseEngine::PostgreSQL
}

fn default_db_host() -> String {
	"localhost".to_string()
}

fn default_db_port() -> u16 {
	5432
}

fn default_db_name() -> String {
	"opensentinel".to_string()
}

fn default_db_user() -> String {
	"postgres".to_string()
}

fn default_db_password() -> EnvOrValue {
	EnvOrValue::EnvVar("${DB_PASSWORD}".to_string())
}

fn default_pool_size() -> u32 {
	10
}

fn default_pkg_concurrency() -> usize {
	4
}

fn default_api_concurrency() -> usize {
	3
}

fn default_max_source_size() -> u64 {
	100
}
