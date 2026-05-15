#![allow(dead_code)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Package {
	pub id: Uuid,
	pub name: String,
	pub version: String,
	pub ecosystem: String,
	pub registry_url: Option<String>,
	pub checksum: Option<String>,
	pub is_direct: bool,
	pub depth: i32,
	pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Dependency {
	pub id: Uuid,
	pub parent_id: Uuid,
	pub child_id: Uuid,
	pub version_constraint: String,
	pub is_dev: bool,
	pub is_optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Advisory {
	pub id: Uuid,
	pub package_id: Uuid,
	pub source: AdvisorySource,
	pub external_id: String,
	pub title: String,
	pub description: String,
	pub severity: SeverityLevel,
	pub cvss_score: Option<f32>,
	pub affected_versions: String,
	pub patched_versions: Option<String>,
	pub published_at: Option<DateTime<Utc>>,
	pub fetched_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "advisory_source", rename_all = "lowercase")]
pub enum AdvisorySource {
	Osv,
	Github,
	Nvd,
	Mitre,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq, PartialOrd)]
#[sqlx(type_name = "severity_level", rename_all = "lowercase")]
pub enum SeverityLevel {
	Safe,
	Low,
	Medium,
	High,
	Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DetectedPattern {
	pub id: Uuid,
	pub package_id: Uuid,
	pub pattern_type: PatternType,
	pub description: String,
	pub file_path: Option<String>,
	pub line_number: Option<i32>,
	pub code_snippet: Option<String>,
	pub confidence: f32,
	pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "pattern_type", rename_all = "snake_case")]
pub enum PatternType {
	CredentialHarvesting,
	CryptoMining,
	NetworkExfiltration,
	InstallHook,
	Typosquatting,
	ReverseshellCode,
	ObfuscatedCode,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MitreMapping {
	pub id: Uuid,
	pub pattern_id: Uuid,
	pub technique_id: String,
	pub technique_name: String,
	pub tactic: String,
	pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScanResult {
	pub id: Uuid,
	pub project_path: String,
	pub ecosystem: String,
	pub total_packages: i32,
	pub critical_count: i32,
	pub high_count: i32,
	pub medium_count: i32,
	pub low_count: i32,
	pub safe_count: i32,
	pub scanned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RiskScore {
	pub id: Uuid,
	pub package_id: Uuid,
	pub scan_id: Uuid,
	pub overall_severity: SeverityLevel,
	pub advisory_score: f32,
	pub pattern_score: f32,
	pub reputation_score: f32,
	pub final_score: f32,
	pub recommendation: String,
	pub scored_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "version_change_type", rename_all = "snake_case")]
pub enum VersionChangeType {
	FilesRemoved,
	LicenseChanged,
	ManifestChanged,
	DependenciesChanged,
	PermissionsChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VersionDiff {
	pub id: Uuid,
	pub package_id: Uuid,
	pub from_version: String,
	pub to_version: String,
	pub change_type: VersionChangeType,
	pub description: String,
	pub severity: SeverityLevel,
	pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MaintainerMetrics {
	pub id: Uuid,
	pub package_name: String,
	pub ecosystem: String,
	pub repo_url: Option<String>,
	pub days_since_push: i32,
	pub releases_last_year: i32,
	pub open_issues: i32,
	pub stars: i32,
	pub forks: i32,
	pub contributor_count: i32,
	pub reputation_score: f32,
	pub fetched_at: DateTime<Utc>,
}
