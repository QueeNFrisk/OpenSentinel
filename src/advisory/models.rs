use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::database::models::{AdvisorySource, SeverityLevel};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryData {
	pub source: AdvisorySource,
	pub external_id: String,
	pub title: String,
	pub description: String,
	pub severity: SeverityLevel,
	pub cvss_score: Option<f32>,
	pub affected_versions: String,
	pub patched_versions: Option<String>,
	pub published_at: Option<DateTime<Utc>>,
	pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreData {
	pub technique_id: String,
	pub technique_name: String,
	pub tactic: String,
	pub url: String,
	pub description: String,
}
