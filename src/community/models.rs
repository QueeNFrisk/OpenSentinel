use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReportSource {
	Community,
	Osv,
	SocketDev,
	Sonatype,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReportSeverity {
	Critical,
	High,
	Medium,
	Low,
}

impl ReportSeverity {
	pub fn label(&self) -> &str {
		match self {
			ReportSeverity::Critical => "CRITICAL",
			ReportSeverity::High     => "HIGH",
			ReportSeverity::Medium   => "MEDIUM",
			ReportSeverity::Low      => "LOW",
		}
	}

	pub fn score(&self) -> f32 {
		match self {
			ReportSeverity::Critical => 1.0,
			ReportSeverity::High     => 0.8,
			ReportSeverity::Medium   => 0.5,
			ReportSeverity::Low      => 0.2,
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityReport {
	pub package_name: String,
	pub ecosystem: String,
	pub matched_version: Option<String>,
	pub severity: ReportSeverity,
	pub reason: String,
	pub source: ReportSource,
	pub reported_at: Option<String>,
	pub references: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MaliciousEntry {
	pub package_name: String,
	pub ecosystem: String,
	pub affected_versions: Option<Vec<String>>,
	pub severity: ReportSeverity,
	pub reason: String,
	pub source: ReportSource,
	pub reported_at: Option<String>,
	pub references: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MaliciousDatabase {
	#[allow(dead_code)]
	pub version: String,
	pub entries: Vec<MaliciousEntry>,
}
