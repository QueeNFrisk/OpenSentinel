use serde::{Deserialize, Serialize};
use crate::community::models::CommunityReport;
use crate::database::models::{MaintainerMetrics, SeverityLevel, VersionDiff};
use crate::advisory::models::{AdvisoryData, MitreData};
use crate::analyzer::models::DetectionMatch;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRisk {
	pub package_name: String,
	pub package_version: String,
	pub ecosystem: String,
	pub overall_severity: SeverityLevel,
	pub advisory_score: f32,
	pub pattern_score: f32,
	pub version_change_score: f32,
	pub reputation_score: f32,
	pub community_score: f32,
	pub final_score: f32,
	pub advisories: Vec<AdvisoryData>,
	pub detections: Vec<DetectionMatch>,
	pub version_changes: Vec<VersionDiff>,
	pub community_reports: Vec<CommunityReport>,
	pub maintainer: Option<MaintainerMetrics>,
	pub mitre_mappings: Vec<MitreData>,
	pub recommendations: Vec<String>,
	pub is_direct: bool,
	pub depth: u32,
}

#[allow(dead_code)]
impl PackageRisk {
	pub fn is_safe(&self) -> bool {
		self.overall_severity == SeverityLevel::Safe
	}

	pub fn severity_label(&self) -> &str {
		match self.overall_severity {
			SeverityLevel::Critical => "CRITICAL",
			SeverityLevel::High => "HIGH",
			SeverityLevel::Medium => "MEDIUM",
			SeverityLevel::Low => "LOW",
			SeverityLevel::Safe => "SAFE",
		}
	}
}
