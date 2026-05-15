use serde::{Deserialize, Serialize};
use crate::database::models::PatternType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMatch {
	pub pattern_type: PatternType,
	pub description: String,
	pub file_path: Option<String>,
	pub line_number: Option<u32>,
	pub code_snippet: Option<String>,
	pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
	pub package_name: String,
	pub package_version: String,
	pub matches: Vec<DetectionMatch>,
	pub has_install_scripts: bool,
}

#[allow(dead_code)]
impl AnalysisResult {
	pub fn new(package_name: impl Into<String>, package_version: impl Into<String>) -> Self {
		Self {
			package_name: package_name.into(),
			package_version: package_version.into(),
			matches: Vec::new(),
			has_install_scripts: false,
		}
	}

	pub fn is_clean(&self) -> bool {
		self.matches.is_empty()
	}

	pub fn highest_confidence(&self) -> f32 {
		self.matches.iter().map(|m| m.confidence).fold(0.0_f32, f32::max)
	}
}
