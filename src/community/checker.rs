use super::models::{CommunityReport, MaliciousDatabase};

static BUNDLED_DB: &str = include_str!("../../data/known_malicious.json");

pub struct CommunityChecker {
	db: MaliciousDatabase,
}

impl CommunityChecker {
	pub fn new() -> Self {
		let db: MaliciousDatabase = serde_json::from_str(BUNDLED_DB)
			.expect("bundled known_malicious.json is malformed");
		Self { db }
	}

	pub fn check(&self, package_name: &str, version: &str, ecosystem: &str) -> Vec<CommunityReport> {
		self.db
			.entries
			.iter()
			.filter(|e| {
				e.ecosystem == ecosystem
					&& e.package_name.eq_ignore_ascii_case(package_name)
			})
			.filter(|e| {
				match &e.affected_versions {
					None => true,
					Some(versions) => versions.iter().any(|v| v == version),
				}
			})
			.map(|e| CommunityReport {
				package_name: e.package_name.clone(),
				ecosystem: e.ecosystem.clone(),
				matched_version: e.affected_versions.as_ref().and_then(|vs| {
					vs.iter().find(|v| v.as_str() == version).cloned()
				}),
				severity: e.severity.clone(),
				reason: e.reason.clone(),
				source: e.source.clone(),
				reported_at: e.reported_at.clone(),
				references: e.references.clone(),
			})
			.collect()
	}

	pub fn db_version(&self) -> &str {
		&self.db.version
	}

	pub fn entry_count(&self) -> usize {
		self.db.entries.len()
	}

	pub fn all_entries(&self) -> &[super::models::MaliciousEntry] {
		&self.db.entries
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn checker() -> CommunityChecker {
		CommunityChecker::new()
	}

	#[test]
	fn loads_bundled_database_without_panic() {
		let c = checker();
		assert!(!c.db_version().is_empty());
	}

	#[test]
	fn detects_event_stream_malicious_version() {
		let reports = checker().check("event-stream", "3.3.6", "npm");
		assert_eq!(reports.len(), 1);
		assert_eq!(reports[0].matched_version, Some("3.3.6".to_string()));
	}

	#[test]
	fn safe_version_of_event_stream_returns_empty() {
		let reports = checker().check("event-stream", "4.0.1", "npm");
		assert!(reports.is_empty());
	}

	#[test]
	fn detects_ua_parser_js_all_malicious_versions() {
		let c = checker();
		assert_eq!(c.check("ua-parser-js", "0.7.29", "npm").len(), 1);
		assert_eq!(c.check("ua-parser-js", "0.7.30", "npm").len(), 1);
		assert_eq!(c.check("ua-parser-js", "1.0.0", "npm").len(), 1);
		assert!(c.check("ua-parser-js", "0.7.31", "npm").is_empty());
	}

	#[test]
	fn detects_package_with_no_version_restriction() {
		let reports = checker().check("peacenotwar", "9.1.1", "npm");
		assert_eq!(reports.len(), 1);
		assert!(reports[0].matched_version.is_none());
	}

	#[test]
	fn case_insensitive_package_name_match() {
		let reports = checker().check("Event-Stream", "3.3.6", "npm");
		assert_eq!(reports.len(), 1);
	}

	#[test]
	fn wrong_ecosystem_returns_empty() {
		let reports = checker().check("event-stream", "3.3.6", "pypi");
		assert!(reports.is_empty());
	}

	#[test]
	fn unknown_package_returns_empty() {
		let reports = checker().check("totally-safe-package", "1.0.0", "npm");
		assert!(reports.is_empty());
	}

	#[test]
	fn report_contains_reason_and_references() {
		let reports = checker().check("event-stream", "3.3.6", "npm");
		assert!(!reports[0].reason.is_empty());
		assert!(!reports[0].references.is_empty());
	}

	#[test]
	fn severity_score_critical_is_one() {
		use super::super::models::ReportSeverity;
		assert!((ReportSeverity::Critical.score() - 1.0).abs() < 0.001);
	}

	#[test]
	fn severity_label_is_uppercase() {
		use super::super::models::ReportSeverity;
		assert_eq!(ReportSeverity::High.label(), "HIGH");
		assert_eq!(ReportSeverity::Medium.label(), "MEDIUM");
	}
}
