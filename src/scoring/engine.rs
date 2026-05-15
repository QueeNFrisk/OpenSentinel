use crate::advisory::mitre::MitreMappingEngine;
use crate::advisory::models::AdvisoryData;
use crate::analyzer::models::{AnalysisResult, DetectionMatch};
use crate::database::models::SeverityLevel;
use super::models::PackageRisk;
use crate::parser::models::ParsedPackage;

pub struct RiskScorer;

impl RiskScorer {
	pub fn score(
		package: &ParsedPackage,
		advisories: Vec<AdvisoryData>,
		analysis: AnalysisResult,
	) -> PackageRisk {
		let advisory_score = Self::calculate_advisory_score(&advisories);
		let pattern_score = Self::calculate_pattern_score(&analysis.matches);
		let final_score = Self::combine_scores(advisory_score, pattern_score);
		let overall_severity = Self::score_to_severity(final_score);

		let mitre_mappings = analysis
			.matches
			.iter()
			.flat_map(|m| MitreMappingEngine::map_pattern(&m.pattern_type))
			.collect::<Vec<_>>();

		let recommendations = Self::generate_recommendations(&advisories, &analysis.matches, &overall_severity);

		PackageRisk {
			package_name: package.name.clone(),
			package_version: package.version.clone(),
			ecosystem: package.ecosystem.clone(),
			overall_severity,
			advisory_score,
			pattern_score,
			final_score,
			advisories,
			detections: analysis.matches,
			mitre_mappings,
			recommendations,
			is_direct: package.is_direct,
			depth: package.depth,
		}
	}

	fn calculate_advisory_score(advisories: &[AdvisoryData]) -> f32 {
		if advisories.is_empty() {
			return 0.0;
		}

		let max_cvss = advisories.iter()
			.filter_map(|a| a.cvss_score)
			.fold(0.0_f32, f32::max);

		if max_cvss > 0.0 {
			return max_cvss / 10.0;
		}

		let max_severity = advisories.iter()
			.map(|a| Self::severity_to_score(&a.severity))
			.fold(0.0_f32, f32::max);

		max_severity
	}

	fn calculate_pattern_score(detections: &[DetectionMatch]) -> f32 {
		if detections.is_empty() {
			return 0.0;
		}

		detections.iter()
			.map(|d| d.confidence)
			.fold(0.0_f32, f32::max)
	}

	fn combine_scores(advisory_score: f32, pattern_score: f32) -> f32 {
		if pattern_score == 0.0 {
			advisory_score
		} else {
			(advisory_score * 0.6 + pattern_score * 0.4).min(1.0)
		}
	}

	fn score_to_severity(score: f32) -> SeverityLevel {
		if score >= 0.9 { SeverityLevel::Critical }
		else if score >= 0.7 { SeverityLevel::High }
		else if score >= 0.4 { SeverityLevel::Medium }
		else if score > 0.0 { SeverityLevel::Low }
		else { SeverityLevel::Safe }
	}

	fn severity_to_score(severity: &SeverityLevel) -> f32 {
		match severity {
			SeverityLevel::Critical => 1.0,
			SeverityLevel::High => 0.8,
			SeverityLevel::Medium => 0.5,
			SeverityLevel::Low => 0.2,
			SeverityLevel::Safe => 0.0,
		}
	}

	fn generate_recommendations(
		advisories: &[AdvisoryData],
		detections: &[DetectionMatch],
		severity: &SeverityLevel,
	) -> Vec<String> {
		let mut recs = Vec::new();

		for advisory in advisories {
			if let Some(patched) = &advisory.patched_versions {
				recs.push(format!("Upgrade to {patched} to patch {}", advisory.external_id));
			}
		}

		for detection in detections {
			recs.push(format!("Review code: {}", detection.description));
		}

		match severity {
			SeverityLevel::Critical | SeverityLevel::High => {
				recs.push("Consider replacing this dependency with a safer alternative".to_string());
				recs.push("Isolate in a sandboxed environment if removal is not possible".to_string());
			}
			SeverityLevel::Medium => {
				recs.push("Monitor for updates and plan upgrade within next sprint".to_string());
			}
			_ => {}
		}

		recs
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::database::models::{AdvisorySource, PatternType};
	use crate::parser::models::ParsedPackage;

	fn make_package(name: &str, version: &str) -> ParsedPackage {
		ParsedPackage {
			name: name.to_string(),
			version: version.to_string(),
			ecosystem: "nodejs".to_string(),
			registry_url: None,
			checksum: None,
			is_direct: true,
			depth: 1,
			dependencies: vec![],
			dev_dependencies: vec![],
			install_scripts: vec![],
		}
	}

	fn make_advisory(cvss: Option<f32>, severity: SeverityLevel) -> AdvisoryData {
		AdvisoryData {
			source: AdvisorySource::Osv,
			external_id: "CVE-2024-0001".to_string(),
			title: "Test advisory".to_string(),
			description: "desc".to_string(),
			severity,
			cvss_score: cvss,
			affected_versions: "< 1.0.0".to_string(),
			patched_versions: Some("1.0.0".to_string()),
			published_at: None,
			references: vec![],
		}
	}

	fn make_detection(confidence: f32, pattern_type: PatternType) -> DetectionMatch {
		DetectionMatch {
			pattern_type,
			description: "test detection".to_string(),
			file_path: None,
			line_number: None,
			code_snippet: None,
			confidence,
		}
	}

	#[test]
	fn score_to_severity_thresholds() {
		assert_eq!(RiskScorer::score_to_severity(0.95), SeverityLevel::Critical);
		assert_eq!(RiskScorer::score_to_severity(0.90), SeverityLevel::Critical);
		assert_eq!(RiskScorer::score_to_severity(0.75), SeverityLevel::High);
		assert_eq!(RiskScorer::score_to_severity(0.70), SeverityLevel::High);
		assert_eq!(RiskScorer::score_to_severity(0.50), SeverityLevel::Medium);
		assert_eq!(RiskScorer::score_to_severity(0.40), SeverityLevel::Medium);
		assert_eq!(RiskScorer::score_to_severity(0.10), SeverityLevel::Low);
		assert_eq!(RiskScorer::score_to_severity(0.0), SeverityLevel::Safe);
	}

	#[test]
	fn combine_scores_weighted_60_40() {
		let result = RiskScorer::combine_scores(0.8, 0.5);
		let expected = 0.8 * 0.6 + 0.5 * 0.4;
		assert!((result - expected).abs() < 0.001);
	}

	#[test]
	fn combine_scores_capped_at_one() {
		let result = RiskScorer::combine_scores(1.0, 1.0);
		assert!((result - 1.0).abs() < 0.001);
	}

	#[test]
	fn safe_package_with_no_advisories_or_detections() {
		let pkg = make_package("lodash", "4.17.21");
		let risk = RiskScorer::score(&pkg, vec![], AnalysisResult::new("lodash", "4.17.21"));
		assert_eq!(risk.overall_severity, SeverityLevel::Safe);
		assert!(risk.is_safe());
		assert_eq!(risk.final_score, 0.0);
	}

	#[test]
	fn critical_cvss_score_maps_to_critical_severity() {
		let pkg = make_package("vulnerable-pkg", "1.0.0");
		let advisory = make_advisory(Some(9.5), SeverityLevel::Critical);
		let risk = RiskScorer::score(&pkg, vec![advisory], AnalysisResult::new("vulnerable-pkg", "1.0.0"));
		assert_eq!(risk.overall_severity, SeverityLevel::Critical);
	}

	#[test]
	fn high_confidence_pattern_with_no_advisory_raises_risk() {
		let pkg = make_package("suspicious-pkg", "1.0.0");
		let mut analysis = AnalysisResult::new("suspicious-pkg", "1.0.0");
		analysis.matches.push(make_detection(1.0, PatternType::CredentialHarvesting));
		let risk = RiskScorer::score(&pkg, vec![], analysis);
		assert!(risk.final_score > 0.0);
		assert!(!risk.is_safe());
	}

	#[test]
	fn advisory_with_patched_version_generates_upgrade_recommendation() {
		let pkg = make_package("pkg", "1.0.0");
		let advisory = make_advisory(Some(7.5), SeverityLevel::High);
		let risk = RiskScorer::score(&pkg, vec![advisory], AnalysisResult::new("pkg", "1.0.0"));
		assert!(risk.recommendations.iter().any(|r| r.contains("1.0.0")));
	}

	#[test]
	fn severity_label_returns_correct_strings() {
		let mut risk = RiskScorer::score(
			&make_package("p", "1.0"),
			vec![make_advisory(Some(9.5), SeverityLevel::Critical)],
			AnalysisResult::new("p", "1.0"),
		);
		risk.overall_severity = SeverityLevel::Critical;
		assert_eq!(risk.severity_label(), "CRITICAL");

		risk.overall_severity = SeverityLevel::Safe;
		assert_eq!(risk.severity_label(), "SAFE");
	}
}
