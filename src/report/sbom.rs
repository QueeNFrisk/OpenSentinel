use anyhow::{Context, Result};
use cyclonedx_bom::external_models::normalized_string::NormalizedString;
use cyclonedx_bom::external_models::uri::Uri;
use cyclonedx_bom::models::bom::Bom;
use cyclonedx_bom::models::component::{Classification, Component, Components};
use cyclonedx_bom::models::metadata::Metadata;
use cyclonedx_bom::models::tool::{Tool, Tools};
use cyclonedx_bom::models::vulnerability::{Vulnerabilities, Vulnerability};
use cyclonedx_bom::models::vulnerability_rating::{
	Score, ScoreMethod, Severity, VulnerabilityRating, VulnerabilityRatings,
};
use cyclonedx_bom::models::vulnerability_source::VulnerabilitySource;
use std::fs;
use std::path::Path;

use crate::database::models::SeverityLevel;
use crate::scoring::models::PackageRisk;
use super::Reporter;

pub struct SbomReporter;

impl Reporter for SbomReporter {
	fn generate(&self, risks: &[PackageRisk], output_path: Option<&Path>) -> Result<()> {
		let bom = Self::build_bom(risks);
		let output = Self::serialize(bom)?;

		match output_path {
			Some(path) => fs::write(path, &output)
				.with_context(|| format!("failed to write SBOM to {}", path.display()))?,
			None => println!("{output}"),
		}

		Ok(())
	}
}

impl SbomReporter {
	fn build_bom(risks: &[PackageRisk]) -> Bom {
		let mut bom = Bom::default();
		bom.metadata = Some(Self::build_metadata());
		bom.components = Some(Self::build_components(risks));
		bom.vulnerabilities = Some(Self::build_vulnerabilities(risks));
		bom
	}

	fn build_metadata() -> Metadata {
		let mut metadata = Metadata::default();
		metadata.tools = Some(Tools::List(vec![Tool {
			vendor: Some(NormalizedString::new("OpenSentinel")),
			name: Some(NormalizedString::new("OpenSentinel")),
			version: Some(NormalizedString::new("0.1.0")),
			..Default::default()
		}]));
		metadata
	}

	fn build_components(risks: &[PackageRisk]) -> Components {
		let components: Vec<Component> = risks
			.iter()
			.map(|risk| {
				let bom_ref = Some(format!("{}-{}", risk.package_name, risk.package_version));
				Component::new(
					Classification::Library,
					&risk.package_name,
					&risk.package_version,
					bom_ref,
				)
			})
			.collect();

		Components(components)
	}

	fn build_vulnerabilities(risks: &[PackageRisk]) -> Vulnerabilities {
		let vulns: Vec<Vulnerability> = risks
			.iter()
			.flat_map(|risk| {
				risk.advisories.iter().map(move |advisory| {
					let mut vuln = Vulnerability::new(Some(advisory.external_id.clone()));

					vuln.id = Some(NormalizedString::new(&advisory.external_id));

					vuln.vulnerability_source = Some(VulnerabilitySource {
						url: advisory.references.first().and_then(|s| Uri::try_from(s.clone()).ok()),
						name: Some(NormalizedString::new(Self::source_label(&advisory.source))),
					});

					let rating = VulnerabilityRating::new(
						advisory.cvss_score.and_then(Score::from_f32),
						Some(Self::map_severity(&advisory.severity)),
						Some(ScoreMethod::CVSSv3),
					);

					vuln.vulnerability_ratings = Some(VulnerabilityRatings(vec![rating]));
					vuln.description = Some(advisory.description.clone());

					vuln
				})
			})
			.collect();

		Vulnerabilities(vulns)
	}

	fn serialize(bom: Bom) -> Result<String> {
		let mut output = Vec::new();
		bom.output_as_json_v1_4(&mut output)
			.context("failed to serialize SBOM as CycloneDX JSON v1.4")?;
		String::from_utf8(output).context("SBOM output was not valid UTF-8")
	}

	fn map_severity(level: &SeverityLevel) -> Severity {
		match level {
			SeverityLevel::Critical => Severity::Critical,
			SeverityLevel::High => Severity::High,
			SeverityLevel::Medium => Severity::Medium,
			SeverityLevel::Low => Severity::Low,
			SeverityLevel::Safe => Severity::None,
		}
	}

	fn source_label(source: &crate::database::models::AdvisorySource) -> &'static str {
		match source {
			crate::database::models::AdvisorySource::Osv => "OSV",
			crate::database::models::AdvisorySource::Github => "GitHub",
			crate::database::models::AdvisorySource::Nvd => "NVD",
			crate::database::models::AdvisorySource::Mitre => "MITRE",
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::advisory::models::AdvisoryData;
	use crate::database::models::{AdvisorySource, SeverityLevel};
	use crate::scoring::models::PackageRisk;

	fn make_risk(name: &str, version: &str, advisories: Vec<AdvisoryData>) -> PackageRisk {
		PackageRisk {
			package_name: name.to_string(),
			package_version: version.to_string(),
			ecosystem: "nodejs".to_string(),
			overall_severity: if advisories.is_empty() { SeverityLevel::Safe } else { SeverityLevel::High },
			advisory_score: 0.0,
			pattern_score: 0.0,
			final_score: 0.0,
			advisories,
			detections: vec![],
			mitre_mappings: vec![],
			recommendations: vec![],
			is_direct: true,
			depth: 1,
		}
	}

	fn make_advisory(id: &str, cvss: f32) -> AdvisoryData {
		AdvisoryData {
			source: AdvisorySource::Osv,
			external_id: id.to_string(),
			title: "Test".to_string(),
			description: "desc".to_string(),
			severity: SeverityLevel::High,
			cvss_score: Some(cvss),
			affected_versions: "< 2.0.0".to_string(),
			patched_versions: Some("2.0.0".to_string()),
			published_at: None,
			references: vec!["https://example.com".to_string()],
		}
	}

	#[test]
	fn produces_valid_cyclonedx_json() {
		let risks = vec![make_risk("lodash", "4.17.20", vec![make_advisory("CVE-2021-23337", 9.1)])];
		let bom = SbomReporter::build_bom(&risks);
		let output = SbomReporter::serialize(bom).unwrap();
		let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
		assert_eq!(parsed["bomFormat"], "CycloneDX");
	}

	#[test]
	fn components_list_contains_all_packages() {
		let risks = vec![
			make_risk("lodash", "4.17.20", vec![]),
			make_risk("express", "4.18.0", vec![]),
		];
		let bom = SbomReporter::build_bom(&risks);
		let components = bom.components.unwrap();
		assert_eq!(components.0.len(), 2);
	}

	#[test]
	fn vulnerabilities_list_includes_all_advisories() {
		let risks = vec![
			make_risk("pkg-a", "1.0.0", vec![
				make_advisory("CVE-2024-0001", 7.5),
				make_advisory("CVE-2024-0002", 9.0),
			]),
		];
		let bom = SbomReporter::build_bom(&risks);
		let vulns = bom.vulnerabilities.unwrap();
		assert_eq!(vulns.0.len(), 2);
	}

	#[test]
	fn empty_risks_produces_empty_components_and_vulnerabilities() {
		let bom = SbomReporter::build_bom(&[]);
		assert_eq!(bom.components.unwrap().0.len(), 0);
		assert_eq!(bom.vulnerabilities.unwrap().0.len(), 0);
	}

	#[test]
	fn metadata_includes_opensentinel_tool() {
		let bom = SbomReporter::build_bom(&[]);
		let Tools::List(list) = bom.metadata.unwrap().tools.unwrap() else { panic!("expected list") };
		let names: Vec<&str> = list.iter()
			.filter_map(|t| t.name.as_ref().map(|n| n.as_ref()))
			.collect();
		assert!(names.contains(&"OpenSentinel"));
	}

	#[test]
	fn severity_maps_correctly() {
		assert!(matches!(SbomReporter::map_severity(&SeverityLevel::Critical), Severity::Critical));
		assert!(matches!(SbomReporter::map_severity(&SeverityLevel::High), Severity::High));
		assert!(matches!(SbomReporter::map_severity(&SeverityLevel::Medium), Severity::Medium));
		assert!(matches!(SbomReporter::map_severity(&SeverityLevel::Low), Severity::Low));
		assert!(matches!(SbomReporter::map_severity(&SeverityLevel::Safe), Severity::None));
	}

	#[test]
	fn generates_file_when_output_path_given() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("sbom.cdx.json");
		let risks = vec![make_risk("pkg", "1.0.0", vec![make_advisory("CVE-2024-0001", 7.5)])];
		SbomReporter.generate(&risks, Some(&path)).unwrap();
		let content = std::fs::read_to_string(&path).unwrap();
		assert!(content.contains("CycloneDX"));
	}
}
