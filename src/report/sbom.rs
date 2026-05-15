use anyhow::{Context, Result};
use cyclonedx_bom::external_models::normalized_string::NormalizedString;
use cyclonedx_bom::models::bom::Bom;
use cyclonedx_bom::models::component::{Classification, Component, Components};
use cyclonedx_bom::models::metadata::Metadata;
use cyclonedx_bom::models::tool::{Tool, Tools};
use cyclonedx_bom::models::vulnerability::{Vulnerabilities, Vulnerability};
use cyclonedx_bom::models::vulnerability_rating::{
	Score, ScoreMethod, Severity, VulnerabilityRating, VulnerabilityRatings,
};
use cyclonedx_bom::external_models::uri::Uri;
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
