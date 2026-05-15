use anyhow::Result;
use std::path::Path;
use crate::scoring::models::PackageRisk;
use super::Reporter;

pub struct TableReporter;

impl Reporter for TableReporter {
	fn generate(&self, risks: &[PackageRisk], _output_path: Option<&Path>) -> Result<()> {
		let width = 80;
		let sep = "─".repeat(width);

		println!("┌{sep}┐");
		println!("│ {:<12} {:<20} {:<10} {:<32} │", "SEVERITY", "PACKAGE", "VERSION", "ISSUE");
		println!("├{sep}┤");

		for risk in risks {
			let issue = risk.advisories.first()
				.map(|a| a.external_id.as_str())
				.or_else(|| risk.detections.first().map(|d| d.description.as_str()))
				.unwrap_or("none");

			println!(
				"│ {:<12} {:<20} {:<10} {:<32} │",
				risk.severity_label(),
				&risk.package_name[..risk.package_name.len().min(20)],
				&risk.package_version[..risk.package_version.len().min(10)],
				&issue[..issue.len().min(32)],
			);
		}

		println!("└{sep}┘");

		Ok(())
	}
}
