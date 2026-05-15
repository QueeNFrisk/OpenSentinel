use anyhow::Result;
use std::fs;
use std::path::Path;
use crate::scoring::models::PackageRisk;
use super::Reporter;

pub struct JsonReporter;

impl Reporter for JsonReporter {
	fn generate(&self, risks: &[PackageRisk], output_path: Option<&Path>) -> Result<()> {
		let json = serde_json::to_string_pretty(risks)?;

		match output_path {
			Some(path) => fs::write(path, &json)?,
			None => println!("{json}"),
		}

		Ok(())
	}
}
