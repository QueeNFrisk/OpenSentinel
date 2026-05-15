pub mod json;
pub mod html;
pub mod sbom;
pub mod table;

pub use json::JsonReporter;
pub use html::HtmlReporter;
pub use sbom::SbomReporter;
pub use table::TableReporter;

use anyhow::Result;
use std::path::Path;
use crate::scoring::models::PackageRisk;

pub trait Reporter {
	fn generate(&self, risks: &[PackageRisk], output_path: Option<&Path>) -> Result<()>;
}
