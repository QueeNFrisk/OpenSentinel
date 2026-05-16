use anyhow::Result;
use std::path::Path;

use super::models::DependencyTree;
use super::nodejs::NodejsParser;
use super::bun::BunParser;
use super::python::PythonParser;
use super::golang::GolangParser;
use super::rust_cargo::RustCargoParser;

pub struct DependencyResolver;

impl DependencyResolver {
	pub async fn resolve(project_path: &Path, ecosystems: &[String]) -> Result<Vec<DependencyTree>> {
		let mut trees = Vec::new();

		for ecosystem in ecosystems {
			match ecosystem.as_str() {
				"nodejs" => {
					if let Some(tree) = NodejsParser::detect_and_parse(project_path).await? {
						trees.push(tree);
					}
				}
				"bun" => {
					if let Some(tree) = BunParser::detect_and_parse(project_path).await? {
						trees.push(tree);
					}
				}
				"python" => {
					if let Some(tree) = PythonParser::detect_and_parse(project_path).await? {
						trees.push(tree);
					}
				}
				"golang" => {
					if let Some(tree) = GolangParser::detect_and_parse(project_path).await? {
						trees.push(tree);
					}
				}
				"rust" => {
					if let Some(tree) = RustCargoParser::detect_and_parse(project_path).await? {
						trees.push(tree);
					}
				}
				unknown => {
					tracing::warn!("unknown ecosystem: {unknown}");
				}
			}
		}

		Ok(trees)
	}
}
