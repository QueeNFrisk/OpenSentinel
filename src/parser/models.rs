use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPackage {
	pub name: String,
	pub version: String,
	pub ecosystem: String,
	pub registry_url: Option<String>,
	pub checksum: Option<String>,
	pub is_direct: bool,
	pub depth: u32,
	pub dependencies: Vec<String>,
	pub dev_dependencies: Vec<String>,
	pub install_scripts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyTree {
	pub root: String,
	pub ecosystem: String,
	pub packages: HashMap<String, ParsedPackage>,
	pub edges: Vec<DependencyEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
	pub parent: String,
	pub child: String,
	pub version_constraint: String,
	pub is_dev: bool,
	pub is_optional: bool,
}

impl DependencyTree {
	pub fn new(root: impl Into<String>, ecosystem: impl Into<String>) -> Self {
		Self {
			root: root.into(),
			ecosystem: ecosystem.into(),
			packages: HashMap::new(),
			edges: Vec::new(),
		}
	}

	pub fn add_package(&mut self, key: impl Into<String>, package: ParsedPackage) {
		self.packages.insert(key.into(), package);
	}

	pub fn add_edge(&mut self, edge: DependencyEdge) {
		self.edges.push(edge);
	}

	#[allow(dead_code)]
	pub fn direct_packages(&self) -> impl Iterator<Item = &ParsedPackage> {
		self.packages.values().filter(|p| p.is_direct)
	}

	#[allow(dead_code)]
	pub fn total_count(&self) -> usize {
		self.packages.len()
	}
}
