use anyhow::Result;
use tree_sitter::Parser;

pub struct AstAnalyzer;

impl AstAnalyzer {
	pub fn analyze_js(source: &str) -> Result<Vec<AstFinding>> {
		let mut parser = Parser::new();
		let language = tree_sitter_javascript::language();
		parser.set_language(&language)?;

		let tree = match parser.parse(source, None) {
			Some(t) => t,
			None => return Ok(Vec::new()),
		};

		let mut findings = Vec::new();
		let root = tree.root_node();
		let bytes = source.as_bytes();

		Self::walk(&root, bytes, source, &mut findings);

		Ok(findings)
	}

	fn walk(
		node: &tree_sitter::Node,
		source_bytes: &[u8],
		source: &str,
		findings: &mut Vec<AstFinding>,
	) {
		let kind = node.kind();

		match kind {
			"call_expression" => {
				if let Some(finding) = Self::check_call(node, source_bytes, source) {
					findings.push(finding);
				}
			}
			"assignment_expression" | "variable_declarator" => {
				if let Some(finding) = Self::check_assignment(node, source_bytes, source) {
					findings.push(finding);
				}
			}
			_ => {}
		}

		for i in 0..node.child_count() {
			if let Some(child) = node.child(i) {
				Self::walk(&child, source_bytes, source, findings);
			}
		}
	}

	fn check_call(
		node: &tree_sitter::Node,
		source_bytes: &[u8],
		source: &str,
	) -> Option<AstFinding> {
		let func_node = node.child_by_field_name("function")?;
		let func_text = func_node.utf8_text(source_bytes).ok()?;

		let start = node.start_position();

		if func_text == "eval" {
			let args = node.child_by_field_name("arguments")?;
			let args_text = args.utf8_text(source_bytes).ok()?;

			if args_text.contains("Buffer.from")
				|| args_text.contains("atob")
				|| args_text.contains("unescape")
				|| args_text.contains("fromCharCode")
			{
				return Some(AstFinding {
					node_type: "eval_encoded".to_string(),
					value: Self::snippet(source, node),
					line: start.row as u32 + 1,
					column: start.column as u32,
				});
			}

			return Some(AstFinding {
				node_type: "eval_call".to_string(),
				value: Self::snippet(source, node),
				line: start.row as u32 + 1,
				column: start.column as u32,
			});
		}

		if func_text == "require" {
			let args = node.child_by_field_name("arguments")?;
			let args_text = args.utf8_text(source_bytes).ok()?;

			if args_text.contains("Buffer.from") || args_text.contains("fromCharCode") {
				return Some(AstFinding {
					node_type: "dynamic_require_obfuscated".to_string(),
					value: Self::snippet(source, node),
					line: start.row as u32 + 1,
					column: start.column as u32,
				});
			}
		}

		if func_text.contains("process.env") || func_text.ends_with(".env") {
			return Some(AstFinding {
				node_type: "env_access_in_call".to_string(),
				value: Self::snippet(source, node),
				line: start.row as u32 + 1,
				column: start.column as u32,
			});
		}

		None
	}

	fn check_assignment(
		node: &tree_sitter::Node,
		source_bytes: &[u8],
		source: &str,
	) -> Option<AstFinding> {
		let value_node = node.child_by_field_name("value")?;
		let value_text = value_node.utf8_text(source_bytes).ok()?;
		let start = node.start_position();

		let secret_patterns = [
			"AKIA",
			"-----BEGIN",
			"sk-",
			"ghp_",
			"github_pat_",
		];

		for pattern in &secret_patterns {
			if value_text.contains(pattern) {
				return Some(AstFinding {
					node_type: "hardcoded_secret".to_string(),
					value: Self::snippet(source, node),
					line: start.row as u32 + 1,
					column: start.column as u32,
				});
			}
		}

		None
	}

	fn snippet(source: &str, node: &tree_sitter::Node) -> String {
		let start = node.start_byte();
		let end = node.end_byte().min(start + 120);
		source.get(start..end).unwrap_or("").trim().to_string()
	}
}

#[derive(Debug, Clone)]
pub struct AstFinding {
	pub node_type: String,
	pub value: String,
	pub line: u32,
	#[allow(dead_code)]
	pub column: u32,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn detects_plain_eval_call() {
		let code = r#"eval(userInput);"#;
		let findings = AstAnalyzer::analyze_js(code).unwrap();
		assert!(findings.iter().any(|f| f.node_type == "eval_call"));
	}

	#[test]
	fn detects_eval_with_buffer_from() {
		let code = r#"eval(Buffer.from('aGVsbG8=', 'base64').toString());"#;
		let findings = AstAnalyzer::analyze_js(code).unwrap();
		assert!(findings.iter().any(|f| f.node_type == "eval_encoded"));
	}

	#[test]
	fn detects_dynamic_require_obfuscated() {
		let code = r#"require(Buffer.from('Li9tYWx3YXJl', 'base64').toString());"#;
		let findings = AstAnalyzer::analyze_js(code).unwrap();
		assert!(findings.iter().any(|f| f.node_type == "dynamic_require_obfuscated"));
	}

	#[test]
	fn detects_hardcoded_aws_key() {
		let code = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
		let findings = AstAnalyzer::analyze_js(code).unwrap();
		assert!(findings.iter().any(|f| f.node_type == "hardcoded_secret"));
	}

	#[test]
	fn clean_code_returns_no_findings() {
		let code = r#"const x = 1 + 2; console.log(x);"#;
		let findings = AstAnalyzer::analyze_js(code).unwrap();
		assert!(findings.is_empty());
	}

	#[test]
	fn finding_has_correct_line_number() {
		let code = "const x = 1;\neval(bad);";
		let findings = AstAnalyzer::analyze_js(code).unwrap();
		let eval_finding = findings.iter().find(|f| f.node_type == "eval_call").unwrap();
		assert_eq!(eval_finding.line, 2);
	}
}
