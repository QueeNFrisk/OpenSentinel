use crate::database::models::PatternType;
use crate::parser::models::ParsedPackage;
use super::models::DetectionMatch;

const SUSPICIOUS_COMMANDS: &[&str] = &[
	"curl ", "wget ", "nc ", "netcat ", "bash -i", "sh -i",
	"python -c", "perl -e", "ruby -e", "node -e",
	"/bin/sh", "/bin/bash", "exec(",
	"base64 -d", "base64 --decode",
	"chmod +x", "chmod 777",
];

pub struct InstallHookAnalyzer;

impl InstallHookAnalyzer {
	pub fn analyze(package: &ParsedPackage) -> Vec<DetectionMatch> {
		package
			.install_scripts
			.iter()
			.filter_map(|script| Self::check_script(script))
			.collect()
	}

	fn check_script(script: &str) -> Option<DetectionMatch> {
		let lower = script.to_lowercase();

		for cmd in SUSPICIOUS_COMMANDS {
			if lower.contains(cmd) {
				return Some(DetectionMatch {
					pattern_type: PatternType::InstallHook,
					description: format!("install script contains suspicious command: {cmd}"),
					file_path: Some("package.json".to_string()),
					line_number: None,
					code_snippet: Some(script.chars().take(120).collect()),
					confidence: 0.85,
				});
			}
		}

		None
	}
}
