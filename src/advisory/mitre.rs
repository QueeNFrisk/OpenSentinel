use crate::database::models::PatternType;
use super::models::MitreData;

pub struct MitreMappingEngine;

impl MitreMappingEngine {
	pub fn map_pattern(pattern_type: &PatternType) -> Vec<MitreData> {
		match pattern_type {
			PatternType::CredentialHarvesting => vec![
				MitreData {
					technique_id: "T1552".to_string(),
					technique_name: "Unsecured Credentials".to_string(),
					tactic: "Credential Access".to_string(),
					url: "https://attack.mitre.org/techniques/T1552/".to_string(),
					description: "Adversaries may search compromised systems to find and obtain insecurely stored credentials.".to_string(),
				},
				MitreData {
					technique_id: "T1552.001".to_string(),
					technique_name: "Credentials In Files".to_string(),
					tactic: "Credential Access".to_string(),
					url: "https://attack.mitre.org/techniques/T1552/001/".to_string(),
					description: "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.".to_string(),
				},
			],

			PatternType::NetworkExfiltration => vec![
					MitreData {
						technique_id: "T1041".to_string(),
						technique_name: "Exfiltration Over C2 Channel".to_string(),
						tactic: "Exfiltration".to_string(),
						url: "https://attack.mitre.org/techniques/T1041/".to_string(),
						description: "Adversaries may steal data by exfiltrating it over an existing command and control channel.".to_string(),
				},
				MitreData {
					technique_id: "T1071.001".to_string(),
					technique_name: "Application Layer Protocol: Web Protocols".to_string(),
					tactic: "Command and Control".to_string(),
					url: "https://attack.mitre.org/techniques/T1071/001/".to_string(),
					description: "Adversaries may communicate using application layer protocols associated with web traffic.".to_string(),
				},
			],

			PatternType::CryptoMining => vec![
				MitreData {
					technique_id: "T1496".to_string(),
					technique_name: "Resource Hijacking".to_string(),
					tactic: "Impact".to_string(),
					url: "https://attack.mitre.org/techniques/T1496/".to_string(),
					description: "Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems such as cryptocurrency mining.".to_string(),
				},
			],

			PatternType::InstallHook => vec![
				MitreData {
					technique_id: "T1195.001".to_string(),
					technique_name: "Compromise Software Dependencies and Development Tools".to_string(),
					tactic: "Initial Access".to_string(),
					url: "https://attack.mitre.org/techniques/T1195/001/".to_string(),
					description: "Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise.".to_string(),
				},
			],

			PatternType::Typosquatting => vec![
				MitreData {
					technique_id: "T1195".to_string(),
					technique_name: "Supply Chain Compromise".to_string(),
					tactic: "Initial Access".to_string(),
					url: "https://attack.mitre.org/techniques/T1195/".to_string(),
					description: "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.".to_string(),
				},
			],

			PatternType::ObfuscatedCode => vec![
				MitreData {
					technique_id: "T1027".to_string(),
					technique_name: "Obfuscated Files or Information".to_string(),
					tactic: "Defense Evasion".to_string(),
					url: "https://attack.mitre.org/techniques/T1027/".to_string(),
					description: "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.".to_string(),
				},
			],

			PatternType::ReverseshellCode => vec![
				MitreData {
					technique_id: "T1059".to_string(),
					technique_name: "Command and Scripting Interpreter".to_string(),
					tactic: "Execution".to_string(),
					url: "https://attack.mitre.org/techniques/T1059/".to_string(),
					description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.".to_string(),
				},
				MitreData {
					technique_id: "T1105".to_string(),
					technique_name: "Ingress Tool Transfer".to_string(),
					tactic: "Command and Control".to_string(),
					url: "https://attack.mitre.org/techniques/T1105/".to_string(),
					description: "Adversaries may transfer tools or other files from an external system into a compromised environment.".to_string(),
				},
			],
		}
	}
}
