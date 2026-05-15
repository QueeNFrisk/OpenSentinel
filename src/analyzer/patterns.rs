#![allow(dead_code)]
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
	pub static ref CREDENTIAL_PATTERNS: Vec<CredentialPattern> = vec![
		CredentialPattern {
			name: "environment variable access".to_string(),
			regex: Regex::new(r#"process\.env\[?["']?(API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY)["']?\]?"#).unwrap(),
			confidence: 0.6,
		},
		CredentialPattern {
			name: "hardcoded secret pattern".to_string(),
			regex: Regex::new(r#"(api_key|apikey|secret|token|password)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]"#).unwrap(),
			confidence: 0.85,
		},
		CredentialPattern {
			name: "SSH private key".to_string(),
			regex: Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
			confidence: 0.99,
		},
		CredentialPattern {
			name: "AWS access key".to_string(),
			regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
			confidence: 0.95,
		},
		CredentialPattern {
			name: "credential exfiltration via HTTP".to_string(),
			regex: Regex::new(r"(fetch|axios|http\.get|http\.post|request)\s*\([^)]*process\.env").unwrap(),
			confidence: 0.9,
		},
	];

	pub static ref CRYPTO_PATTERNS: Vec<CryptoPattern> = vec![
		CryptoPattern {
			name: "crypto mining pool connection".to_string(),
			regex: Regex::new(r"(stratum\+tcp|stratum2\+tcp|pool\.minexmr|xmr\.pool|crypto-pool)").unwrap(),
			confidence: 0.98,
		},
		CryptoPattern {
			name: "coinhive or similar miner".to_string(),
			regex: Regex::new(r"(coinhive|cryptonight|monero|CoinHive\.Anonymous)").unwrap(),
			confidence: 0.9,
		},
		CryptoPattern {
			name: "worker thread crypto mining".to_string(),
			regex: Regex::new(r"new Worker.*hash|worker.*mine|startMining").unwrap(),
			confidence: 0.75,
		},
	];

	pub static ref NETWORK_EXFIL_PATTERNS: Vec<NetworkPattern> = vec![
		NetworkPattern {
			name: "data POST to external domain".to_string(),
			regex: Regex::new(r#"(axios\.post|fetch\s*\([^)]*method\s*:\s*["']POST|http\.request\s*\([^)]*method\s*:\s*["']POST)\s*[^)]*https?://"#).unwrap(),
			confidence: 0.7,
		},
		NetworkPattern {
			name: "DNS exfiltration pattern".to_string(),
			regex: Regex::new(r"dns\.lookup|dns\.resolve.*\+.*process\.env").unwrap(),
			confidence: 0.85,
		},
		NetworkPattern {
			name: "base64 encoded network payload".to_string(),
			regex: Regex::new(r#"Buffer\.from\([^)]+\)\.toString\(["'](base64|hex)["']"#).unwrap(),
			confidence: 0.65,
		},
	];

	pub static ref OBFUSCATION_PATTERNS: Vec<ObfuscationPattern> = vec![
		ObfuscationPattern {
			name: "eval with encoded string".to_string(),
			regex: Regex::new(r"eval\s*\(\s*(?:Buffer\.from|atob|unescape)\s*\(").unwrap(),
			confidence: 0.95,
		},
		ObfuscationPattern {
			name: "hex encoded eval".to_string(),
			regex: Regex::new(r#"eval\s*\(\s*["']\\x[0-9a-fA-F]{2}"#).unwrap(),
			confidence: 0.98,
		},
		ObfuscationPattern {
			name: "dynamic require of obfuscated module".to_string(),
			regex: Regex::new(r"require\s*\(\s*(?:Buffer\.from|atob|String\.fromCharCode)\s*\(").unwrap(),
			confidence: 0.92,
		},
	];
}

pub struct CredentialPattern {
	pub name: String,
	pub regex: Regex,
	pub confidence: f32,
}

pub struct CryptoPattern {
	pub name: String,
	pub regex: Regex,
	pub confidence: f32,
}

pub struct NetworkPattern {
	pub name: String,
	pub regex: Regex,
	pub confidence: f32,
}

pub struct ObfuscationPattern {
	pub name: String,
	pub regex: Regex,
	pub confidence: f32,
}
