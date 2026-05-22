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

	pub static ref FILESYSTEM_PATTERNS: Vec<FilesystemPattern> = vec![
		FilesystemPattern {
			name: "read /etc/passwd".to_string(),
			regex: Regex::new(r#"[/"']/etc/passwd["')?]?"#).unwrap(),
			confidence: 0.95,
		},
		FilesystemPattern {
			name: "read /etc/shadow".to_string(),
			regex: Regex::new(r#"[/"']/etc/shadow["')?]?"#).unwrap(),
			confidence: 0.95,
		},
		FilesystemPattern {
			name: "read /proc/self or process info".to_string(),
			regex: Regex::new(r#"/proc/self|/proc/[0-9]+/(environ|cmdline|maps|status)"#).unwrap(),
			confidence: 0.95,
		},
		FilesystemPattern {
			name: "access SSH directory".to_string(),
			regex: Regex::new(r#"~?/?\.ssh|~/?\.aws|aws/credentials"#).unwrap(),
			confidence: 0.90,
		},
		FilesystemPattern {
			name: "write to system directories".to_string(),
			regex: Regex::new(r#"writeFile\s*\([^)]*[/"']/(?:etc|boot|sys|lib)[/"')?]"#).unwrap(),
			confidence: 0.90,
		},
		FilesystemPattern {
			name: "hidden file creation".to_string(),
			regex: Regex::new(r#"writeFile|mkdir\s*\([^)]*[/"']\.[\w]|^\s*\.[a-z]"#).unwrap(),
			confidence: 0.75,
		},
		FilesystemPattern {
			name: "temporary file in /tmp with shell script".to_string(),
			regex: Regex::new(r#"/tmp/[^/"]*\.sh|writeFile\s*\([^)]*'/tmp/"#).unwrap(),
			confidence: 0.85,
		},
		FilesystemPattern {
			name: ".env or config file access".to_string(),
			regex: Regex::new(r#"\.env|config\.json|credentials\.\w+|secret\."#).unwrap(),
			confidence: 0.70,
		},
	];

	pub static ref NETWORK_CONN_PATTERNS: Vec<NetworkConnPattern> = vec![
		NetworkConnPattern {
			name: "reverse shell via bash".to_string(),
			regex: Regex::new(r#"bash\s+-i\s*>?&?\s*/dev/tcp/|bash -i >&|sh -i >&"#).unwrap(),
			confidence: 0.98,
		},
		NetworkConnPattern {
			name: "netcat reverse shell".to_string(),
			regex: Regex::new(r"nc\s+-e\s+/bin/|ncat\s+-e\s+/bin/|nc\s+.*-p.*bash").unwrap(),
			confidence: 0.98,
		},
		NetworkConnPattern {
			name: "socket creation or connection".to_string(),
			regex: Regex::new(r#"socket\s*\(|inet_aton|gethostbyname|connect\s*\([^)]*"#).unwrap(),
			confidence: 0.70,
		},
		NetworkConnPattern {
			name: "DNS lookup or resolution".to_string(),
			regex: Regex::new(r"dns\.lookup|dns\.resolve|getaddrinfo|nslookup").unwrap(),
			confidence: 0.65,
		},
		NetworkConnPattern {
			name: "hardcoded IP address".to_string(),
			regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
			confidence: 0.50,
		},
		NetworkConnPattern {
			name: "suspicious port (IRC, leet ports)".to_string(),
			regex: Regex::new(r"[:][6667]|[:][4444]|[:][8888]|[:][31337]").unwrap(),
			confidence: 0.65,
		},
	];

	pub static ref SYSCALL_PATTERNS: Vec<SyscallPattern> = vec![
		SyscallPattern {
			name: "execve with /bin/bash".to_string(),
			regex: Regex::new(r#"execve\s*\([^)]*[/"']/bin/bash|spawn\s*\([^)]*[/"']/bin/bash|exec\s*\([^)]*bash"#).unwrap(),
			confidence: 0.95,
		},
		SyscallPattern {
			name: "shell invocation via spawn/exec".to_string(),
			regex: Regex::new(r"spawn.*shell|execFile.*sh|child_process\.exec|popen\s*\(").unwrap(),
			confidence: 0.75,
		},
		SyscallPattern {
			name: "privilege escalation via sudo".to_string(),
			regex: Regex::new(r"sudo\s+-S|sudo\s+chmod|chmod\s+[0-7]{4}.*[0-7]{4}|setuid|setgid").unwrap(),
			confidence: 0.88,
		},
		SyscallPattern {
			name: "process tracing or manipulation".to_string(),
			regex: Regex::new(r"ptrace|process\.kill|proc\.terminate|/proc/\d+/mem").unwrap(),
			confidence: 0.92,
		},
		SyscallPattern {
			name: "fork or clone syscall".to_string(),
			regex: Regex::new(r"\bfork\s*\(|\bclone\s*\(|\bfork\s*\(\s*\)").unwrap(),
			confidence: 0.70,
		},
		SyscallPattern {
			name: "LD_PRELOAD or library path injection".to_string(),
			regex: Regex::new(r"LD_PRELOAD|LD_LIBRARY_PATH").unwrap(),
			confidence: 0.90,
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

pub struct FilesystemPattern {
	pub name: String,
	pub regex: Regex,
	pub confidence: f32,
}

pub struct NetworkConnPattern {
	pub name: String,
	pub regex: Regex,
	pub confidence: f32,
}

pub struct SyscallPattern {
	pub name: String,
	pub regex: Regex,
	pub confidence: f32,
}
