use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

use crate::database::models::PatternType;
use super::ast::AstAnalyzer;
use super::models::DetectionMatch;
use super::patterns::{CREDENTIAL_PATTERNS, CRYPTO_PATTERNS, NETWORK_EXFIL_PATTERNS, OBFUSCATION_PATTERNS};

pub struct CredentialHarvestingDetector;

impl CredentialHarvestingDetector {
  pub async fn scan_directory(path: &Path) -> Result<Vec<DetectionMatch>> {
    Self::scan_directory_impl(path, false).await
  }

  pub async fn scan_directory_with_ast(path: &Path) -> Result<Vec<DetectionMatch>> {
    Self::scan_directory_impl(path, true).await
  }

  async fn scan_directory_impl(path: &Path, use_ast: bool) -> Result<Vec<DetectionMatch>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
      let mut matches = Vec::new();

      for entry in WalkDir::new(&path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| CredentialHarvestingDetector::is_scannable(e.path()))
      {
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
          matches.extend(CredentialHarvestingDetector::scan_content(&content, entry.path()));

          if use_ast && CredentialHarvestingDetector::is_js_file(entry.path()) {
            if let Ok(ast_findings) = AstAnalyzer::analyze_js(&content) {
              let entry_path = entry.path().to_path_buf();
              matches.extend(ast_findings.into_iter().map(|f| {
                CredentialHarvestingDetector::ast_finding_to_detection(f, &entry_path)
              }));
            }
          }
        }
      }

      Ok::<Vec<DetectionMatch>, anyhow::Error>(matches)
    })
    .await?
  }

  fn ast_finding_to_detection(finding: super::ast::AstFinding, file_path: &Path) -> DetectionMatch {
    let pattern_type = match finding.node_type.as_str() {
      "eval_call" | "eval_encoded" | "dynamic_require_obfuscated" => PatternType::ObfuscatedCode,
      "hardcoded_secret" | "env_access_in_call" => PatternType::CredentialHarvesting,
      _ => PatternType::ObfuscatedCode,
    };

    let confidence = match finding.node_type.as_str() {
      "eval_encoded" | "dynamic_require_obfuscated" => 0.92,
      "hardcoded_secret" => 0.88,
      "eval_call" => 0.7,
      _ => 0.6,
    };

    DetectionMatch {
      pattern_type,
      description: format!("AST: {}", finding.node_type.replace('_', " ")),
      file_path: Some(file_path.to_string_lossy().to_string()),
      line_number: Some(finding.line),
      code_snippet: Some(finding.value),
      confidence,
    }
  }

  fn is_js_file(path: &Path) -> bool {
    matches!(
      path.extension().and_then(|e| e.to_str()),
      Some("js" | "mjs" | "cjs" | "ts" | "mts" | "cts")
    )
  }

  fn scan_content(content: &str, file_path: &Path) -> Vec<DetectionMatch> {
    let mut matches = Vec::new();
    let path_str = file_path.to_string_lossy().to_string();

    for (line_num, line) in content.lines().enumerate() {
    for pattern in CREDENTIAL_PATTERNS.iter() {
      if pattern.regex.is_match(line) {
        matches.push(DetectionMatch {
          pattern_type: PatternType::CredentialHarvesting,
          description: pattern.name.clone(),
          file_path: Some(path_str.clone()),
          line_number: Some((line_num + 1) as u32),
          code_snippet: Some(line.trim().to_string()),
          confidence: pattern.confidence,
        });
      }
    }

    for pattern in CRYPTO_PATTERNS.iter() {
      if pattern.regex.is_match(line) {
        matches.push(DetectionMatch {
          pattern_type: PatternType::CryptoMining,
          description: pattern.name.clone(),
          file_path: Some(path_str.clone()),
          line_number: Some((line_num + 1) as u32),
          code_snippet: Some(line.trim().to_string()),
          confidence: pattern.confidence,
        });
      }
    }

    for pattern in NETWORK_EXFIL_PATTERNS.iter() {
      if pattern.regex.is_match(line) {
        matches.push(DetectionMatch {
          pattern_type: PatternType::NetworkExfiltration,
          description: pattern.name.clone(),
          file_path: Some(path_str.clone()),
          line_number: Some((line_num + 1) as u32),
          code_snippet: Some(line.trim().to_string()),
          confidence: pattern.confidence,
        });
      }
    }

    for pattern in OBFUSCATION_PATTERNS.iter() {
      if pattern.regex.is_match(line) {
        matches.push(DetectionMatch {
          pattern_type: PatternType::ObfuscatedCode,
          description: pattern.name.clone(),
          file_path: Some(path_str.clone()),
          line_number: Some((line_num + 1) as u32),
          code_snippet: Some(line.trim().to_string()),
          confidence: pattern.confidence,
        });
      }
    }
  }

  matches
  }

  fn is_scannable(path: &Path) -> bool {
    if !path.is_file() {
      return false;
    }

    let skip_dirs = ["node_modules", ".git", "dist", "build", ".cache"];
    for component in path.components() {
      let name = component.as_os_str().to_string_lossy();
      if skip_dirs.iter().any(|&d| name == d) {
        return false;
      }
    }

    matches!(
      path.extension().and_then(|e| e.to_str()),
      Some("js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "json")
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::Path;

  fn scan(code: &str) -> Vec<DetectionMatch> {
    CredentialHarvestingDetector::scan_content(code, Path::new("test.js"))
  }

  #[test]
  fn detects_hardcoded_api_key() {
    let code = r#"const secret = "mysupersecrettoken12345678";"#;
    let matches = scan(code);
    assert!(matches.iter().any(|m| m.pattern_type == PatternType::CredentialHarvesting));
  }

  #[test]
  fn detects_ssh_private_key() {
    let code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
    let matches = scan(code);
    assert!(matches.iter().any(|m| m.pattern_type == PatternType::CredentialHarvesting));
  }

  #[test]
  fn detects_aws_access_key() {
      let code = "const key = 'AKIAIOSFODNN7EXAMPLE';";
      let matches = scan(code);
      assert!(matches.iter().any(|m| m.pattern_type == PatternType::CredentialHarvesting));
  }

  #[test]
  fn detects_crypto_mining_pool() {
    let code = "connect('stratum+tcp://pool.minexmr.com:4444');";
    let matches = scan(code);
    assert!(matches.iter().any(|m| m.pattern_type == PatternType::CryptoMining));
  }

  #[test]
  fn detects_coinhive_miner() {
    let code = "CoinHive.Anonymous('site_key').start();";
    let matches = scan(code);
    assert!(matches.iter().any(|m| m.pattern_type == PatternType::CryptoMining));
  }

  #[test]
  fn detects_eval_with_encoded_string() {
    let code = "eval(Buffer.from('aGVsbG8=', 'base64').toString());";
    let matches = scan(code);
    assert!(matches.iter().any(|m| m.pattern_type == PatternType::ObfuscatedCode));
  }

  #[test]
  fn detects_dynamic_require_obfuscated() {
    let code = "require(Buffer.from('Li9tYWx3YXJl', 'base64').toString());";
    let matches = scan(code);
    assert!(matches.iter().any(|m| m.pattern_type == PatternType::ObfuscatedCode));
  }

  #[test]
  fn clean_code_returns_no_matches() {
    let code = "const x = 1 + 2; console.log(x);";
    let matches = scan(code);
    assert!(matches.is_empty());
  }

  #[test]
  fn match_includes_file_path_and_line_number() {
    let code = "const key = 'AKIAIOSFODNN7EXAMPLE';";
    let matches = scan(code);
    let m = &matches[0];
    assert!(m.file_path.is_some());
    assert_eq!(m.line_number, Some(1));
    assert!(m.code_snippet.is_some());
  }
}
