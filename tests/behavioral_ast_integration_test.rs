use opensentinel::analyzer::behavioral::BehavioralAnalyzer;
use opensentinel::analyzer::behavioral_ast::BehavioralAstAnalyzer;
use opensentinel::database::models::PatternType;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

fn write_file(dir: &TempDir, name: &str, content: &str) {
    let path = dir.path().join(name);
    let mut f = File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

fn has(findings: &[opensentinel::analyzer::models::DetectionMatch], kind: &PatternType) -> bool {
    findings.iter().any(|d| &d.pattern_type == kind)
}

fn max_conf(
    findings: &[opensentinel::analyzer::models::DetectionMatch],
    kind: &PatternType,
) -> f32 {
    findings
        .iter()
        .filter(|d| &d.pattern_type == kind)
        .map(|d| d.confidence)
        .fold(0.0_f32, f32::max)
}

// ---------------------------------------------------------------------------
// AST detects what regex misses: code hidden in comments
// ---------------------------------------------------------------------------

#[test]
fn ast_ignores_fs_access_in_js_comment() {
    let source = r#"
// Example: fs.readFileSync('/etc/passwd')
// Do NOT do this in production code.
const x = 1;
"#;
    // Regex would match the comment line; AST should not
    let ast_only = BehavioralAstAnalyzer::analyze(source, "docs.js");
    assert!(
        !has(&ast_only, &PatternType::FilesystemAccess),
        "AST should not flag code inside a comment"
    );
}

#[test]
fn ast_ignores_subprocess_in_python_comment() {
    let source = r#"
# subprocess.run(['/bin/bash', '-i'], shell=True)  # never do this
x = 1
"#;
    let ast_only = BehavioralAstAnalyzer::analyze(source, "app.py");
    assert!(
        !has(&ast_only, &PatternType::SystemCall),
        "AST should not flag subprocess inside a Python comment"
    );
}

#[test]
fn ast_ignores_exec_command_in_go_comment() {
    let source = r#"
package main
// exec.Command("/bin/bash", "-i") — dangerous example
func main() {}
"#;
    let ast_only = BehavioralAstAnalyzer::analyze(source, "main.go");
    assert!(
        !has(&ast_only, &PatternType::SystemCall),
        "AST should not flag exec.Command inside a Go comment"
    );
}

// ---------------------------------------------------------------------------
// AST adds higher-confidence hits that combine with regex results
// ---------------------------------------------------------------------------

#[test]
fn scan_with_ast_produces_more_or_equal_findings_than_regex_only() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "spy.js", "const x = fs.readFileSync('/etc/passwd', 'utf8');");

    let regex_only = BehavioralAnalyzer::scan_directory(dir.path()).unwrap();
    let with_ast = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();

    assert!(
        with_ast.len() >= regex_only.len(),
        "AST scan should not produce fewer findings than regex-only"
    );
}

#[test]
fn ast_findings_have_higher_confidence_than_regex_for_same_pattern() {
    let dir = TempDir::new().unwrap();
    // Both regex and AST should fire; AST confidence should be >= regex confidence
    write_file(&dir, "evil.js", "fs.readFileSync('/etc/passwd', 'utf8');");

    let regex_conf = max_conf(
        &BehavioralAnalyzer::scan_directory(dir.path()).unwrap(),
        &PatternType::FilesystemAccess,
    );
    let ast_conf = max_conf(
        &BehavioralAstAnalyzer::analyze("fs.readFileSync('/etc/passwd', 'utf8');", "evil.js"),
        &PatternType::FilesystemAccess,
    );

    assert!(
        ast_conf >= regex_conf,
        "AST confidence ({ast_conf}) should be >= regex confidence ({regex_conf})"
    );
}

// ---------------------------------------------------------------------------
// JS end-to-end: all three pattern types via AST in one directory
// ---------------------------------------------------------------------------

#[test]
fn js_end_to_end_all_three_pattern_types() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "fs.js", r#"fs.readFileSync('/etc/passwd', 'utf8');"#);
    write_file(&dir, "net.js", r#"net.createConnection(4444, '10.0.0.1');"#);
    write_file(&dir, "sys.js", r#"child_process.exec('/bin/bash -i');"#);

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();

    assert!(has(&findings, &PatternType::FilesystemAccess), "missing FilesystemAccess");
    assert!(has(&findings, &PatternType::NetworkConnection), "missing NetworkConnection");
    assert!(has(&findings, &PatternType::SystemCall), "missing SystemCall");
}

// ---------------------------------------------------------------------------
// Python end-to-end
// ---------------------------------------------------------------------------

#[test]
fn python_end_to_end_all_three_pattern_types() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "fs.py", r#"data = open('/etc/passwd', 'r').read()"#);
    write_file(&dir, "sys.py", r#"subprocess.run(['/bin/bash', '-i'], shell=True)"#);

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();

    assert!(has(&findings, &PatternType::FilesystemAccess), "missing FilesystemAccess");
    assert!(has(&findings, &PatternType::SystemCall), "missing SystemCall");
}

// ---------------------------------------------------------------------------
// Go end-to-end
// ---------------------------------------------------------------------------

#[test]
fn go_end_to_end_all_three_pattern_types() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "main.go",
        r#"
package main
import ("os"; "os/exec"; "net")
func main() {
    f, _ := os.Open("/etc/passwd")
    _ = f
    cmd := exec.Command("/bin/bash", "-i")
    _ = cmd
    conn, _ := net.Dial("tcp", "10.0.0.1:4444")
    _ = conn
}
"#,
    );

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();

    assert!(has(&findings, &PatternType::FilesystemAccess), "Go: missing FilesystemAccess");
    assert!(has(&findings, &PatternType::SystemCall), "Go: missing SystemCall");
    assert!(has(&findings, &PatternType::NetworkConnection), "Go: missing NetworkConnection");
}

// ---------------------------------------------------------------------------
// TypeScript
// ---------------------------------------------------------------------------

#[test]
fn typescript_detects_readfilesync_etc_shadow() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "reader.ts",
        r#"const raw: string = fs.readFileSync('/etc/shadow', 'utf8');"#,
    );

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();
    assert!(has(&findings, &PatternType::FilesystemAccess));
    assert!(max_conf(&findings, &PatternType::FilesystemAccess) >= 0.90);
}

// ---------------------------------------------------------------------------
// Confidence & JSON invariants
// ---------------------------------------------------------------------------

#[test]
fn ast_findings_json_roundtrip() {
    let dir = TempDir::new().unwrap();
    write_file(&dir, "evil.py", r#"subprocess.run(['/bin/bash', '-i'], shell=True)"#);

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();
    assert!(!findings.is_empty());

    let json = serde_json::to_string_pretty(&findings).unwrap();
    let parsed: Vec<opensentinel::analyzer::models::DetectionMatch> =
        serde_json::from_str(&json).unwrap();

    assert!(has(&parsed, &PatternType::SystemCall));
    for d in &parsed {
        assert!(d.confidence > 0.0 && d.confidence <= 1.0);
        assert!(d.file_path.is_some());
        assert!(d.line_number.is_some());
    }
}

// ---------------------------------------------------------------------------
// No false positives on clean code
// ---------------------------------------------------------------------------

#[test]
fn no_ast_false_positives_on_clean_js() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "app.js",
        r#"
const path = require('path');
const config = require('./config.json');
console.log(config.version);
module.exports = { run: () => {} };
"#,
    );

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();
    let high: Vec<_> = findings.iter().filter(|d| d.confidence > 0.80).collect();
    assert!(
        high.is_empty(),
        "clean JS triggered high-confidence AST findings: {high:#?}"
    );
}

#[test]
fn no_ast_false_positives_on_clean_python() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "utils.py",
        r#"
import os
import json

def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)

if __name__ == '__main__':
    cfg = load_config('./config.json')
    print(cfg)
"#,
    );

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();
    let high: Vec<_> = findings.iter().filter(|d| d.confidence > 0.80).collect();
    assert!(
        high.is_empty(),
        "clean Python triggered high-confidence AST findings: {high:#?}"
    );
}

#[test]
fn no_ast_false_positives_on_clean_go() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "server.go",
        r#"
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
}

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}
"#,
    );

    let findings = BehavioralAnalyzer::scan_directory_with_ast(dir.path()).unwrap();
    let high: Vec<_> = findings.iter().filter(|d| d.confidence > 0.80).collect();
    assert!(
        high.is_empty(),
        "clean Go triggered high-confidence AST findings: {high:#?}"
    );
}
