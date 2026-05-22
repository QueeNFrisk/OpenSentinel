use std::path::Path;
use tree_sitter::Parser;

use crate::analyzer::models::DetectionMatch;
use crate::database::models::PatternType;

pub struct BehavioralAstAnalyzer;

// ---------------------------------------------------------------------------
// Sensitive path segments that trigger FilesystemAccess when seen as call args
// ---------------------------------------------------------------------------
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/self",
    "/.ssh",
    "/.aws",
    "aws/credentials",
    "/var/log",
    "/boot/",
    "/sys/",
];

// ---------------------------------------------------------------------------
// Suspicious ports — IRC, leet ports, common reverse-shell ports
// ---------------------------------------------------------------------------
const SUSPICIOUS_PORTS: &[&str] = &["4444", "6667", "31337", "8888", "1337", "9001"];

// ---------------------------------------------------------------------------
// Shell executables that imply high-confidence system call intent
// ---------------------------------------------------------------------------
const SHELL_EXECUTABLES: &[&str] = &[
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/bin/dash",
    "cmd.exe",
    "powershell",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl BehavioralAstAnalyzer {
    pub fn analyze(source: &str, file_path: &str) -> Vec<DetectionMatch> {
        let ext = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());

        match ext.as_deref() {
            Some("js" | "mjs" | "cjs") => Self::analyze_javascript(source, file_path),
            Some("ts" | "mts" | "cts") => Self::analyze_typescript(source, file_path),
            Some("py") => Self::analyze_python(source, file_path),
            Some("go") => Self::analyze_go(source, file_path),
            _ => Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // JavaScript
    // -----------------------------------------------------------------------

    fn analyze_javascript(source: &str, file_path: &str) -> Vec<DetectionMatch> {
        let mut parser = Parser::new();
        if parser.set_language(&tree_sitter_javascript::language()).is_err() {
            return Vec::new();
        }
        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let mut findings = Vec::new();
        let root = tree.root_node();
        Self::walk_js(&root, source.as_bytes(), source, file_path, &mut findings);
        findings
    }

    fn analyze_typescript(source: &str, file_path: &str) -> Vec<DetectionMatch> {
        let mut parser = Parser::new();
        let lang = tree_sitter_typescript::language_typescript();
        if parser.set_language(&lang).is_err() {
            return Vec::new();
        }
        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let mut findings = Vec::new();
        let root = tree.root_node();
        Self::walk_js(&root, source.as_bytes(), source, file_path, &mut findings);
        findings
    }

    fn walk_js(
        node: &tree_sitter::Node,
        bytes: &[u8],
        source: &str,
        file_path: &str,
        findings: &mut Vec<DetectionMatch>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(m) = Self::check_js_call(node, bytes, source, file_path) {
                findings.push(m);
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::walk_js(&child, bytes, source, file_path, findings);
            }
        }
    }

    fn check_js_call(
        node: &tree_sitter::Node,
        bytes: &[u8],
        source: &str,
        file_path: &str,
    ) -> Option<DetectionMatch> {
        let func = node.child_by_field_name("function")?;
        let func_text = func.utf8_text(bytes).ok()?;
        let args = node.child_by_field_name("arguments")?;
        let args_text = args.utf8_text(bytes).ok()?.to_lowercase();
        let line = node.start_position().row as u32 + 1;
        let snippet = snippet(source, node);

        // --- FilesystemAccess ---
        let fs_fns = [
            "fs.readfile", "fs.readfilesync", "fs.open", "fs.opensync",
            "fs.createreadstream", "fs.writefile", "fs.writefilesync",
        ];
        let func_lower = func_text.to_lowercase();
        if fs_fns.iter().any(|f| func_lower.ends_with(f.trim_start_matches("fs."))) {
            if let Some(path) = SENSITIVE_PATHS.iter().find(|p| args_text.contains(*p)) {
                return Some(DetectionMatch {
                    pattern_type: PatternType::FilesystemAccess,
                    description: format!("AST: {func_text}() with sensitive path {path}"),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line),
                    code_snippet: Some(snippet),
                    confidence: 0.96,
                });
            }
        }

        // --- SystemCall: child_process ---
        let cp_fns = ["exec", "execsync", "execfile", "execfilesync", "spawn", "spawnsync"];
        if cp_fns.iter().any(|f| func_lower.ends_with(f)) {
            let confidence = if SHELL_EXECUTABLES.iter().any(|s| args_text.contains(*s)) {
                0.94
            } else {
                0.78
            };
            return Some(DetectionMatch {
                pattern_type: PatternType::SystemCall,
                description: format!("AST: shell execution via {func_text}()"),
                file_path: Some(file_path.to_string()),
                line_number: Some(line),
                code_snippet: Some(snippet),
                confidence,
            });
        }

        // --- NetworkConnection: net / http with suspicious ports ---
        let net_fns = [
            "net.createconnection", "net.connect", "http.request",
            "https.request", "http.get", "https.get",
        ];
        if net_fns.iter().any(|f| func_lower.contains(f)) {
            if let Some(port) = SUSPICIOUS_PORTS.iter().find(|p| args_text.contains(*p)) {
                return Some(DetectionMatch {
                    pattern_type: PatternType::NetworkConnection,
                    description: format!("AST: {func_text}() on suspicious port {port}"),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line),
                    code_snippet: Some(snippet),
                    confidence: 0.76,
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // Python
    // -----------------------------------------------------------------------

    fn analyze_python(source: &str, file_path: &str) -> Vec<DetectionMatch> {
        let mut parser = Parser::new();
        if parser.set_language(&tree_sitter_python::language()).is_err() {
            return Vec::new();
        }
        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let mut findings = Vec::new();
        let root = tree.root_node();
        Self::walk_python(&root, source.as_bytes(), source, file_path, &mut findings);
        findings
    }

    fn walk_python(
        node: &tree_sitter::Node,
        bytes: &[u8],
        source: &str,
        file_path: &str,
        findings: &mut Vec<DetectionMatch>,
    ) {
        if node.kind() == "call" {
            if let Some(m) = Self::check_python_call(node, bytes, source, file_path) {
                findings.push(m);
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::walk_python(&child, bytes, source, file_path, findings);
            }
        }
    }

    fn check_python_call(
        node: &tree_sitter::Node,
        bytes: &[u8],
        source: &str,
        file_path: &str,
    ) -> Option<DetectionMatch> {
        let func = node.child_by_field_name("function")?;
        let func_text = func.utf8_text(bytes).ok()?;
        let args = node.child_by_field_name("arguments")?;
        let args_text = args.utf8_text(bytes).ok()?.to_lowercase();
        let func_lower = func_text.to_lowercase();
        let line = node.start_position().row as u32 + 1;
        let snippet = snippet(source, node);

        // --- FilesystemAccess ---
        let fs_fns = ["open", "os.open", "os.read", "pathlib.path"];
        if fs_fns.iter().any(|f| func_lower == *f || func_lower.ends_with(f)) {
            if let Some(path) = SENSITIVE_PATHS.iter().find(|p| args_text.contains(*p)) {
                return Some(DetectionMatch {
                    pattern_type: PatternType::FilesystemAccess,
                    description: format!("AST: {func_text}() with sensitive path {path}"),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line),
                    code_snippet: Some(snippet),
                    confidence: 0.93,
                });
            }
        }

        // --- SystemCall ---
        let subprocess_fns = [
            "subprocess.run", "subprocess.popen", "subprocess.call",
            "subprocess.check_output", "subprocess.check_call",
        ];
        let os_exec_fns = ["os.system", "os.popen", "os.execv", "os.execve", "os.execvp"];

        if subprocess_fns.iter().any(|f| func_lower == *f) {
            let confidence = if args_text.contains("shell=true")
                || SHELL_EXECUTABLES.iter().any(|s| args_text.contains(*s))
            {
                0.90
            } else {
                0.78
            };
            return Some(DetectionMatch {
                pattern_type: PatternType::SystemCall,
                description: format!("AST: subprocess execution via {func_text}()"),
                file_path: Some(file_path.to_string()),
                line_number: Some(line),
                code_snippet: Some(snippet),
                confidence,
            });
        }

        if os_exec_fns.iter().any(|f| func_lower == *f) {
            let confidence = if SHELL_EXECUTABLES.iter().any(|s| args_text.contains(*s)) {
                0.93
            } else {
                0.84
            };
            return Some(DetectionMatch {
                pattern_type: PatternType::SystemCall,
                description: format!("AST: OS-level execution via {func_text}()"),
                file_path: Some(file_path.to_string()),
                line_number: Some(line),
                code_snippet: Some(snippet),
                confidence,
            });
        }

        // --- NetworkConnection ---
        if func_lower.ends_with("socket.connect") || func_lower == "socket.connect" {
            if let Some(port) = SUSPICIOUS_PORTS.iter().find(|p| args_text.contains(*p)) {
                return Some(DetectionMatch {
                    pattern_type: PatternType::NetworkConnection,
                    description: format!("AST: socket.connect() on suspicious port {port}"),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line),
                    code_snippet: Some(snippet),
                    confidence: 0.75,
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // Go
    // -----------------------------------------------------------------------

    fn analyze_go(source: &str, file_path: &str) -> Vec<DetectionMatch> {
        let mut parser = Parser::new();
        if parser.set_language(&tree_sitter_go::language()).is_err() {
            return Vec::new();
        }
        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Vec::new(),
        };
        let mut findings = Vec::new();
        let root = tree.root_node();
        Self::walk_go(&root, source.as_bytes(), source, file_path, &mut findings);
        findings
    }

    fn walk_go(
        node: &tree_sitter::Node,
        bytes: &[u8],
        source: &str,
        file_path: &str,
        findings: &mut Vec<DetectionMatch>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(m) = Self::check_go_call(node, bytes, source, file_path) {
                findings.push(m);
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::walk_go(&child, bytes, source, file_path, findings);
            }
        }
    }

    fn check_go_call(
        node: &tree_sitter::Node,
        bytes: &[u8],
        source: &str,
        file_path: &str,
    ) -> Option<DetectionMatch> {
        let func = node.child_by_field_name("function")?;
        let func_text = func.utf8_text(bytes).ok()?;
        let args = node.child_by_field_name("arguments")?;
        let args_text = args.utf8_text(bytes).ok()?.to_lowercase();
        let func_lower = func_text.to_lowercase();
        let line = node.start_position().row as u32 + 1;
        let snippet = snippet(source, node);

        // --- FilesystemAccess ---
        let fs_fns = ["os.open", "os.readfile", "ioutil.readfile", "os.openfile"];
        if fs_fns.iter().any(|f| func_lower == *f) {
            if let Some(path) = SENSITIVE_PATHS.iter().find(|p| args_text.contains(*p)) {
                return Some(DetectionMatch {
                    pattern_type: PatternType::FilesystemAccess,
                    description: format!("AST: {func_text}() with sensitive path {path}"),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line),
                    code_snippet: Some(snippet),
                    confidence: 0.93,
                });
            }
        }

        // --- SystemCall ---
        let exec_fns = ["exec.command", "exec.commandcontext"];
        if exec_fns.iter().any(|f| func_lower == *f) {
            let confidence = if SHELL_EXECUTABLES.iter().any(|s| args_text.contains(*s)) {
                0.93
            } else {
                0.72
            };
            return Some(DetectionMatch {
                pattern_type: PatternType::SystemCall,
                description: format!("AST: shell command execution via {func_text}()"),
                file_path: Some(file_path.to_string()),
                line_number: Some(line),
                code_snippet: Some(snippet),
                confidence,
            });
        }

        // --- NetworkConnection ---
        let net_fns = ["net.dial", "net.dialtcp", "net.dialudp", "net.dialunix"];
        if net_fns.iter().any(|f| func_lower == *f) {
            if let Some(port) = SUSPICIOUS_PORTS.iter().find(|p| args_text.contains(*p)) {
                return Some(DetectionMatch {
                    pattern_type: PatternType::NetworkConnection,
                    description: format!("AST: {func_text}() on suspicious port {port}"),
                    file_path: Some(file_path.to_string()),
                    line_number: Some(line),
                    code_snippet: Some(snippet),
                    confidence: 0.76,
                });
            }
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

fn snippet(source: &str, node: &tree_sitter::Node) -> String {
    let start = node.start_byte();
    let end = node.end_byte().min(start + 120);
    source.get(start..end).unwrap_or("").trim().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn has(findings: &[DetectionMatch], kind: &PatternType) -> bool {
        findings.iter().any(|f| &f.pattern_type == kind)
    }

    fn confidence_of(findings: &[DetectionMatch], kind: &PatternType) -> f32 {
        findings
            .iter()
            .filter(|f| &f.pattern_type == kind)
            .map(|f| f.confidence)
            .fold(0.0_f32, f32::max)
    }

    // JS / TS -----------------------------------------------------------------

    #[test]
    fn js_fs_readfilesync_etc_passwd() {
        let code = r#"const data = fs.readFileSync('/etc/passwd', 'utf8');"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "script.js");
        assert!(has(&findings, &PatternType::FilesystemAccess));
        assert!(confidence_of(&findings, &PatternType::FilesystemAccess) >= 0.90);
    }

    #[test]
    fn js_exec_bin_bash() {
        let code = r#"child_process.exec('/bin/bash -i');"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "run.js");
        assert!(has(&findings, &PatternType::SystemCall));
        assert!(confidence_of(&findings, &PatternType::SystemCall) >= 0.90);
    }

    #[test]
    fn js_spawn_generic_not_shell() {
        let code = r#"child_process.spawn('node', ['server.js']);"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "run.js");
        assert!(has(&findings, &PatternType::SystemCall));
        assert!(confidence_of(&findings, &PatternType::SystemCall) < 0.90);
    }

    #[test]
    fn js_net_create_connection_suspicious_port() {
        let code = r#"net.createConnection(4444, '10.0.0.1');"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "conn.js");
        assert!(has(&findings, &PatternType::NetworkConnection));
    }

    #[test]
    fn js_comment_is_ignored() {
        let code = r#"
// fs.readFileSync('/etc/passwd') — example in docs
const x = 1;
"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "docs.js");
        assert!(
            !has(&findings, &PatternType::FilesystemAccess),
            "comment triggered false positive"
        );
    }

    #[test]
    fn ts_readfilesync_etc_shadow() {
        let code = r#"const raw: string = fs.readFileSync('/etc/shadow', 'utf8');"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "reader.ts");
        assert!(has(&findings, &PatternType::FilesystemAccess));
    }

    // Python ------------------------------------------------------------------

    #[test]
    fn python_open_etc_passwd() {
        let code = r#"data = open('/etc/passwd', 'r').read()"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "spy.py");
        assert!(has(&findings, &PatternType::FilesystemAccess));
        assert!(confidence_of(&findings, &PatternType::FilesystemAccess) >= 0.90);
    }

    #[test]
    fn python_subprocess_run_shell_true() {
        let code = r#"subprocess.run('bash -i', shell=True)"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "exec.py");
        assert!(has(&findings, &PatternType::SystemCall));
        assert!(confidence_of(&findings, &PatternType::SystemCall) >= 0.88);
    }

    #[test]
    fn python_subprocess_run_generic() {
        let code = r#"subprocess.run(['pip', 'install', 'requests'])"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "setup.py");
        assert!(has(&findings, &PatternType::SystemCall));
        assert!(confidence_of(&findings, &PatternType::SystemCall) < 0.85);
    }

    #[test]
    fn python_os_system_bash() {
        let code = r#"os.system('/bin/bash -c "whoami"')"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "shell.py");
        assert!(has(&findings, &PatternType::SystemCall));
        assert!(confidence_of(&findings, &PatternType::SystemCall) >= 0.80);
    }

    #[test]
    fn python_comment_ignored() {
        let code = r#"
# open('/etc/passwd') — do not do this
result = open('config.json', 'r').read()
"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "docs.py");
        assert!(
            !has(&findings, &PatternType::FilesystemAccess),
            "comment or safe path triggered false positive"
        );
    }

    // Go ----------------------------------------------------------------------

    #[test]
    fn go_os_open_etc_passwd() {
        let code = r#"
package main
import "os"
func main() { f, _ := os.Open("/etc/passwd"); _ = f }
"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "main.go");
        assert!(has(&findings, &PatternType::FilesystemAccess));
        assert!(confidence_of(&findings, &PatternType::FilesystemAccess) >= 0.90);
    }

    #[test]
    fn go_exec_command_bin_bash() {
        let code = r#"
package main
import "os/exec"
func main() { cmd := exec.Command("/bin/bash", "-i"); _ = cmd }
"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "shell.go");
        assert!(has(&findings, &PatternType::SystemCall));
        assert!(confidence_of(&findings, &PatternType::SystemCall) >= 0.90);
    }

    #[test]
    fn go_net_dial_suspicious_port() {
        let code = r#"
package main
import "net"
func main() { conn, _ := net.Dial("tcp", "10.0.0.1:4444"); _ = conn }
"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "conn.go");
        assert!(has(&findings, &PatternType::NetworkConnection));
    }

    #[test]
    fn unknown_extension_returns_empty() {
        let code = r#"some content with /etc/passwd in it"#;
        let findings = BehavioralAstAnalyzer::analyze(code, "data.xml");
        assert!(findings.is_empty());
    }
}
