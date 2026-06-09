use std::fs;
use std::path::Path;
use crate::domain::threat::{Threat, ThreatLevel};
use crate::domain::rules::ThreatRule;

/// Returns true when content contains the structural invariants of a Caesar-shift
/// eval harness, regardless of the shift value (ROT-N for any N).
///
/// Every correct implementation of a Caesar cipher over a-z/A-Z **must** contain:
///   • `charCodeAt`  — read the character code
///   • `% 26`        — wrap around the 26-letter alphabet (impossible to omit)
///   • `fromCharCode`— reconstruct the shifted character
///
/// Combined with `eval(` (the execution wrapper), this signature is
/// shift-value-independent and cannot be trivially evaded without abandoning
/// the algorithm entirely.
fn has_caesar_shift_eval_harness(content: &str) -> bool {
    let has_structural_core =
        content.contains("charCodeAt")
        && content.contains("% 26")
        && content.contains("fromCharCode");

    let has_eval_wrapper = content.contains("eval(");

    // Require the core arithmetic AND the eval wrapper.
    // Either alone is too broad; together they are highly specific.
    has_structural_core && has_eval_wrapper
}

pub struct SetupJsRule;

impl ThreatRule for SetupJsRule {
    fn name(&self) -> &'static str {
        "Direct Dropper File check"
    }

    fn description(&self) -> &'static str {
        "Scanning for direct payloads and droppers (.github/setup.js)..."
    }

    fn check(&self, dir: &Path) -> Vec<Threat> {
        let mut threats = Vec::new();
        let setup_js_path = dir.join(".github/setup.js");
        if setup_js_path.exists() {
            let mut indicators: Vec<&str> = Vec::new();

            let file_size = fs::metadata(&setup_js_path).map(|m| m.len()).unwrap_or(0);
            if file_size > 500_000 {
                // The confirmed Miasma dropper is 4.3 MB — a one-liner JS file that large is
                // always suspicious.
                indicators.push("oversized file (>500 KB)");
            }

            if let Ok(content) = fs::read_to_string(&setup_js_path) {
                // Shift-value-agnostic detection: checks for the structural invariants
                // that every Caesar-shift eval harness must contain (charCodeAt + % 26 +
                // fromCharCode + eval), regardless of whether the shift is 4, 9, or any
                // other value.
                if has_caesar_shift_eval_harness(&content) {
                    indicators.push("Caesar-shift eval harness (shift-value-agnostic)");
                }
                // AES-128-GCM inner loader
                if content.contains("createDecipheriv") && content.contains("aes-128-gcm") {
                    indicators.push("AES-128-GCM decipher block");
                }
                // Bun runtime download (pinned release pulled from oven-sh/bun)
                if content.contains("oven-sh/bun") {
                    indicators.push("Bun runtime download (oven-sh/bun)");
                }
                // Payload written to /tmp/p<rand>.js then executed
                if content.contains("writeFileSync") && content.contains("/tmp/p") {
                    indicators.push("temp-file payload drop (/tmp/p*)");
                }
            }

            let description = if indicators.is_empty() {
                "Found '.github/setup.js' — the known Miasma Worm dropper path. \
                No specific signatures matched but the file location itself is the IOC.".to_string()
            } else {
                format!(
                    "Found '.github/setup.js' matching Miasma Worm IOCs: {}.",
                    indicators.join(", ")
                )
            };

            threats.push(Threat {
                file_path: setup_js_path,
                threat_type: "Miasma Dropper".to_string(),
                description,
                level: ThreatLevel::Critical,
            });
        }

        // Recursively check other js/ts files for same obfuscated eval signatures
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            if let Ok(entries) = fs::read_dir(current) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        // Skip node_modules or .git
                        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if name != "node_modules" && name != ".git" {
                            stack.push(path);
                        }
                    } else if path.is_file() {
                        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                            if ext == "js" || ext == "ts" {
                                if let Ok(content) = fs::read_to_string(&path) {
                                    if has_caesar_shift_eval_harness(&content) {
                                        threats.push(Threat {
                                            file_path: path.clone(),
                                            threat_type: "Obfuscated Caesar-Shift Loader".to_string(),
                                            description: "File contains the structural invariants of a Caesar-shift eval harness (charCodeAt + % 26 + fromCharCode + eval), \
                                                indicating a Miasma Worm-style loader. Detection is shift-value-agnostic.".to_string(),
                                            level: ThreatLevel::Critical,
                                        });
                                    } else if content.contains("oven-sh/bun") && (content.contains("createDecipheriv") || content.contains("writeFileSync")) {
                                        threats.push(Threat {
                                            file_path: path.clone(),
                                            threat_type: "Miasma Bun Loader Signature".to_string(),
                                            description: "File downloads and executes the Bun runtime from oven-sh/bun with a write/decrypt operation — matching the Shai-Hulud staged loader.".to_string(),
                                            level: ThreatLevel::Critical,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        threats
    }
}
