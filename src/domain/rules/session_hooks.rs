use std::fs;
use std::path::Path;
use serde_json::Value;
use crate::domain::threat::{Threat, ThreatLevel};
use crate::domain::rules::ThreatRule;

pub struct SessionStartHooksRule;

impl ThreatRule for SessionStartHooksRule {
    fn name(&self) -> &'static str {
        "AI Agent session start hooks"
    }

    fn description(&self) -> &'static str {
        "Checking agent session start hooks (.claude & .gemini)..."
    }

    fn check(&self, dir: &Path) -> Vec<Threat> {
        let mut threats = Vec::new();
        let mut claude_cmds: Vec<String> = Vec::new();
        let mut gemini_cmds: Vec<String> = Vec::new();

        self.check_file(dir, ".claude/settings.json", "Claude", &mut threats, &mut claude_cmds);
        self.check_file(dir, ".gemini/settings.json", "Gemini CLI", &mut threats, &mut gemini_cmds);

        // Cross-correlation: both files carrying the exact same hook command is the
        // byte-identical Miasma footprint (worm copies the same config to every agent).
        if !claude_cmds.is_empty() && claude_cmds == gemini_cmds {
            threats.push(Threat {
                file_path: dir.to_path_buf(),
                threat_type: "Miasma Multi-Agent Hook Correlation".to_string(),
                description: format!(
                    "Both .claude/settings.json and .gemini/settings.json have identical \
                    SessionStart hook command(s): {:?}. Byte-identical configs across multiple AI \
                    agents is the exact fingerprint of the Miasma Worm source-repo injection campaign.",
                    claude_cmds
                ),
                level: ThreatLevel::Critical,
            });
        }

        threats
    }
}

impl SessionStartHooksRule {
    fn check_file(&self, dir: &Path, rel_path: &str, tool_name: &str, threats: &mut Vec<Threat>, found_commands: &mut Vec<String>) {
        let settings_path = dir.join(rel_path);
        if settings_path.exists() {
            if let Ok(content) = fs::read_to_string(&settings_path) {
                if let Ok(json) = serde_json::from_str::<Value>(&content) {
                    if let Some(hooks) = json.get("hooks") {
                        if let Some(session_start) = hooks.get("SessionStart") {
                            let mut has_command_hook = false;
                            let mut hook_commands = Vec::new();

                            // Try parsing array of matchers/hooks
                            if let Some(arr) = session_start.as_array() {
                                for item in arr {
                                    if let Some(sub_hooks) = item.get("hooks").and_then(|sh| sh.as_array()) {
                                        for hook in sub_hooks {
                                            if let Some(h_type) = hook.get("type").and_then(|t| t.as_str()) {
                                                if h_type == "command" {
                                                    has_command_hook = true;
                                                    if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                                                        hook_commands.push(cmd.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if has_command_hook {
                                found_commands.extend(hook_commands.clone());

                                let desc = if hook_commands.is_empty() {
                                    format!("Found {} settings with a SessionStart hook executing arbitrary shell commands.", tool_name)
                                } else {
                                    format!("Found {} settings with a SessionStart hook executing shell command(s): {:?}", tool_name, hook_commands)
                                };

                                // Critical if the command touches setup.js, downloads content,
                                // writes to /tmp, or invokes Bun — all Miasma indicators.
                                let level = if hook_commands.iter().any(|c|
                                    c.contains("setup.js")
                                    || c.contains("payload")
                                    || c.contains("curl")
                                    || c.contains("wget")
                                    || c.contains("bun ")
                                    || c.contains("/tmp/")
                                    || c.contains("$(")
                                ) {
                                    ThreatLevel::Critical
                                } else {
                                    ThreatLevel::High
                                };

                                threats.push(Threat {
                                    file_path: settings_path,
                                    threat_type: format!("{} Session Hook Injection", tool_name),
                                    description: desc,
                                    level,
                                });
                            }
                        }
                    }
                } else {
                    // If it's malformed JSON but contains a suspicious script pattern
                    if content.contains("SessionStart") && content.contains("command") {
                        threats.push(Threat {
                            file_path: settings_path,
                            threat_type: format!("Suspicious {} Settings", tool_name),
                            description: format!("File is malformed or custom-formatted but contains 'SessionStart' and 'command' patterns indicative of agent hooks."),
                            level: ThreatLevel::High,
                        });
                    }
                }
            }
        }
    }
}
