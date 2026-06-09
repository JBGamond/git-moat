use std::fs;
use std::path::Path;
use serde_json::Value;
use crate::domain::threat::{Threat, ThreatLevel};
use crate::domain::rules::ThreatRule;

pub struct VscodeTasksRule;

impl ThreatRule for VscodeTasksRule {
    fn name(&self) -> &'static str {
        "VS Code folderOpen tasks"
    }

    fn description(&self) -> &'static str {
        "Checking VS Code task folderOpen auto-runs..."
    }

    fn check(&self, dir: &Path) -> Vec<Threat> {
        let mut threats = Vec::new();
        let tasks_path = dir.join(".vscode/tasks.json");
        if tasks_path.exists() {
            if let Ok(content) = fs::read_to_string(&tasks_path) {
                if let Ok(json) = serde_json::from_str::<Value>(&content) {
                    if let Some(tasks) = json.get("tasks").and_then(|t| t.as_array()) {
                        for task in tasks {
                            let mut runs_on_open = false;
                            if let Some(run_options) = task.get("runOptions") {
                                if let Some(run_on) = run_options.get("runOn").and_then(|r| r.as_str()) {
                                    if run_on == "folderOpen" {
                                        runs_on_open = true;
                                    }
                                }
                            }

                            if runs_on_open {
                                let label = task.get("label").and_then(|l| l.as_str()).unwrap_or("unlabeled");
                                let command = task.get("command").and_then(|c| c.as_str()).unwrap_or("none");
                                
                                let is_miasma_setup = command.contains("setup.js") || command.contains(".github");
                                let level = if is_miasma_setup {
                                    ThreatLevel::Critical
                                } else {
                                    ThreatLevel::High
                                };

                                threats.push(Threat {
                                    file_path: tasks_path.clone(),
                                    threat_type: "VS Code Task Auto-run".to_string(),
                                    description: format!(
                                        "Found VS Code task labeled '{}' programmed to run automatically on folderOpen. Executed command: '{}'",
                                        label, command
                                    ),
                                    level,
                                });
                            }
                        }
                    }
                } else {
                    if content.contains("folderOpen") && content.contains("command") {
                        threats.push(Threat {
                            file_path: tasks_path,
                            threat_type: "Suspicious VS Code Tasks".to_string(),
                            description: "File is malformed but contains 'folderOpen' and 'command' parameters indicative of auto-run settings.".to_string(),
                            level: ThreatLevel::High,
                        });
                    }
                }
            }
        }
        threats
    }
}
