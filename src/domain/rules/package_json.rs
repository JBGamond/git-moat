use std::fs;
use std::path::Path;
use serde_json::Value;
use crate::domain::threat::{Threat, ThreatLevel};
use crate::domain::rules::ThreatRule;

pub struct PackageJsonRule;

impl ThreatRule for PackageJsonRule {
    fn name(&self) -> &'static str {
        "NPM package.json scripts"
    }

    fn description(&self) -> &'static str {
        "Inspecting package.json scripts and lifecycles..."
    }

    fn check(&self, dir: &Path) -> Vec<Threat> {
        let mut threats = Vec::new();
        let pkg_path = dir.join("package.json");
        if pkg_path.exists() {
            if let Ok(content) = fs::read_to_string(&pkg_path) {
                if let Ok(json) = serde_json::from_str::<Value>(&content) {
                    if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
                        let suspicious_hooks = [
                            // lifecycle hooks that auto-run during install / publish
                            "preinstall", "install", "postinstall",
                            "prepare", "prepack", "postpack",
                            // test hooks exploited by Miasma
                            "test", "pretest", "posttest",
                        ];

                        for hook in &suspicious_hooks {
                            if let Some(script_val) = scripts.get(*hook).and_then(|val| val.as_str()) {
                                if script_val.contains("setup.js") || script_val.contains(".github/setup") {
                                    threats.push(Threat {
                                        file_path: pkg_path.clone(),
                                        threat_type: format!("NPM {} Hijack", hook),
                                        description: format!(
                                            "package.json has script '{}' overridden to execute: '{}' (matches Miasma persistence vector).",
                                            hook, script_val
                                        ),
                                        level: ThreatLevel::Critical,
                                    });
                                } else if script_val.contains("curl") || script_val.contains("wget") || script_val.contains("eval") || script_val.contains("bun ") {
                                    threats.push(Threat {
                                        file_path: pkg_path.clone(),
                                        threat_type: format!("Suspicious NPM {} script", hook),
                                        description: format!(
                                            "package.json script '{}' invokes raw web requests or shell execution: '{}'",
                                            hook, script_val
                                        ),
                                        level: ThreatLevel::High,
                                    });
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
