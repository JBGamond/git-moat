use std::fs;
use std::path::Path;
use crate::domain::threat::{Threat, ThreatLevel};
use crate::domain::rules::ThreatRule;

pub struct BindingGypRule;

impl ThreatRule for BindingGypRule {
    fn name(&self) -> &'static str {
        "node-gyp silent build command expansions"
    }

    fn description(&self) -> &'static str {
        "Checking binding.gyp silent build expansions..."
    }

    fn check(&self, dir: &Path) -> Vec<Threat> {
        let mut threats = Vec::new();
        let gyp_path = dir.join("binding.gyp");
        if gyp_path.exists() {
            if let Ok(content) = fs::read_to_string(&gyp_path) {
                // node-gyp Command expansion pattern: <!(command)
                if content.contains("<!(") {
                    let has_suspicious_cmd = content.contains("node ") 
                        || content.contains(".js") 
                        || content.contains("curl") 
                        || content.contains("wget") 
                        || content.contains("sh ");

                    let (level, description) = if has_suspicious_cmd {
                        (
                            ThreatLevel::Critical,
                            "Found binding.gyp parsing containing a command expansion '<!(...)' running an arbitrary node/script parser (silent auto-run on npm install).".to_string()
                        )
                    } else {
                        (
                            ThreatLevel::High,
                            "Found binding.gyp file with a command expansion '<!(...)'. Command expansions execute automatically at config-time but are rare in benign projects.".to_string()
                        )
                    };

                    threats.push(Threat {
                        file_path: gyp_path,
                        threat_type: "node-gyp Config Auto-run".to_string(),
                        description,
                        level,
                    });
                }
            }
        }
        threats
    }
}
