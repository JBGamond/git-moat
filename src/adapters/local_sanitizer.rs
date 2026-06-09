use std::path::Path;
use crate::ports::sanitizer::RepositorySanitizer;

pub struct LocalRepositorySanitizer;

impl RepositorySanitizer for LocalRepositorySanitizer {
    fn delete_file(&self, path: &Path) -> Result<(), std::io::Error> {
        std::fs::remove_file(path)
    }

    fn sanitize_package_json(&self, path: &Path, threat_type: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut json: serde_json::Value = serde_json::from_str(&content)?;
        
        if let Some(scripts) = json.get_mut("scripts").and_then(|s| s.as_object_mut()) {
            let hooks = ["preinstall", "install", "postinstall", "test", "pretest", "posttest"];
            let threat_lower = threat_type.to_lowercase();
            
            for hook in &hooks {
                if threat_lower.contains(hook) {
                    scripts.remove(*hook);
                }
            }
        }
        
        let sanitized_content = serde_json::to_string_pretty(&json)?;
        std::fs::write(path, sanitized_content)?;
        Ok(())
    }
}
