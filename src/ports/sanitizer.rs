use std::path::Path;

/// Interface/Port representing file system and log operations needed for sanitization.
pub trait RepositorySanitizer {
    fn delete_file(&self, path: &Path) -> Result<(), std::io::Error>;
    fn sanitize_package_json(&self, path: &Path, threat_type: &str) -> Result<(), Box<dyn std::error::Error>>;
}
