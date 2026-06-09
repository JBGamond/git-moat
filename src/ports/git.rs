use std::path::PathBuf;

/// Interface/Port representing Git wrapper operations (the Driver).
pub trait GitClient {
    fn clone(&self, args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>>;
}
