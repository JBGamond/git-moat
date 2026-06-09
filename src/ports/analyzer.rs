use std::path::Path;
use crate::domain::threat::Threat;

/// Analyzer port defining how to scan directories for security threats.
pub trait ThreatAnalyzer {
    fn scan(&self, dir: &Path) -> Vec<Threat>;
}
