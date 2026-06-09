use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Critical, // Direct auto-execution payload or silent backdoor
    High,     // Auto-execution trigger configured
    Medium,   // Suspicious script or potential vulnerability
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::Critical => write!(f, "CRITICAL"),
            ThreatLevel::High => write!(f, "HIGH"),
            ThreatLevel::Medium => write!(f, "MEDIUM"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Threat {
    pub file_path: PathBuf,
    pub threat_type: String,
    pub description: String,
    pub level: ThreatLevel,
}

/// The outcome of attempting to remediate a single threat.
#[derive(Debug, Clone)]
pub enum RemediationOutcome {
    /// File was fully deleted.
    Deleted,
    /// package.json was sanitized in-place (malicious scripts stripped).
    Sanitized,
    /// Threat is metadata-only (e.g. git-log anomaly); nothing to delete.
    LoggedOnly,
    /// Remediation was attempted but failed with an error message.
    Failed(String),
}

/// Pairs a detected threat with the outcome of the remediation attempt.
#[derive(Debug, Clone)]
pub struct RemediatedThreat {
    pub threat: Threat,
    pub outcome: RemediationOutcome,
}

/// The final structured report returned by the use-case service.
#[derive(Debug)]
pub struct ScanReport {
    pub target_dir: PathBuf,
    /// Non-empty when at least one threat was found; each entry includes the
    /// remediation outcome so the presentation layer can render it.
    pub remediations: Vec<RemediatedThreat>,
}
