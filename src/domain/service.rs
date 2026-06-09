use crate::domain::threat::{RemediatedThreat, RemediationOutcome, ScanReport};
use crate::ports::analyzer::ThreatAnalyzer;
use crate::ports::git::GitClient;
use crate::ports::sanitizer::RepositorySanitizer;

/// Core use-case interactor.
/// Contains only business logic — no I/O, no UI, no presentation dependencies.
pub struct SafeGitService<Git, Scanner, Clean>
where
    Git: GitClient,
    Scanner: ThreatAnalyzer,
    Clean: RepositorySanitizer,
{
    git_client: Git,
    analyzer: Scanner,
    sanitizer: Clean,
}

impl<Git, Scanner, Clean> SafeGitService<Git, Scanner, Clean>
where
    Git: GitClient,
    Scanner: ThreatAnalyzer,
    Clean: RepositorySanitizer,
{
    pub fn new(git_client: Git, analyzer: Scanner, sanitizer: Clean) -> Self {
        Self { git_client, analyzer, sanitizer }
    }

    /// Clone the repository, scan it, and remediate any found threats.
    /// Returns a structured `ScanReport` on success; an `Err` only when the
    /// clone itself fails or the directory cannot be located.
    pub fn execute_clone(
        &self,
        git_args: &[String],
    ) -> Result<ScanReport, Box<dyn std::error::Error>> {
        let target_dir = self.git_client.clone(git_args)?;

        if !target_dir.exists() {
            return Err(format!(
                "Cloned directory '{}' does not exist or was renamed.",
                target_dir.display()
            )
            .into());
        }

        let threats = self.analyzer.scan(&target_dir);

        if threats.is_empty() {
            return Ok(ScanReport { target_dir, remediations: vec![] });
        }

        let remediations = threats
            .into_iter()
            .map(|threat| {
                let outcome = self.remediate(&threat);
                RemediatedThreat { threat, outcome }
            })
            .collect();

        Ok(ScanReport { target_dir, remediations })
    }

    fn remediate(&self, threat: &crate::domain::threat::Threat) -> RemediationOutcome {
        let is_pkg_json =
            threat.file_path.file_name().and_then(|s| s.to_str()) == Some("package.json");

        if is_pkg_json {
            match self.sanitizer.sanitize_package_json(&threat.file_path, &threat.threat_type) {
                Ok(_) => return RemediationOutcome::Sanitized,
                Err(e) => {
                    // Sanitization failed — fall through to deletion
                    if let Err(del_err) = self.sanitizer.delete_file(&threat.file_path) {
                        return RemediationOutcome::Failed(format!(
                            "sanitize failed ({e}); delete also failed ({del_err})"
                        ));
                    }
                    return RemediationOutcome::Deleted;
                }
            }
        }

        if !threat.file_path.exists() {
            // Already gone (e.g. duplicate threat entry for same file)
            return RemediationOutcome::Deleted;
        }

        if threat.file_path.is_dir() {
            // Directory paths signal metadata-only threats (git log anomalies, etc.)
            return RemediationOutcome::LoggedOnly;
        }

        match self.sanitizer.delete_file(&threat.file_path) {
            Ok(_) => RemediationOutcome::Deleted,
            Err(e) => RemediationOutcome::Failed(e.to_string()),
        }
    }
}
