use std::path::Path;
use crate::domain::threat::{RemediatedThreat, RemediationOutcome, ScanReport, ThreatLevel};
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

    /// Scan `branch` in a temporary git worktree without disturbing the working
    /// tree, then perform the actual `git checkout` only if no Critical or High
    /// threats are found.
    ///
    /// All threat outcomes are `LoggedOnly` because the worktree is transient —
    /// the caller (presentation layer) should treat the returned report as a
    /// gate: non-empty remediations mean the checkout was blocked.
    pub fn execute_checkout(
        &self,
        repo_dir: &Path,
        branch: &str,
    ) -> Result<ScanReport, Box<dyn std::error::Error>> {
        // Unique temp path — collisions are astronomically unlikely at nanosecond resolution.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let worktree_path = std::env::temp_dir().join(format!("git_moat_wt_{:x}", nanos));

        self.git_client.worktree_add(repo_dir, branch, &worktree_path)?;

        let threats = self.analyzer.scan(&worktree_path);

        // Clean up the worktree regardless of what was found.
        let _ = self.git_client.worktree_remove(repo_dir, &worktree_path);

        if threats.is_empty() {
            // Branch is clean — perform the checkout and return an empty report.
            self.git_client.checkout(repo_dir, branch)?;
            return Ok(ScanReport { target_dir: repo_dir.to_path_buf(), remediations: vec![] });
        }

        // Threats found — block the checkout. Map everything to LoggedOnly because
        // there is nothing on disk to remediate (the worktree has been removed).
        let remediations = threats
            .into_iter()
            .map(|threat| RemediatedThreat {
                threat,
                outcome: RemediationOutcome::LoggedOnly,
            })
            .collect::<Vec<_>>();

        // Only proceed with the checkout if threats are Medium or below.
        let has_blocking_threat = remediations
            .iter()
            .any(|r| matches!(r.threat.level, ThreatLevel::Critical | ThreatLevel::High));

        if !has_blocking_threat {
            self.git_client.checkout(repo_dir, branch)?;
        }

        Ok(ScanReport { target_dir: repo_dir.to_path_buf(), remediations })
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
