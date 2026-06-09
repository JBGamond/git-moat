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
        // 1. Get current active branch
        let active = self.git_client.active_branch(repo_dir)?;
        let is_already_active = active == branch;

        // 2. Fetch the branch from origin to see if local is late.
        // Ignore fetch errors (e.g. no remote configured).
        let mut has_remote = false;
        if self.git_client.fetch(repo_dir, branch).is_ok() {
            has_remote = true;
        }

        let remote_ref = format!("origin/{}", branch);

        // 3. Check if local branch is behind the remote ref.
        let mut is_behind = false;
        if has_remote {
            if let Ok(behind_count) = self.git_client.commits_behind(repo_dir, branch, &remote_ref) {
                if behind_count > 0 {
                    is_behind = true;
                    println!("Local branch '{}' is behind remote tracking branch by {} commit(s). Scanning remote...", branch, behind_count);
                }
            }
        }

        // If we are already on this branch and NOT behind, we can bypass worktree creation and scanning.
        if is_already_active && !is_behind {
            println!("Already on branch '{}' and it is up to date.", branch);
            return Ok(ScanReport { target_dir: repo_dir.to_path_buf(), remediations: vec![] });
        }

        // 4. Determine what rev to scan.
        // If the local branch is behind (or doesn't exist yet but remote does), we MUST scan the remote's latest state.
        let scan_ref = if is_behind {
            remote_ref.clone()
        } else {
            branch.to_string()
        };

        // Unique temp path — collisions are astronomically unlikely at nanosecond resolution.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let worktree_path = std::env::temp_dir().join(format!("git_moat_wt_{:x}", nanos));

        // Create detached worktree using our safe --detach method which works even if already checked out.
        self.git_client.worktree_add_detached(repo_dir, &scan_ref, &worktree_path)?;

        let threats = self.analyzer.scan(&worktree_path);

        // Clean up the worktree regardless of what was found.
        let _ = self.git_client.worktree_remove(repo_dir, &worktree_path);

        if threats.is_empty() {
            // Branch/remote is clean — perform the pull or checkout.
            if is_already_active {
                if is_behind {
                    println!("Fast-forwarding local branch '{}' to match remote HEAD...", branch);
                    self.git_client.pull_fast_forward(repo_dir)?;
                }
            } else {
                self.git_client.checkout(repo_dir, branch)?;
                if is_behind {
                    println!("Fast-forwarding local branch '{}' to match remote HEAD...", branch);
                    let _ = self.git_client.pull_fast_forward(repo_dir); // pulling might fail if local has uncommitted work, don't crash
                }
            }
            return Ok(ScanReport { target_dir: repo_dir.to_path_buf(), remediations: vec![] });
        }

        // Threats found — block the checkout/pull. Map everything to LoggedOnly because
        // there is nothing on-disk to remediate (the worktree has been removed).
        let remediations = threats
            .into_iter()
            .map(|threat| RemediatedThreat {
                threat,
                outcome: RemediationOutcome::LoggedOnly,
            })
            .collect::<Vec<_>>();

        // Only proceed with checkout/pull if threats are Medium or below.
        let has_blocking_threat = remediations
            .iter()
            .any(|r| matches!(r.threat.level, ThreatLevel::Critical | ThreatLevel::High));

        if !has_blocking_threat {
            if is_already_active {
                if is_behind {
                    let _ = self.git_client.pull_fast_forward(repo_dir);
                }
            } else {
                self.git_client.checkout(repo_dir, branch)?;
                if is_behind {
                    let _ = self.git_client.pull_fast_forward(repo_dir);
                }
            }
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
