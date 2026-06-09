use std::path::{Path, PathBuf};

/// Interface/Port representing Git wrapper operations (the Driver).
pub trait GitClient {
    /// Clone a repository. All standard `git clone` flags are forwarded.
    fn clone(&self, args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>>;

    /// Create a temporary worktree at `worktree_path` for a specific revision (detached HEAD).
    /// Prevents conflicts when the branch is checked out elsewhere.
    fn worktree_add_detached(
        &self,
        repo_dir: &Path,
        rev: &str,
        worktree_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Remove a worktree previously created with `worktree_add_detached`.
    fn worktree_remove(
        &self,
        repo_dir: &Path,
        worktree_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Switch the working tree to `branch` (equivalent to `git checkout <branch>`).
    fn checkout(
        &self,
        repo_dir: &Path,
        branch: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Get the name of the currently active branch in the repo.
    fn active_branch(&self, repo_dir: &Path) -> Result<String, Box<dyn std::error::Error>>;

    /// Fetch progress from origin for a given branch.
    fn fetch(&self, repo_dir: &Path, branch: &str) -> Result<(), Box<dyn std::error::Error>>;

    /// Check if target branch is behind its remote version.
    /// Returns the number of commits behind.
    fn commits_behind(
        &self,
        repo_dir: &Path,
        local_branch: &str,
        remote_ref: &str,
    ) -> Result<usize, Box<dyn std::error::Error>>;

    /// Pull/update the branch via fast-forward merge.
    fn pull_fast_forward(&self, repo_dir: &Path) -> Result<(), Box<dyn std::error::Error>>;
}

