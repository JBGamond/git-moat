use std::path::{Path, PathBuf};

/// Interface/Port representing Git wrapper operations (the Driver).
pub trait GitClient {
    /// Clone a repository. All standard `git clone` flags are forwarded.
    fn clone(&self, args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>>;

    /// Create a temporary worktree at `worktree_path` for `branch`.
    /// Fetches from origin first if the branch is not available locally.
    fn worktree_add(
        &self,
        repo_dir: &Path,
        branch: &str,
        worktree_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Remove a worktree previously created with `worktree_add`.
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
}
