use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use crate::ports::git::GitClient;

pub struct LocalGitClient;

impl GitClient for LocalGitClient {
    fn clone(&self, args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let (_repo_url, target_dir) = parse_clone_args(args)
            .ok_or("Could not parse target repository or output directory from arguments.")?;

        let mut child = Command::new("git")
            .args(args)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let status = child.wait()?;
        if !status.success() {
            return Err(format!("'git clone' failed with exit status: {}", status).into());
        }

        Ok(target_dir)
    }

    fn worktree_add_detached(
        &self,
        repo_dir: &Path,
        rev: &str,
        worktree_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let repo_str = repo_dir.to_str().ok_or("repo path is not valid UTF-8")?;
        let wt_str   = worktree_path.to_str().ok_or("worktree path is not valid UTF-8")?;

        let status = Command::new("git")
            .args(["-C", repo_str, "worktree", "add", "--detach", wt_str, rev])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(format!("Could not create detached worktree for rev '{}'.", rev).into())
        }
    }

    fn worktree_remove(
        &self,
        repo_dir: &Path,
        worktree_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let repo_str = repo_dir.to_str().ok_or("repo path is not valid UTF-8")?;
        let wt_str   = worktree_path.to_str().ok_or("worktree path is not valid UTF-8")?;

        Command::new("git")
            .args(["-C", repo_str, "worktree", "remove", "--force", wt_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        Ok(())
    }

    fn checkout(
        &self,
        repo_dir: &Path,
        branch: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let repo_str = repo_dir.to_str().ok_or("repo path is not valid UTF-8")?;

        let status = Command::new("git")
            .args(["-C", repo_str, "checkout", branch])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(format!("'git checkout {}' failed.", branch).into())
        }
    }

    fn active_branch(&self, repo_dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let repo_str = repo_dir.to_str().ok_or("repo path is not valid UTF-8")?;
        let output = Command::new("git")
            .args(["-C", repo_str, "symbolic-ref", "--short", "HEAD"])
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            // It might be detached head or similar
            let output2 = Command::new("git")
                .args(["-C", repo_str, "rev-parse", "--abbrev-ref", "HEAD"])
                .output()?;
            if output2.status.success() {
                Ok(String::from_utf8_lossy(&output2.stdout).trim().to_string())
            } else {
                Err("Could not determine active branch.".into())
            }
        }
    }

    fn fetch(&self, repo_dir: &Path, branch: &str) -> Result<(), Box<dyn std::error::Error>> {
        let repo_str = repo_dir.to_str().ok_or("repo path is not valid UTF-8")?;
        let status = Command::new("git")
            .args(["-C", repo_str, "fetch", "origin", branch])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err("Fetch failed.".into())
        }
    }

    fn commits_behind(
        &self,
        repo_dir: &Path,
        local_branch: &str,
        remote_ref: &str,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let repo_str = repo_dir.to_str().ok_or("repo path is not valid UTF-8")?;

        // Check if local branch exists
        let check_local = Command::new("git")
            .args(["-C", repo_str, "show-ref", "--verify", &format!("refs/heads/{}", local_branch)])
            .output()?;

        if !check_local.status.success() {
            // Local branch does not exist yet. So yes, it is "late" / needs tracking.
            return Ok(1);
        }

        let output = Command::new("git")
            .args(["-C", repo_str, "rev-list", "--count", &format!("{}..{}", local_branch, remote_ref)])
            .output()?;

        if output.status.success() {
            let count_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let count = count_str.parse::<usize>().unwrap_or(0);
            Ok(count)
        } else {
            Ok(0)
        }
    }

    fn pull_fast_forward(&self, repo_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let repo_str = repo_dir.to_str().ok_or("repo path is not valid UTF-8")?;
        let status = Command::new("git")
            .args(["-C", repo_str, "pull", "--ff-only"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err("Fast-forward pull/merge failed.".into())
        }
    }
}

/// Parses `git clone` arguments, respecting flags that consume a value (--depth, -b, …),
/// to extract the positional repository URL and optional destination directory.
pub fn parse_clone_args(args: &[String]) -> Option<(String, PathBuf)> {
    let mut actual_args = args;
    if !actual_args.is_empty() && actual_args[0] == "clone" {
        actual_args = &actual_args[1..];
    }

    let mut repo_url: Option<String> = None;
    let mut target_dir: Option<PathBuf> = None;
    let mut i = 0;
    let mut double_dash = false;

    const OPTIONS_WITH_VALUES: &[&str] = &[
        "-b", "--branch",
        "-c", "--config",
        "--depth",
        "--filter",
        "-j", "--jobs",
        "--reference",
        "--reference-if-able",
        "--separate-git-dir",
        "--shallow-exclude",
        "--shallow-since",
        "--template",
        "-o", "--origin",
        "--server-option",
        "--bundle-uri",
    ];

    while i < actual_args.len() {
        let arg = &actual_args[i];

        if double_dash {
            if repo_url.is_none() { repo_url = Some(arg.clone()); }
            else if target_dir.is_none() { target_dir = Some(PathBuf::from(arg)); }
            i += 1;
            continue;
        }

        if arg == "--" {
            double_dash = true;
            i += 1;
            continue;
        }

        if arg.starts_with('-') {
            let takes_value = OPTIONS_WITH_VALUES.contains(&arg.as_str()) && !arg.contains('=');
            i += if takes_value { 2 } else { 1 };
        } else {
            if repo_url.is_none() { repo_url = Some(arg.clone()); }
            else if target_dir.is_none() { target_dir = Some(PathBuf::from(arg)); }
            i += 1;
        }
    }

    let url = repo_url?;
    let dir = target_dir.unwrap_or_else(|| {
        default_dir_name(&url)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("repo"))
    });
    Some((url, dir))
}

fn default_dir_name(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');
    if trimmed.is_empty() { return None; }
    let last = trimmed.split('/').last()?;
    let name = last.split(':').last()?;
    let name = if name.to_lowercase().ends_with(".git") { &name[..name.len() - 4] } else { name };
    if name.is_empty() { None } else { Some(name.to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dir_name() {
        assert_eq!(default_dir_name("https://github.com/foo/bar.git"), Some("bar".into()));
        assert_eq!(default_dir_name("https://github.com/foo/bar/"),    Some("bar".into()));
        assert_eq!(default_dir_name("git@github.com:foo/baz.git"),     Some("baz".into()));
        assert_eq!(default_dir_name("git@github.com:foo/baz"),         Some("baz".into()));
        assert_eq!(default_dir_name("/path/to/local/repo"),            Some("repo".into()));
    }

    #[test]
    fn test_parse_clone_args_with_flags() {
        let args = ["clone", "--depth", "1", "-b", "main",
                    "https://github.com/foo/bar.git", "target-folder"]
            .iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (url, dir) = parse_clone_args(&args).unwrap();
        assert_eq!(url, "https://github.com/foo/bar.git");
        assert_eq!(dir, PathBuf::from("target-folder"));
    }

    #[test]
    fn test_parse_clone_args_default_dir() {
        let args = ["clone", "--depth=1", "https://github.com/foo/bar.git"]
            .iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (url, dir) = parse_clone_args(&args).unwrap();
        assert_eq!(url, "https://github.com/foo/bar.git");
        assert_eq!(dir, PathBuf::from("bar"));
    }
}
