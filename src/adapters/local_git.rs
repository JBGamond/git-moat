use std::path::PathBuf;
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
