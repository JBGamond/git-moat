// All modules live in lib.rs; main.rs is a thin entry-point.
use git_moat::adapters::local_git::{LocalGitClient, parse_clone_args};
use git_moat::adapters::local_sanitizer::LocalRepositorySanitizer;
use git_moat::adapters::threat_analyzer::CompositeThreatAnalyzer;
use git_moat::domain::service::SafeGitService;
use git_moat::domain::threat::{RemediationOutcome, ThreatLevel};

use std::env;
use std::process;
use colored::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        process::exit(0);
    }

    let cli_args = &args[1..];

    if cli_args[0] == "--help" || cli_args[0] == "-h" {
        print_help();
        process::exit(0);
    }

    let service = SafeGitService::new(LocalGitClient, CompositeThreatAnalyzer::new(), LocalRepositorySanitizer);

    match cli_args[0].as_str() {
        "checkout" => {
            let branch = match cli_args.get(1) {
                Some(b) => b.clone(),
                None => {
                    eprintln!("{} Missing branch name.", "Error:".red().bold());
                    eprintln!("Usage: git-moat checkout <branch>");
                    process::exit(1);
                }
            };
            run_checkout(&service, &branch);
        }
        "pull" => {
            // Secure pull: scan incoming commits on the current branch before merging.
            // Reuses the checkout path which already handles fetch → scan → fast-forward.
            run_pull(&service);
        }
        "fetch" => {
            // fetch only downloads refs; it does not modify the working tree so no scan needed.
            run_passthrough_fetch(&cli_args[1..]);
        }
        "clone" => {
            run_clone(&service, cli_args);
        }
        other if other.starts_with('-') || !other.contains('/') && !other.contains('.') => {
            // Treat bare flags or a plain first word as implicit `clone` shorthand.
            let mut git_args = vec!["clone".to_string()];
            git_args.extend_from_slice(cli_args);
            run_clone(&service, &git_args);
        }
        _ => {
            // Looks like a URL passed without `clone` keyword — treat as implicit clone.
            let mut git_args = vec!["clone".to_string()];
            git_args.extend_from_slice(cli_args);
            run_clone(&service, &git_args);
        }
    }
}

fn run_clone(
    service: &SafeGitService<LocalGitClient, CompositeThreatAnalyzer, LocalRepositorySanitizer>,
    git_args: &[String],
) {
    let (repo_url, target_dir) = match parse_clone_args(git_args) {
        Some(p) => p,
        None => {
            eprintln!("{} Could not parse repository URL or output directory.", "Error:".red().bold());
            eprintln!("Usage: git-moat clone <repo-url> [directory]");
            process::exit(1);
        }
    };

    println!("{}", "====================================================".cyan());
    println!("{} Wrapping: {} {}", "git-moat".bold().green(), "git".yellow(), git_args.join(" "));
    println!("{} Target Directory: {}", "git-moat".bold().green(), target_dir.display().to_string().cyan());
    println!("{} Repository URL:   {}", "git-moat".bold().green(), repo_url.cyan());
    println!("{}", "====================================================".cyan());

    println!("\n{}", "Starting git-moat Security Threat Analysis...".magenta().bold());

    match service.execute_clone(git_args) {
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            process::exit(1);
        }
        Ok(report) if report.remediations.is_empty() => {
            println!("{}", "✔ Security check complete: No auto-run configuration hacks or Miasma indicators found.".green().bold());
            println!("{}", "It is safe to open this directory in your editor or run package commands.".green());
        }
        Ok(report) => {
            print_threat_report(&report.remediations);
            process::exit(1);
        }
    }
}

fn run_checkout(
    service: &SafeGitService<LocalGitClient, CompositeThreatAnalyzer, LocalRepositorySanitizer>,
    branch: &str,
) {
    // Resolve the git repo root from the current directory.
    let repo_dir = match std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        Ok(out) if out.status.success() => {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            std::path::PathBuf::from(path)
        }
        _ => {
            eprintln!("{} Not inside a git repository.", "Error:".red().bold());
            process::exit(1);
        }
    };

    println!("{}", "====================================================".cyan());
    println!("{} Scanning branch: {}", "git-moat".bold().green(), branch.cyan().bold());
    println!("{} Repository:      {}", "git-moat".bold().green(), repo_dir.display().to_string().cyan());
    println!("{}", "====================================================".cyan());
    println!("\n{}", "Scanning branch in temporary worktree — working tree untouched...".magenta().bold());

    match service.execute_checkout(&repo_dir, branch) {
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            process::exit(1);
        }
        Ok(report) if report.remediations.is_empty() => {
            println!("{} Branch '{}' is clean. Switched successfully.", "✔".green(), branch.cyan().bold());
        }
        Ok(report) => {
            let has_blocker = report.remediations.iter().any(|r| {
                matches!(r.threat.level, ThreatLevel::Critical | ThreatLevel::High)
            });
            if has_blocker {
                println!("\n{}", "⚠️  SECURITY ALERT: CHECKOUT BLOCKED ⚠️".red().bold().on_black());
                println!("{}", "Branch contains Critical/High threats. Checkout was aborted.".red());
                println!("{}\n", "Remove the threat vectors from the branch before switching.".red());
            } else {
                println!("\n{}", "⚠  Medium-level findings — checkout proceeded.".yellow().bold());
            }
            print_threat_report(&report.remediations);
            if has_blocker { process::exit(1); }
        }
    }
}

fn print_threat_report(remediations: &[git_moat::domain::threat::RemediatedThreat]) {
    for (i, item) in remediations.iter().enumerate() {
        let level_str = match item.threat.level {
            ThreatLevel::Critical => item.threat.level.to_string().red().bold(),
            ThreatLevel::High     => item.threat.level.to_string().yellow().bold(),
            ThreatLevel::Medium   => item.threat.level.to_string().yellow(),
        };
        println!("{}. [{}] {} ({})", i + 1, level_str, item.threat.threat_type.bold(), item.threat.file_path.display());
        println!("   Description: {}", item.threat.description);
        let remediation_label = match &item.outcome {
            RemediationOutcome::Deleted    => format!("{} File deleted.", "✔".green()),
            RemediationOutcome::Sanitized  => format!("{} Sanitized: malicious script hook removed.", "✔".green()),
            RemediationOutcome::LoggedOnly => format!("{} Logged only (scan-only or commit-log anomaly).", "i".cyan()),
            RemediationOutcome::Failed(e)  => format!("{} FAILED: {} — delete manually!", "✘".red().bold(), e),
        };
        println!("   Remediation: {}\n", remediation_label);
    }

    let failed = remediations.iter().filter(|r| matches!(r.outcome, RemediationOutcome::Failed(_))).count();
    if failed > 0 {
        eprintln!("{} {} threat(s) could not be cleaned up. Delete them manually before opening.", "WARNING:".yellow().bold(), failed);
    }
}

fn run_pull(
    service: &SafeGitService<LocalGitClient, CompositeThreatAnalyzer, LocalRepositorySanitizer>,
) {
    let repo_dir = match std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        Ok(out) if out.status.success() => {
            std::path::PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        _ => {
            eprintln!("{} Not inside a git repository.", "Error:".red().bold());
            process::exit(1);
        }
    };

    let branch = match std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
    {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => {
            eprintln!("{} Could not determine current branch.", "Error:".red().bold());
            process::exit(1);
        }
    };

    println!("{}", "====================================================".cyan());
    println!("{} Secure pull for branch: {}", "git-moat".bold().green(), branch.cyan().bold());
    println!("{} Repository:             {}", "git-moat".bold().green(), repo_dir.display().to_string().cyan());
    println!("{}", "====================================================".cyan());
    println!("\n{}", "Scanning incoming commits before merging...".magenta().bold());

    match service.execute_checkout(&repo_dir, &branch) {
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            process::exit(1);
        }
        Ok(report) if report.remediations.is_empty() => {
            println!("{} Branch '{}' is clean and up to date.", "✔".green(), branch.cyan().bold());
        }
        Ok(report) => {
            let has_blocker = report.remediations.iter().any(|r| {
                matches!(r.threat.level, ThreatLevel::Critical | ThreatLevel::High)
            });
            if has_blocker {
                println!("\n{}", "⚠️  SECURITY ALERT: PULL BLOCKED ⚠️".red().bold().on_black());
                println!("{}", "Incoming commits contain Critical/High threats. Pull was aborted.".red());
            } else {
                println!("\n{}", "⚠  Medium-level findings — pull proceeded.".yellow().bold());
            }
            print_threat_report(&report.remediations);
            if has_blocker { process::exit(1); }
        }
    }
}

fn run_passthrough_fetch(extra_args: &[String]) {
    println!("{}", "====================================================".cyan());
    println!("{} Running: git fetch {}", "git-moat".bold().green(), extra_args.join(" ").cyan());
    println!("{}", "====================================================".cyan());

    let exit = std::process::Command::new("git")
        .arg("fetch")
        .args(extra_args)
        .status();

    match exit {
        Ok(s) if s.success() => {}
        Ok(s) => process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            process::exit(1);
        }
    }
}

fn print_help() {
    println!("{}", "git-moat — Secure Git CLI".green().bold());
    println!("Protects developers and AI coding agents from Miasma Worm & supply-chain auto-runs.");
    println!("\nUsage:");
    println!("  git-moat clone <git-clone-arguments>");
    println!("  git-moat checkout <branch>          scan branch in a temp worktree, then switch if safe");
    println!("  git-moat pull                       scan incoming commits on current branch, then fast-forward");
    println!("  git-moat fetch [args]               passthrough to git fetch (no scan needed)");
    println!("  git-moat <git-clone-arguments>      shorthand — 'clone' is implicit");
    println!("\nExamples:");
    println!("  git-moat clone https://github.com/Azure/durabletask.git");
    println!("  git-moat clone --depth 1 -b main https://github.com/icflorescu/mantine-datatable.git");
    println!("  git-moat checkout feature/new-api");
    println!("  git-moat pull");
    println!("  git-moat fetch --all");
}
