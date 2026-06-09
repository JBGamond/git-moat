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

    let git_args: Vec<String> = if cli_args[0] == "--help" || cli_args[0] == "-h" {
        print_help();
        process::exit(0);
    } else if cli_args[0] == "clone" {
        cli_args.to_vec()
    } else {
        let mut v = vec!["clone".to_string()];
        v.extend_from_slice(cli_args);
        v
    };

    let (repo_url, target_dir) = match parse_clone_args(&git_args) {
        Some(p) => p,
        None => {
            eprintln!("{} Could not parse repository URL or output directory.", "Error:".red().bold());
            eprintln!("Usage: safe-git clone <repo-url> [directory]");
            process::exit(1);
        }
    };

    println!("{}", "====================================================".cyan());
    println!("{} Wrapping: {} {}", "safe-git".bold().green(), "git".yellow(), git_args.join(" "));
    println!("{} Target Directory: {}", "safe-git".bold().green(), target_dir.display().to_string().cyan());
    println!("{} Repository URL:   {}", "safe-git".bold().green(), repo_url.cyan());
    println!("{}", "====================================================".cyan());

    let service = SafeGitService::new(LocalGitClient, CompositeThreatAnalyzer::new(), LocalRepositorySanitizer);

    println!("\n{}", "Starting safe-git Security Threat Analysis...".magenta().bold());

    match service.execute_clone(&git_args) {
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            process::exit(1);
        }
        Ok(report) if report.remediations.is_empty() => {
            println!("{}", "✔ Security check complete: No auto-run configuration hacks or Miasma indicators found.".green().bold());
            println!("{}", "It is safe to open this directory in your editor or run package commands.".green());
            process::exit(0);
        }
        Ok(report) => {
            println!("\n{}", "⚠️  SECURITY ALERT: MALICIOUS THREATS DETECTED! ⚠️".red().bold().on_black());
            println!("{}", "This repository contains configurations designed to auto-execute malicious scripts.".red());
            println!("{}", "Opening this directory in VS Code, Claude Code, Gemini CLI, or Cursor will trigger the threat.".red());
            println!("All threat vectors will be removed or sanitized to protect your environment.\n");

            for (i, item) in report.remediations.iter().enumerate() {
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
                    RemediationOutcome::LoggedOnly => format!("{} Logged — no file to remove (commit-log anomaly).", "i".cyan()),
                    RemediationOutcome::Failed(e)  => format!("{} FAILED: {} — delete manually!", "✘".red().bold(), e),
                };
                println!("   Remediation: {}\n", remediation_label);
            }

            let failed = report.remediations.iter().filter(|r| matches!(r.outcome, RemediationOutcome::Failed(_))).count();
            if failed == 0 {
                println!("{}", "✔ All threat vectors removed/sanitized. Repository is now safe to open!".green().bold());
            } else {
                eprintln!("{} {} threat(s) could not be cleaned up. Delete them manually before opening.", "WARNING:".yellow().bold(), failed);
            }

            process::exit(1);
        }
    }
}

fn print_help() {
    println!("{}", "safe-git — Secure Git Clone CLI".green().bold());
    println!("Protects developers and AI coding agents from Miasma Worm & supply-chain auto-runs.");
    println!("\nUsage:");
    println!("  safe-git clone <git-clone-arguments>");
    println!("  safe-git <git-clone-arguments>   (shorthand — 'clone' is implicit)");
    println!("\nExamples:");
    println!("  safe-git clone https://github.com/Azure/durabletask.git");
    println!("  safe-git clone --depth 1 https://github.com/icflorescu/mantine-datatable.git my-folder");
}
