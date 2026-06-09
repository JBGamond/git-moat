use std::path::Path;
use std::process::Command;
use crate::domain::threat::{Threat, ThreatLevel};
use crate::domain::rules::ThreatRule;

pub struct GitHistoryLogsRule;

impl ThreatRule for GitHistoryLogsRule {
    fn name(&self) -> &'static str {
        "Git Commit logs / timestamps analysis"
    }

    fn description(&self) -> &'static str {
        "Inspecting git history, signatures, and backdated logs..."
    }

    fn check(&self, dir: &Path) -> Vec<Threat> {
        let mut threats = Vec::new();
        let output = Command::new("git")
            .args(&["log", "-n", "20", "--pretty=format:%H|%an|%ae|%at|%cn|%ce|%s|%G?"])
            .current_dir(dir)
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let logs_str = String::from_utf8_lossy(&out.stdout);
                for line in logs_str.lines() {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 8 {
                        let hash = parts[0];
                        let author_name = parts[1];
                        let author_email = parts[2];
                        let author_time_str = parts[3];
                        let _committer_name = parts[4];
                        let _committer_email = parts[5];
                        let subject = parts[6];
                        let signature = parts[7]; // G?, can be G, B, U, X, Y, R, N, etc.

                        let is_unsigned = signature == "N" || signature.is_empty();
                        
                        // 1. Check for github-actions user making unsigned direct commits
                        let is_github_actions = author_email == "github-actions@github.com" || author_name.contains("github-actions");
                        if is_github_actions && is_unsigned {
                            threats.push(Threat {
                                file_path: dir.to_path_buf(),
                                threat_type: "Suspicious Git Log: Unsigned github-actions Commit".to_string(),
                                description: format!(
                                    "Commit {} by author '{} <{}>' is unsigned. The Miasma Worm leverages stolen tokens to force-push unsigned commits impersonating github-actions.",
                                    hash, author_name, author_email
                                ),
                                level: ThreatLevel::High,
                            });
                        }

                        // 2. Check for [skip ci] in unsigned commits containing common dependency / configuration wording
                        let subject_lower = subject.to_lowercase();
                        let represents_skip_ci = subject_lower.contains("[skip ci]") || subject_lower.contains("skip-ci");
                        let is_dependency_update = subject_lower.contains("dependencies") || subject_lower.contains("update") || subject_lower.contains("dependency") || subject_lower.contains("chore");
                        
                        if represents_skip_ci && is_unsigned && is_dependency_update {
                            threats.push(Threat {
                                file_path: dir.to_path_buf(),
                                threat_type: "Suspicious Git Log: Unsigned skip-ci Commit".to_string(),
                                description: format!(
                                    "Commit {} ('{}') is unsigned and contains dependency update verbiage with '[skip ci]'. This is the exact fingerprint used by Miasma/Shai-Hulud to bypass CI scanners and avoid drawing attention.",
                                    hash, subject
                                ),
                                level: ThreatLevel::High,
                            });
                        }

                        // 3. Check for extremely old/backdated commits in otherwise recent repositories
                        if let Ok(timestamp) = author_time_str.parse::<i64>() {
                            if timestamp > 0 && timestamp < 1640995200 && represents_skip_ci {
                                threats.push(Threat {
                                    file_path: dir.to_path_buf(),
                                    threat_type: "Suspicious Git Log: Backdated skip-ci Commit".to_string(),
                                    description: format!(
                                        "Commit {} ('{}') has a backdated timestamp from before 2022 but includes '[skip ci]'. Attackers use stolen PATs with backdated timestamps to hide malicious commits in dormant branches.",
                                        hash, subject
                                    ),
                                    level: ThreatLevel::High,
                                });
                            }
                        }
                    }
                }
            }
        }
        threats
    }
}
