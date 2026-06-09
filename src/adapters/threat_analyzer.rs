use std::path::Path;
use crate::ports::analyzer::ThreatAnalyzer;
use crate::domain::threat::Threat;
use crate::domain::rules::ThreatRule;

// Import our rule implementations
use crate::domain::rules::setup_js::SetupJsRule;
use crate::domain::rules::session_hooks::SessionStartHooksRule;
use crate::domain::rules::vscode_tasks::VscodeTasksRule;
use crate::domain::rules::cursor_rules::CursorRulesRule;
use crate::domain::rules::package_json::PackageJsonRule;
use crate::domain::rules::binding_gyp::BindingGypRule;
use crate::domain::rules::git_history::GitHistoryLogsRule;
use crate::domain::rules::build_hooks::BuildHooksRule;

pub struct CompositeThreatAnalyzer {
    rules: Vec<Box<dyn ThreatRule>>,
}

impl CompositeThreatAnalyzer {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn ThreatRule>> = vec![
            Box::new(SetupJsRule),
            Box::new(SessionStartHooksRule),
            Box::new(VscodeTasksRule),
            Box::new(CursorRulesRule),
            Box::new(PackageJsonRule),
            Box::new(BindingGypRule),
            Box::new(GitHistoryLogsRule),
            Box::new(BuildHooksRule),
        ];
        Self { rules }
    }
}

impl ThreatAnalyzer for CompositeThreatAnalyzer {
    fn scan(&self, dir: &Path) -> Vec<Threat> {
        let total = self.rules.len();
        let mut threats = Vec::new();

        for (i, rule) in self.rules.iter().enumerate() {
            println!("  -> [{}/{}] {}", i + 1, total, rule.description());
            threats.extend(rule.check(dir));
        }

        threats
    }
}

/// Runs every registered rule without the progress-print side-effect.
/// Intended for use in tests; available as a regular pub function so
/// integration tests (tests/ crate) can call it.
pub fn scan_all_rules(dir: &Path) -> Vec<Threat> {
    CompositeThreatAnalyzer::new()
        .rules
        .iter()
        .flat_map(|rule| rule.check(dir))
        .collect()
}
