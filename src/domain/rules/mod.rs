use std::path::Path;
use crate::domain::threat::Threat;

pub mod setup_js;
pub mod session_hooks;
pub mod vscode_tasks;
pub mod cursor_rules;
pub mod package_json;
pub mod binding_gyp;
pub mod git_history;
pub mod build_hooks;

/// Rule trait (or Policy Port) defining individual threat check algorithms.
pub trait ThreatRule {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn check(&self, dir: &Path) -> Vec<Threat>;
}

