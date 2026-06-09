/// Cross-ecosystem build hook auto-execution detector.
///
/// Every major dependency manager or build system has at least one hook that
/// executes arbitrary shell commands automatically — either at install time, at
/// `make` parse time, or on the first project open.  This mirrors exactly how
/// `binding.gyp` is exploited for Node.js native extensions, and how Miasma's
/// `package.json` test-script hijack works.
///
/// Ecosystems covered:
///  • PHP   — composer.json  (pre/post-install-cmd, post-autoload-dump)
///  • Ruby  — Gemfile (non-standard sources), *.gemspec (native extensions)
///  • Make  — Makefile / GNUmakefile ($(shell …) + auto-run targets)
///  • iOS   — Podfile (pre_install / post_install blocks)
///  • Py    — setup.py (module-level exec), pyproject.toml (build backends)
///  • Java  — pom.xml (exec-maven-plugin), build.gradle (exec {} blocks)
///  • Rust  — build.rs (Command::new — runs on every `cargo build`)
use std::fs;
use std::path::Path;
use serde_json::Value;
use crate::domain::threat::{Threat, ThreatLevel};
use crate::domain::rules::ThreatRule;

pub struct BuildHooksRule;

impl ThreatRule for BuildHooksRule {
    fn name(&self) -> &'static str {
        "Cross-ecosystem build hook auto-execution"
    }

    fn description(&self) -> &'static str {
        "Scanning build/dependency manifests for auto-executing hook vectors \
        (Composer, Gemfile, gemspec, Makefile, Podfile, setup.py, pyproject.toml, \
        pom.xml, Gradle, build.rs)..."
    }

    fn check(&self, dir: &Path) -> Vec<Threat> {
        let mut threats = Vec::new();
        check_composer(dir, &mut threats);
        check_gemfile(dir, &mut threats);
        check_gemspec(dir, &mut threats);
        check_makefile(dir, &mut threats);
        check_podfile(dir, &mut threats);
        check_setup_py(dir, &mut threats);
        check_pyproject(dir, &mut threats);
        check_pom_xml(dir, &mut threats);
        check_gradle(dir, &mut threats);
        check_build_rs(dir, &mut threats);
        threats
    }
}

// ── Shared classification helpers ────────────────────────────────────────────

/// Known worm / dropper IOCs — always Critical regardless of context.
const DROPPER_IOCS: &[&str] = &[
    ".github/setup",
    "oven-sh/bun",
    "/tmp/p",
];

/// Network download patterns — High in any auto-run context.
const DOWNLOAD_PATTERNS: &[&str] = &[
    "curl ",
    "curl\t",
    "wget ",
    "Invoke-WebRequest",
    "urllib.request",
    "requests.get(",
];

/// Classify a command snippet.  Returns (level, human-readable reason) if suspicious.
fn classify(cmd: &str) -> Option<(ThreatLevel, String)> {
    for p in DROPPER_IOCS {
        if cmd.contains(p) {
            return Some((ThreatLevel::Critical, format!("Miasma IOC `{}`", p)));
        }
    }
    for p in DOWNLOAD_PATTERNS {
        if cmd.contains(p.trim()) {
            return Some((ThreatLevel::High, format!("network download via `{}`", p.trim())));
        }
    }
    // Interpreter + script-file extension in an auto-run hook is always worth flagging.
    let interpreters = ["node ", "bun ", "python ", "python3 ", "ruby ", "php "];
    let script_exts  = [".js", ".py", ".rb", ".php", ".sh"];
    if interpreters.iter().any(|i| cmd.contains(i))
        && script_exts.iter().any(|e| cmd.contains(e))
    {
        return Some((ThreatLevel::High, "executes a script file in an auto-run hook".to_string()));
    }
    None
}

fn emit(
    threats: &mut Vec<Threat>,
    path: std::path::PathBuf,
    threat_type: impl Into<String>,
    description: impl Into<String>,
    level: ThreatLevel,
) {
    threats.push(Threat {
        file_path: path,
        threat_type: threat_type.into(),
        description: description.into(),
        level,
    });
}

// ── PHP / Composer ───────────────────────────────────────────────────────────

fn check_composer(dir: &Path, threats: &mut Vec<Threat>) {
    let path = dir.join("composer.json");
    if !path.exists() { return; }
    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };
    let json: Value = match serde_json::from_str(&content) { Ok(v) => v, Err(_) => return };

    // All of these run automatically on `composer install` / `composer update`
    // without any additional user confirmation.
    const AUTO_HOOKS: &[&str] = &[
        "pre-install-cmd",
        "post-install-cmd",
        "pre-update-cmd",
        "post-update-cmd",
        "post-autoload-dump",      // runs on every `composer install`
        "pre-package-install",
        "post-package-install",
    ];

    let scripts = match json.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return,
    };

    for hook in AUTO_HOOKS {
        let cmds: Vec<String> = match scripts.get(*hook) {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(arr)) => arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => continue,
        };
        for cmd in &cmds {
            if let Some((level, reason)) = classify(cmd) {
                emit(
                    threats,
                    path.clone(),
                    "Composer Hook Auto-run",
                    format!(
                        "composer.json `{}` script executes automatically on `composer install`: \
                        `{}` — {}.",
                        hook, cmd, reason
                    ),
                    level,
                );
            }
        }
    }
}

// ── Ruby / Bundler ───────────────────────────────────────────────────────────

fn check_gemfile(dir: &Path, threats: &mut Vec<Threat>) {
    let path = dir.join("Gemfile");
    if !path.exists() { return; }
    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') { continue; }

        // Non-standard source redirects ALL gem downloads to attacker infrastructure.
        // Miasma was confirmed to plant Gemfiles in Ruby project targets.
        if trimmed.starts_with("source") && !trimmed.contains("rubygems.org") {
            emit(
                threats,
                path.clone(),
                "Gemfile Non-Standard Source",
                format!(
                    "Gemfile declares a gem source outside rubygems.org: `{}`. \
                    A rogue gem server can serve malicious gems with the same names as real packages.",
                    trimmed
                ),
                ThreatLevel::High,
            );
        }

        // Inline eval in a Gemfile is essentially never present in legitimate projects.
        if trimmed.starts_with("eval ") || trimmed.starts_with("eval(") {
            emit(
                threats,
                path.clone(),
                "Gemfile Inline Eval",
                format!(
                    "Gemfile contains an inline `eval` call: `{}`. \
                    This is not a standard Bundler pattern and indicates injected code.",
                    trimmed
                ),
                ThreatLevel::Critical,
            );
        }
    }
}

fn check_gemspec(dir: &Path, threats: &mut Vec<Threat>) {
    let entries = match fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("gemspec") { continue; }
        let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => continue };

        // `.extensions = [...]` triggers native compilation: ruby extconf.rb → make.
        // Equivalent to the binding.gyp attack vector for Node.js.
        let has_extensions = content.contains(".extensions = ") || content.contains(".extensions=");
        let has_native = content.contains("extconf.rb") || content.contains("ext/Makefile");
        if !has_extensions || !has_native { continue; }

        if let Some((level, reason)) = classify(&content) {
            emit(
                threats,
                path,
                "gemspec Native Extension Auto-run",
                format!(
                    "gemspec declares native extensions (compile at `gem install` time) \
                    and contains a suspicious command — {}. \
                    Native extensions run arbitrary code without user confirmation.",
                    reason
                ),
                level,
            );
        } else {
            emit(
                threats,
                path,
                "gemspec Native Extension",
                "gemspec declares native extensions (extconf.rb / Makefile). \
                These compile and execute code automatically at `gem install` time — \
                the Ruby equivalent of the binding.gyp attack vector. Verify the \
                extension source has not been tampered with.",
                ThreatLevel::Medium,
            );
        }
    }
}

// ── Make ─────────────────────────────────────────────────────────────────────

fn check_makefile(dir: &Path, threats: &mut Vec<Threat>) {
    for name in &["Makefile", "GNUmakefile", "makefile"] {
        let path = dir.join(name);
        if !path.exists() { continue; }
        let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => continue };

        // $(shell ...) in variable assignments executes at *parse time* — before any
        // target runs, the moment `make` is invoked.
        for line in content.lines() {
            if line.contains("$(shell ") {
                if let Some((level, reason)) = classify(line) {
                    emit(
                        threats,
                        path.clone(),
                        "Makefile Parse-time Shell Expansion",
                        format!(
                            "Makefile `$(shell ...)` variable expansion fires at `make` parse \
                            time (before any target runs) and contains a suspicious command — \
                            {}: `{}`.",
                            reason, line.trim()
                        ),
                        level,
                    );
                }
            }
        }

        // Recipe lines inside well-known auto-invoked targets.
        const AUTO_TARGETS: &[&str] = &[
            "all:", "install:", "build:", "test:", "check:", "setup:",
        ];
        let mut in_auto_target = false;
        let mut emitted = false;
        for line in content.lines() {
            if AUTO_TARGETS.iter().any(|t| line.starts_with(t)) {
                in_auto_target = true;
                continue;
            }
            if in_auto_target && !emitted {
                if line.starts_with('\t') {
                    if let Some((level, reason)) = classify(line) {
                        emit(
                            threats,
                            path.clone(),
                            "Makefile Auto-target Command",
                            format!(
                                "Makefile auto-run target recipe contains a suspicious command — \
                                {}: `{}`.",
                                reason, line.trim()
                            ),
                            level,
                        );
                        emitted = true;
                    }
                } else if !line.trim().is_empty() && !line.starts_with('#') {
                    in_auto_target = false;
                }
            }
        }
    }
}

// ── CocoaPods ─────────────────────────────────────────────────────────────────

fn check_podfile(dir: &Path, threats: &mut Vec<Threat>) {
    let path = dir.join("Podfile");
    if !path.exists() { return; }
    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };

    // pre_install / post_install blocks run Ruby code automatically during `pod install`.
    // Direct equivalent of npm's postinstall hook.
    for hook in &["pre_install", "post_install"] {
        if !content.contains(hook) { continue; }
        if let Some(idx) = content.find(hook) {
            let body = &content[idx..];
            if let Some((level, reason)) = classify(body) {
                emit(
                    threats,
                    path.clone(),
                    "Podfile Hook Auto-run",
                    format!(
                        "Podfile `{}` block auto-runs Ruby code during `pod install` \
                        and contains a suspicious command — {}.",
                        hook, reason
                    ),
                    level,
                );
            } else if body.contains("system(") || body.contains("IO.popen") || body.contains("` ") {
                emit(
                    threats,
                    path.clone(),
                    "Podfile Hook Shell Execution",
                    format!(
                        "Podfile `{}` block executes shell commands via `system()`, backtick \
                        or `IO.popen`. This code runs automatically during `pod install`.",
                        hook
                    ),
                    ThreatLevel::High,
                );
            }
        }
    }
}

// ── Python ────────────────────────────────────────────────────────────────────

fn check_setup_py(dir: &Path, threats: &mut Vec<Threat>) {
    let path = dir.join("setup.py");
    if !path.exists() { return; }
    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };

    // Code at module level (not indented inside a function/class) runs when pip
    // imports setup.py, i.e., on `pip install`, before setup() is even called.
    for line in content.lines() {
        if line.starts_with("    ") || line.starts_with('\t') { continue; }
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() { continue; }
        if let Some((level, reason)) = classify(trimmed) {
            emit(
                threats,
                path.clone(),
                "setup.py Module-level Execution",
                format!(
                    "setup.py contains a module-level command that runs at `pip install` time \
                    (before `setup()` is called): `{}` — {}.",
                    trimmed, reason
                ),
                level,
            );
            break;
        }
    }
}

fn check_pyproject(dir: &Path, threats: &mut Vec<Threat>) {
    let path = dir.join("pyproject.toml");
    if !path.exists() { return; }
    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };

    // [build-system] — the build backend is imported and run on `pip install`.
    // An unknown/unrecognized backend is a supply-chain foothold.
    if content.contains("[build-system]") {
        const KNOWN_BACKENDS: &[&str] = &[
            "setuptools", "hatchling", "flit_core", "flit",
            "poetry-core", "poetry", "maturin", "pdm-backend",
            "pdm", "scikit-build-core", "mesonpy",
        ];
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with("requires") && !KNOWN_BACKENDS.iter().any(|b| t.contains(b)) {
                emit(
                    threats,
                    path.clone(),
                    "pyproject.toml Unknown Build Backend",
                    format!(
                        "pyproject.toml `[build-system].requires` references an unrecognized \
                        build backend: `{}`. A malicious build backend runs arbitrary code at \
                        `pip install` / `pip wheel` time.",
                        t
                    ),
                    ThreatLevel::High,
                );
                break;
            }
        }
    }

    // Hatch build hooks execute scripts at build time.
    if content.contains("[tool.hatch.build.hooks") {
        if let Some((level, reason)) = classify(&content) {
            emit(
                threats,
                path.clone(),
                "pyproject.toml Hatch Build Hook",
                format!(
                    "pyproject.toml defines a Hatch build hook containing a suspicious command \
                    — {}. Build hooks execute at `pip install` time.",
                    reason
                ),
                level,
            );
        }
    }
}

// ── Java / Maven ──────────────────────────────────────────────────────────────

fn check_pom_xml(dir: &Path, threats: &mut Vec<Threat>) {
    let path = dir.join("pom.xml");
    if !path.exists() { return; }
    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };

    if content.contains("exec-maven-plugin") {
        if let Some((level, reason)) = classify(&content) {
            emit(
                threats,
                path,
                "Maven exec-maven-plugin Auto-run",
                format!(
                    "pom.xml uses `exec-maven-plugin` and contains a suspicious command \
                    in the Maven build lifecycle — {}.",
                    reason
                ),
                level,
            );
        } else {
            emit(
                threats,
                path,
                "Maven exec-maven-plugin",
                "pom.xml uses `exec-maven-plugin`, which can execute arbitrary shell commands \
                during any Maven lifecycle phase. Verify all `<executable>` configurations \
                are intentional and have not been injected.",
                ThreatLevel::Medium,
            );
        }
    }
}

// ── Java / Gradle ─────────────────────────────────────────────────────────────

fn check_gradle(dir: &Path, threats: &mut Vec<Threat>) {
    for name in &["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"] {
        let path = dir.join(name);
        if !path.exists() { continue; }
        let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => continue };

        // Configuration-phase `exec {}` blocks fire on every `gradle` invocation,
        // not just during specific tasks — equivalent to `$(shell ...)` in Make.
        let has_exec = content.contains("exec {")
            || content.contains("exec{")
            || content.contains("Runtime.getRuntime().exec(")
            || content.contains("ProcessBuilder(");

        if has_exec {
            if let Some((level, reason)) = classify(&content) {
                emit(
                    threats,
                    path,
                    "Gradle exec Block Auto-run",
                    format!(
                        "Gradle build file contains a configuration-phase exec block with a \
                        suspicious command (fires on every `gradle` invocation) — {}.",
                        reason
                    ),
                    level,
                );
            } else {
                emit(
                    threats,
                    path,
                    "Gradle exec Block",
                    "Gradle build file uses `exec {}` or `Runtime.getRuntime().exec()`. \
                    Configuration-phase exec calls fire on every Gradle invocation. \
                    Verify the command has not been injected.",
                    ThreatLevel::Medium,
                );
            }
        }
    }
}

// ── Rust / Cargo ──────────────────────────────────────────────────────────────

fn check_build_rs(dir: &Path, threats: &mut Vec<Threat>) {
    let path = dir.join("build.rs");
    if !path.exists() { return; }
    let content = match fs::read_to_string(&path) { Ok(c) => c, Err(_) => return };

    // build.rs is a Cargo build script — it runs automatically on every `cargo build`,
    // before the crate itself compiles.
    if content.contains("Command::new") || content.contains("std::process::Command") {
        if let Some((level, reason)) = classify(&content) {
            emit(
                threats,
                path,
                "Cargo build.rs External Command",
                format!(
                    "build.rs (auto-runs on every `cargo build`) executes a suspicious \
                    external command — {}.",
                    reason
                ),
                level,
            );
        } else {
            // Medium — bindgen/protoc/cc use of Command::new is legitimate but worth flagging
            // when the repo is unfamiliar.
            emit(
                threats,
                path,
                "Cargo build.rs External Command",
                "build.rs uses `Command::new` to run an external program. Cargo build scripts \
                execute automatically on `cargo build`. Common for bindgen/protoc/cc, but \
                verify the command has not been tampered with.",
                ThreatLevel::Medium,
            );
        }
    }
}
