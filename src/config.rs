use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReposConfig {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub skip: Vec<String>,
    #[serde(default)]
    pub include_forks: bool,
    #[serde(default)]
    pub include_archived: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksConfig {
    #[serde(default = "default_true")]
    pub vulnerabilities: bool,
    #[serde(default = "default_true")]
    pub github_alerts: bool,
    #[serde(default = "default_true")]
    pub posture: bool,
    #[serde(default = "default_true")]
    pub secrets: bool,
    #[serde(default = "default_true")]
    pub git_history_secrets: bool,
    #[serde(default = "default_true")]
    pub workflows: bool,
    #[serde(default = "default_true")]
    pub integrity: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ChecksConfig {
    fn default() -> Self {
        Self {
            vulnerabilities: true,
            github_alerts: true,
            posture: true,
            secrets: true,
            git_history_secrets: true,
            workflows: true,
            integrity: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistConfig {
    #[serde(default)]
    pub ignore_secrets: Vec<String>,
    #[serde(default)]
    pub ignore_vulns: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyConfig {
    pub slack: Option<String>,
    pub discord: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotConfig {
    #[serde(default = "default_owner")]
    pub owner: String,
    #[serde(default)]
    pub repos: ReposConfig,
    #[serde(default)]
    pub checks: ChecksConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_owner() -> String {
    "Srinivasan-78".to_string()
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            owner: default_owner(),
            repos: ReposConfig::default(),
            checks: ChecksConfig::default(),
            allowlist: AllowlistConfig::default(),
            notify: NotifyConfig::default(),
            enabled: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepoOverridePatch {
    enabled: Option<bool>,
    checks: Option<ChecksPatch>,
    allowlist: Option<AllowlistConfig>,
    #[serde(default)]
    ignore_secrets: Vec<String>,
    #[serde(default)]
    ignore_vulns: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChecksPatch {
    vulnerabilities: Option<bool>,
    github_alerts: Option<bool>,
    posture: Option<bool>,
    secrets: Option<bool>,
    git_history_secrets: Option<bool>,
    workflows: Option<bool>,
    integrity: Option<bool>,
}

pub fn load_config(config_path: &Path) -> BotConfig {
    if !config_path.exists() {
        return BotConfig::default();
    }
    match fs::read_to_string(config_path) {
        Ok(raw) => serde_json::from_str::<BotConfig>(&raw).unwrap_or_else(|e| {
            eprintln!(
                "::warning::Failed to parse {}: {e}. Using defaults.",
                config_path.display()
            );
            BotConfig::default()
        }),
        Err(_) => BotConfig::default(),
    }
}

pub fn apply_repo_overrides(base: &BotConfig, repo_dir: &Path) -> BotConfig {
    let override_path = repo_dir.join(".masterbot.json");
    if !override_path.exists() {
        return base.clone();
    }
    let raw = match fs::read_to_string(&override_path) {
        Ok(s) => s,
        Err(_) => return base.clone(),
    };
    let patch: RepoOverridePatch = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(_) => {
            let name = repo_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("repo");
            eprintln!("::warning::ignored malformed .masterbot.json in {name}");
            return base.clone();
        }
    };

    let mut merged = base.clone();
    if let Some(enabled) = patch.enabled {
        merged.enabled = enabled;
    }
    if let Some(c) = patch.checks {
        if let Some(v) = c.vulnerabilities {
            merged.checks.vulnerabilities = v;
        }
        if let Some(v) = c.github_alerts {
            merged.checks.github_alerts = v;
        }
        if let Some(v) = c.posture {
            merged.checks.posture = v;
        }
        if let Some(v) = c.secrets {
            merged.checks.secrets = v;
        }
        if let Some(v) = c.git_history_secrets {
            merged.checks.git_history_secrets = v;
        }
        if let Some(v) = c.workflows {
            merged.checks.workflows = v;
        }
        if let Some(v) = c.integrity {
            merged.checks.integrity = v;
        }
    }
    if let Some(al) = patch.allowlist {
        merged.allowlist.ignore_secrets.extend(al.ignore_secrets);
        merged.allowlist.ignore_vulns.extend(al.ignore_vulns);
    }
    merged.allowlist.ignore_secrets.extend(patch.ignore_secrets);
    merged.allowlist.ignore_vulns.extend(patch.ignore_vulns);
    merged
}
