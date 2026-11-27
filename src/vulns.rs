use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnEntry {
    pub id: String,
    pub cve: Option<String>,
    pub severity: String,
    pub summary: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVulnFinding {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source: String,
    pub vulns: Vec<VulnEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvResult {
    pub status: String,
    pub checked: usize,
    pub findings: Vec<PackageVulnFinding>,
}

fn add_pkg(
    map: &mut BTreeMap<String, Dependency>,
    name: &str,
    version: &str,
    ecosystem: &str,
    source: &str,
) {
    let n = name.trim();
    let v = version.trim();
    if n.is_empty() || v.is_empty() || v == "*" {
        return;
    }
    let key = format!("{ecosystem}:{n}@{v}");
    map.entry(key).or_insert_with(|| Dependency {
        name: n.to_string(),
        version: v.to_string(),
        ecosystem: ecosystem.to_string(),
        source: source.to_string(),
    });
}

fn parse_npm_lock(repo_dir: &Path, map: &mut BTreeMap<String, Dependency>) -> bool {
    let p = repo_dir.join("package-lock.json");
    let Ok(raw) = fs::read_to_string(p) else {
        return false;
    };
    let Ok(data) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    if let Some(pkgs) = data.get("packages").and_then(|v| v.as_object()) {
        for (pkg_path, meta) in pkgs {
            if pkg_path.is_empty() {
                continue;
            }
            let Some(ver) = meta.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = if let Some(idx) = pkg_path.rfind("node_modules/") {
                &pkg_path[idx + "node_modules/".len()..]
            } else {
                meta.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(pkg_path)
            };
            add_pkg(map, name, ver, "npm", "package-lock.json");
        }
        return true;
    }
    true
}

fn parse_pnpm_lock(repo_dir: &Path, map: &mut BTreeMap<String, Dependency>) -> bool {
    let p = repo_dir.join("pnpm-lock.yaml");
    let Ok(text) = fs::read_to_string(p) else {
        return false;
    };
    let mut in_packages = false;
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim() == "packages:" && !line.starts_with(' ') {
            in_packages = true;
            continue;
        }
        if in_packages && !line.is_empty() && !line.starts_with(' ') {
            in_packages = false;
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let trimmed = line
            .trim()
            .trim_end_matches(':')
            .trim_matches(|c| c == '\'' || c == '"')
            .trim_start_matches('/');
        let spec = trimmed.split('(').next().unwrap_or("");
        if let Some(at_idx) = spec.rfind('@') {
            if at_idx > 0 {
                add_pkg(
                    map,
                    &spec[..at_idx],
                    &spec[at_idx + 1..],
                    "npm",
                    "pnpm-lock.yaml",
                );
            }
        }
    }
    true
}

fn parse_yarn_lock(repo_dir: &Path, map: &mut BTreeMap<String, Dependency>) -> bool {
    let p = repo_dir.join("yarn.lock");
    let Ok(text) = fs::read_to_string(p) else {
        return false;
    };
    let mut cur_names: Vec<String> = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || line.starts_with("__metadata:") {
            continue;
        }
        if !line.starts_with(' ') && line.ends_with(':') {
            let header = &line[..line.len() - 1];
            cur_names = header
                .split(',')
                .filter_map(|part| {
                    let s = part.trim().trim_matches(|c| c == '\'' || c == '"');
                    s.rfind('@')
                        .filter(|&idx| idx > 0)
                        .map(|idx| s[..idx].to_string())
                })
                .collect();
            continue;
        }
        if let Some(rest) = line.trim_start().strip_prefix("version") {
            if line.starts_with("  ") && !cur_names.is_empty() {
                let ver = rest
                    .trim_start_matches(':')
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'');
                for name in &cur_names {
                    add_pkg(map, name, ver, "npm", "yarn.lock");
                }
                cur_names.clear();
            }
        }
    }
    true
}

fn parse_package_json_pinned(repo_dir: &Path, map: &mut BTreeMap<String, Dependency>) {
    let p = repo_dir.join("package.json");
    let Ok(raw) = fs::read_to_string(p) else {
        return;
    };
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let exact_re = Regex::new(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$").unwrap();
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(deps) = pkg.get(field).and_then(|v| v.as_object()) {
            for (name, val) in deps {
                if let Some(ver) = val.as_str() {
                    if exact_re.is_match(ver.trim()) {
                        add_pkg(map, name, ver.trim(), "npm", "package.json");
                    }
                }
            }
        }
    }
}

fn parse_requirements_txt(repo_dir: &Path, map: &mut BTreeMap<String, Dependency>) {
    let Ok(entries) = fs::read_dir(repo_dir) else {
        return;
    };
    let re = Regex::new(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([^\s,]+)$").unwrap();
    for ent in entries.flatten() {
        let fname = ent.file_name().to_string_lossy().to_string();
        if !fname.to_lowercase().starts_with("requirements")
            || !fname.to_lowercase().ends_with(".txt")
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(ent.path()) else {
            continue;
        };
        for raw in text.lines() {
            let line = raw
                .split('#')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if line.is_empty() || line.starts_with('-') {
                continue;
            }
            if let Some(c) = re.captures(line) {
                add_pkg(map, &c[1], &c[2], "PyPI", &fname);
            }
        }
    }
}

fn parse_go_mod(repo_dir: &Path, map: &mut BTreeMap<String, Dependency>) {
    let Ok(text) = fs::read_to_string(repo_dir.join("go.mod")) else {
        return;
    };
    let mut in_block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "require (" {
            in_block = true;
            continue;
        }
        if in_block && line == ")" {
            in_block = false;
            continue;
        }
        let target = if in_block {
            line
        } else if let Some(r) = line.strip_prefix("require ") {
            r.trim()
        } else {
            continue;
        };
        let mut parts = target.split_whitespace();
        if let (Some(name), Some(ver)) = (parts.next(), parts.next()) {
            if ver.starts_with('v') {
                add_pkg(
                    map,
                    name,
                    ver.trim_end_matches("+incompatible"),
                    "Go",
                    "go.mod",
                );
            }
        }
    }
}

fn parse_toml_packages(
    repo_dir: &Path,
    filename: &str,
    ecosystem: &str,
    map: &mut BTreeMap<String, Dependency>,
) {
    let Ok(text) = fs::read_to_string(repo_dir.join(filename)) else {
        return;
    };
    let name_re = Regex::new(r#"(?m)^\s*name\s*=\s*"([^"]+)""#).unwrap();
    let ver_re = Regex::new(r#"(?m)^\s*version\s*=\s*"([^"]+)""#).unwrap();
    for block in text.split("[[package]]") {
        if let (Some(n), Some(v)) = (name_re.captures(block), ver_re.captures(block)) {
            add_pkg(map, &n[1], &v[1], ecosystem, filename);
        }
    }
}

pub fn parse_dependencies(repo_dir: &Path) -> Vec<Dependency> {
    let mut map = BTreeMap::new();
    let has_npm_lock = parse_npm_lock(repo_dir, &mut map)
        || parse_pnpm_lock(repo_dir, &mut map)
        || parse_yarn_lock(repo_dir, &mut map);
    if !has_npm_lock {
        parse_package_json_pinned(repo_dir, &mut map);
    }
    parse_requirements_txt(repo_dir, &mut map);
    parse_go_mod(repo_dir, &mut map);
    parse_toml_packages(repo_dir, "Cargo.lock", "crates.io", &mut map);
    parse_toml_packages(repo_dir, "poetry.lock", "PyPI", &mut map);
    parse_toml_packages(repo_dir, "uv.lock", "PyPI", &mut map);
    map.into_values().collect()
}

pub fn query_osv_vulnerabilities(deps: &[Dependency]) -> OsvResult {
    if deps.is_empty() {
        return OsvResult {
            status: "ok".into(),
            checked: 0,
            findings: vec![],
        };
    }
    let Ok(client) = Client::builder().timeout(Duration::from_secs(15)).build() else {
        return OsvResult {
            status: "unavailable".into(),
            checked: deps.len(),
            findings: vec![],
        };
    };

    let mut matched: Vec<(&Dependency, Vec<String>)> = Vec::new();
    let mut unique_ids = BTreeSet::new();

    for chunk in deps.chunks(500) {
        let queries: Vec<serde_json::Value> = chunk
            .iter()
            .map(|p| serde_json::json!({ "package": { "name": p.name, "ecosystem": p.ecosystem }, "version": p.version }))
            .collect();
        let Ok(res) = client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&serde_json::json!({ "queries": queries }))
            .send()
        else {
            return OsvResult {
                status: "unavailable".into(),
                checked: deps.len(),
                findings: vec![],
            };
        };
        if !res.status().is_success() {
            return OsvResult {
                status: "unavailable".into(),
                checked: deps.len(),
                findings: vec![],
            };
        }
        let Ok(data) = res.json::<serde_json::Value>() else {
            return OsvResult {
                status: "unavailable".into(),
                checked: deps.len(),
                findings: vec![],
            };
        };
        if let Some(results) = data.get("results").and_then(|v| v.as_array()) {
            for (idx, pkg) in chunk.iter().enumerate() {
                let ids: Vec<String> = results
                    .get(idx)
                    .and_then(|r| r.get("vulns"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| {
                                v.get("id").and_then(|s| s.as_str()).map(str::to_string)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if !ids.is_empty() {
                    for id in &ids {
                        if unique_ids.len() < 25 {
                            unique_ids.insert(id.clone());
                        }
                    }
                    matched.push((pkg, ids));
                }
            }
        }
    }

    let mut details: HashMap<String, serde_json::Value> = HashMap::new();
    for id in unique_ids {
        if let Ok(res) = client
            .get(format!("https://api.osv.dev/v1/vulns/{id}"))
            .send()
        {
            if res.status().is_success() {
                if let Ok(val) = res.json::<serde_json::Value>() {
                    details.insert(id, val);
                }
            }
        }
    }

    let findings = matched
        .into_iter()
        .map(|(pkg, ids)| PackageVulnFinding {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            ecosystem: pkg.ecosystem.clone(),
            source: pkg.source.clone(),
            vulns: ids
                .into_iter()
                .map(|id| {
                    let d = details.get(&id);
                    let cve = d
                        .and_then(|v| v.get("aliases"))
                        .and_then(|v| v.as_array())
                        .and_then(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .find(|s| s.to_uppercase().starts_with("CVE-"))
                        })
                        .map(str::to_string);
                    let severity = d
                        .and_then(|v| v.pointer("/database_specific/severity"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_uppercase())
                        .unwrap_or_else(|| "UNKNOWN".to_string());
                    let summary = d
                        .and_then(|v| v.get("summary").and_then(|s| s.as_str()))
                        .unwrap_or("Vulnerability reported in OSV")
                        .to_string();
                    let url = format!("https://osv.dev/vulnerability/{id}");
                    VulnEntry {
                        id,
                        cve,
                        severity,
                        summary,
                        url,
                    }
                })
                .collect(),
        })
        .collect();

    OsvResult {
        status: "ok".into(),
        checked: deps.len(),
        findings,
    }
}
