use crate::auditor::{ScorecardItem, StackInfo, TodoItem};
use reqwest::blocking::Client;
use serde::Serialize;
use std::env;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct AiResult {
    pub status: String,
    pub insights: Option<String>,
}

pub fn analyze_with_gemini(
    repo_name: &str,
    stack: &StackInfo,
    scorecard: &[ScorecardItem],
    todos: &[TodoItem],
    api_key_override: Option<&str>,
) -> AiResult {
    let api_key = api_key_override
        .map(str::to_string)
        .or_else(|| env::var("GEMINI_API_KEY").ok())
        .unwrap_or_default();
    if api_key.trim().is_empty() {
        return AiResult {
            status: "skipped".into(),
            insights: None,
        };
    }

    let failing: Vec<String> = scorecard
        .iter()
        .filter(|s| s.status != "Pass")
        .map(|s| format!("- {}: {} ({})", s.category, s.status, s.evidence))
        .collect();
    let todo_lines: Vec<String> = todos
        .iter()
        .take(10)
        .map(|t| format!("- [{}] {}: {} — {}", t.priority, t.id, t.title, t.reason))
        .collect();

    let prompt = format!(
        "You are a Principal DevSecOps & Software Architect reviewing \"{repo_name}\".\nStack: languages={:?}, pm={:?}, has_tests={}.\n{}\n{}\nProvide 3-5 concise, actionable recommendations in Markdown bullet points.",
        stack.languages,
        stack.package_manager,
        stack.has_tests,
        if failing.is_empty() { "All scorecard items Pass.".into() } else { format!("Gaps:\n{}", failing.join("\n")) },
        if todo_lines.is_empty() { String::new() } else { format!("TODOs:\n{}", todo_lines.join("\n")) }
    );

    let model = env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemini-2.5-flash".into());
    let url =
        format!("https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent");
    let Ok(client) = Client::builder().timeout(Duration::from_secs(20)).build() else {
        return AiResult {
            status: "error".into(),
            insights: None,
        };
    };
    let payload = serde_json::json!({
        "contents": [{ "role": "user", "parts": [{ "text": prompt }] }],
        "generationConfig": { "temperature": 0.2, "maxOutputTokens": 512 }
    });
    let Ok(res) = client
        .post(url)
        .header("x-goog-api-key", &api_key)
        .json(&payload)
        .send()
    else {
        return AiResult {
            status: "error".into(),
            insights: None,
        };
    };
    if !res.status().is_success() {
        return AiResult {
            status: "error".into(),
            insights: None,
        };
    }
    let Ok(data) = res.json::<serde_json::Value>() else {
        return AiResult {
            status: "error".into(),
            insights: None,
        };
    };
    let text = data
        .pointer("/candidates/0/content/parts")
        .and_then(|v| v.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());

    match text {
        Some(insights) => AiResult {
            status: "ok".into(),
            insights: Some(insights),
        },
        None => AiResult {
            status: "error".into(),
            insights: None,
        },
    }
}
