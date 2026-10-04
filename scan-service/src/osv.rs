//! OSV.dev lookup. Malware advisories (`MAL-…`) are confirmed findings; other
//! advisories are low (npryx is about running untrusted code, not CVE triage).
//! A failed lookup produces no finding — never an error.

use crate::model::{Finding, Severity, Source};
use serde_json::{json, Value};
use std::time::Duration;

pub async fn query(client: &reqwest::Client, url: &str, name: &str, version: &str) -> Vec<Finding> {
    let body = json!({ "package": { "name": name, "ecosystem": "npm" }, "version": version });
    let resp = client.post(url).json(&body).timeout(Duration::from_secs(4)).send().await;
    let Ok(resp) = resp else { return vec![] };
    if !resp.status().is_success() {
        return vec![];
    }
    let Ok(v) = resp.json::<Value>().await else { return vec![] };
    parse(&v)
}

pub fn parse(v: &Value) -> Vec<Finding> {
    let vulns = v.get("vulns").and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let mut malware = Vec::new();
    let mut other = Vec::new();
    for vuln in &vulns {
        let id = vuln.get("id").and_then(|x| x.as_str()).unwrap_or("?").to_string();
        let summary = vuln.get("summary").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let aliases: Vec<String> = vuln
            .get("aliases")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if id.starts_with("MAL-") || aliases.iter().any(|a| a.starts_with("MAL-")) {
            malware.push((id, summary));
        } else {
            other.push((id, summary));
        }
    }
    let mut out = Vec::new();
    if !malware.is_empty() {
        let mut f = Finding::new(
            "osv.malware",
            Severity::Confirmed,
            Source::Osv,
            "reported as malware",
            malware.iter().map(|(id, s)| if s.is_empty() { id.clone() } else { format!("{id}: {s}") }).collect::<Vec<_>>().join("; "),
        );
        f.evidence = malware.first().map(|(id, _)| format!("https://osv.dev/vulnerability/{id}"));
        out.push(f);
    }
    if !other.is_empty() {
        out.push(Finding::new(
            "osv.vulnerability",
            Severity::Low,
            Source::Osv,
            format!("{} known vulnerabilit{}", other.len(), if other.len() == 1 { "y" } else { "ies" }),
            other.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>().join(", "),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malware_is_confirmed_others_low() {
        let v = json!({ "vulns": [
            { "id": "MAL-2025-1234", "summary": "Malicious code in evil-pkg (npm)" },
            { "id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2024-1"] }
        ]});
        let f = parse(&v);
        assert_eq!(f[0].id, "osv.malware");
        assert_eq!(f[0].severity, Severity::Confirmed);
        assert!(f[0].detail.contains("MAL-2025-1234"));
        assert_eq!(f[1].id, "osv.vulnerability");
        assert_eq!(f[1].severity, Severity::Low);
        assert!(parse(&json!({})).is_empty());
    }
}
