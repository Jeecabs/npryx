//! Registry metadata: the full packument (the abbreviated "corgi" form drops
//! `time`, maintainers and attestations, which the diff needs).

use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum RegistryError {
    NotFound,
    TooLarge,
    Upstream(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::NotFound => write!(f, "no such package or version"),
            RegistryError::TooLarge => write!(f, "packument too large"),
            RegistryError::Upstream(e) => write!(f, "registry error: {e}"),
        }
    }
}

const PACKUMENT_CAP: usize = 96 * 1024 * 1024;

/// What we need from one version's manifest.
#[derive(Clone, Debug, Default)]
pub struct VersionMeta {
    pub version: String,
    pub integrity: Option<String>,
    pub tarball: Option<String>,
    pub has_provenance: bool,
    pub scripts: BTreeMap<String, String>,
    pub maintainers: Vec<String>,
    pub publisher: Option<String>,
    pub dependencies: BTreeMap<String, String>,
    pub repository_hosts: Vec<String>,
    /// e.g. "evanw/esbuild" for GitHub-hosted repos.
    pub github_repo: Option<String>,
    pub main: Option<String>,
    pub exports: Option<Value>,
    pub bin: Vec<String>,
    pub published: Option<time::OffsetDateTime>,
}

pub struct Packument {
    pub name: String,
    raw: Value,
}

pub fn encode_name(name: &str) -> String {
    name.replacen('/', "%2F", 1)
}

pub async fn fetch(client: &reqwest::Client, registry: &str, name: &str) -> Result<Packument, RegistryError> {
    let url = format!("{}/{}", registry.trim_end_matches('/'), encode_name(name));
    let resp = client
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| RegistryError::Upstream(e.to_string()))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(RegistryError::NotFound);
    }
    if !resp.status().is_success() {
        return Err(RegistryError::Upstream(format!("HTTP {}", resp.status())));
    }
    if resp.content_length().is_some_and(|l| l as usize > PACKUMENT_CAP) {
        return Err(RegistryError::TooLarge);
    }
    let bytes = resp.bytes().await.map_err(|e| RegistryError::Upstream(e.to_string()))?;
    if bytes.len() > PACKUMENT_CAP {
        return Err(RegistryError::TooLarge);
    }
    let raw: Value = serde_json::from_slice(&bytes).map_err(|e| RegistryError::Upstream(e.to_string()))?;
    Ok(Packument { name: name.to_string(), raw })
}

fn str_map(v: Option<&Value>) -> BTreeMap<String, String> {
    v.and_then(|v| v.as_object())
        .map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
        .unwrap_or_default()
}

fn person_name(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.split(" <").next().unwrap_or(s).trim().to_string()),
        Value::Object(o) => o.get("name").and_then(|n| n.as_str()).map(str::to_string),
        _ => None,
    }
}

/// Hosts named by `repository` / `homepage` / `bugs`, plus the GitHub owner/repo.
fn home_hosts(m: &Value) -> (Vec<String>, Option<String>) {
    let mut urls = Vec::new();
    match m.get("repository") {
        Some(Value::String(s)) => urls.push(s.clone()),
        Some(Value::Object(o)) => {
            if let Some(u) = o.get("url").and_then(|u| u.as_str()) {
                urls.push(u.to_string());
            }
        }
        _ => {}
    }
    for k in ["homepage"] {
        if let Some(u) = m.get(k).and_then(|u| u.as_str()) {
            urls.push(u.to_string());
        }
    }
    if let Some(u) = m.get("bugs").and_then(|b| b.get("url")).and_then(|u| u.as_str()) {
        urls.push(u.to_string());
    }
    let mut hosts = Vec::new();
    let mut gh = None;
    for u in urls {
        // "github:owner/repo" shorthand and bare "owner/repo"
        if let Some(rest) = u.strip_prefix("github:") {
            gh = Some(rest.trim_end_matches(".git").to_string());
            hosts.push("github.com".into());
            continue;
        }
        if let Some(host) = crate::analyze::dest::host_of(&u) {
            if host == "github.com" {
                if let Some(path) = u.split("github.com").nth(1) {
                    let seg: Vec<&str> = path.trim_start_matches([':', '/']).split('/').filter(|s| !s.is_empty()).collect();
                    if seg.len() >= 2 {
                        gh.get_or_insert(format!("{}/{}", seg[0], seg[1].trim_end_matches(".git")));
                    }
                }
            }
            hosts.push(host);
        }
    }
    hosts.sort();
    hosts.dedup();
    (hosts, gh)
}

impl Packument {
    pub fn version(&self, v: &str) -> Option<VersionMeta> {
        let m = self.raw.get("versions")?.get(v)?;
        let dist = m.get("dist");
        let (repository_hosts, github_repo) = home_hosts(m);
        let bin = match m.get("bin") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Object(o)) => o.values().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => vec![],
        };
        Some(VersionMeta {
            version: v.to_string(),
            integrity: dist.and_then(|d| d.get("integrity")).and_then(|i| i.as_str()).map(str::to_string),
            tarball: dist.and_then(|d| d.get("tarball")).and_then(|i| i.as_str()).map(str::to_string),
            has_provenance: dist.and_then(|d| d.get("attestations")).is_some_and(|a| !a.is_null()),
            scripts: str_map(m.get("scripts")),
            maintainers: m
                .get("maintainers")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(person_name).collect())
                .unwrap_or_default(),
            publisher: m.get("_npmUser").and_then(person_name),
            dependencies: str_map(m.get("dependencies")),
            repository_hosts,
            github_repo,
            main: m.get("main").and_then(|x| x.as_str()).map(str::to_string),
            exports: m.get("exports").cloned(),
            bin,
            published: self.published(v),
        })
    }

    fn published(&self, v: &str) -> Option<time::OffsetDateTime> {
        self.raw.get("time")?.get(v)?.as_str().and_then(crate::util::parse_rfc3339)
    }

    /// The latest version published before `v`. A stable `v` only compares
    /// against stable versions, so a stray prerelease isn't the baseline.
    pub fn previous(&self, v: &str) -> Option<String> {
        let at = self.published(v)?;
        let stable = !v.contains('-');
        let versions = self.raw.get("versions")?.as_object()?;
        versions
            .keys()
            .filter(|k| k.as_str() != v && (!stable || !k.contains('-')))
            .filter_map(|k| self.published(k).map(|t| (t, k)))
            .filter(|(t, _)| *t < at)
            .max_by_key(|(t, _)| *t)
            .map(|(_, k)| k.clone())
    }
}

#[cfg(test)]
pub(crate) fn packument_from(name: &str, raw: Value) -> Packument {
    Packument { name: name.to_string(), raw }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Packument {
        packument_from(
            "demo",
            json!({
                "name": "demo",
                "versions": {
                    "1.0.0": { "dist": { "integrity": "sha512-a", "attestations": { "url": "x" } }, "maintainers": [{"name": "alice"}] },
                    "1.1.0-beta.1": { "dist": { "integrity": "sha512-b" } },
                    "1.1.0": {
                        "dist": { "integrity": "sha512-c", "tarball": "https://r/demo-1.1.0.tgz" },
                        "maintainers": ["bob <b@x>"], "_npmUser": {"name": "mallory"},
                        "scripts": { "postinstall": "node setup.js" },
                        "repository": { "url": "git+https://github.com/acme/demo.git" },
                        "bin": { "demo": "cli.js" }
                    }
                },
                "time": {
                    "created": "2020-01-01T00:00:00Z",
                    "1.0.0": "2020-01-01T00:00:00Z",
                    "1.1.0-beta.1": "2020-02-01T00:00:00Z",
                    "1.1.0": "2020-03-01T00:00:00Z"
                }
            }),
        )
    }

    #[test]
    fn resolves_version_meta() {
        let p = sample();
        let m = p.version("1.1.0").unwrap();
        assert_eq!(m.integrity.as_deref(), Some("sha512-c"));
        assert!(!m.has_provenance);
        assert_eq!(m.maintainers, ["bob"]);
        assert_eq!(m.publisher.as_deref(), Some("mallory"));
        assert_eq!(m.github_repo.as_deref(), Some("acme/demo"));
        assert_eq!(m.bin, ["cli.js"]);
        assert!(p.version("1.0.0").unwrap().has_provenance);
        assert!(p.version("9.9.9").is_none());
    }

    #[test]
    fn previous_skips_prereleases_for_stable() {
        let p = sample();
        assert_eq!(p.previous("1.1.0").as_deref(), Some("1.0.0"));
        assert_eq!(p.previous("1.1.0-beta.1").as_deref(), Some("1.0.0"));
        assert_eq!(p.previous("1.0.0"), None);
    }

    #[test]
    fn scoped_names_are_encoded() {
        assert_eq!(encode_name("@scope/pkg"), "@scope%2Fpkg");
        assert_eq!(encode_name("plain"), "plain");
    }
}
