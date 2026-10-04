//! Server configuration from the environment (see docs/scan-api.md).

use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ApiKey {
    pub key: String,
    pub rpm: u32,
    pub label: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: String,
    pub cache_dir: PathBuf,
    pub signing_key: PathBuf,
    /// None = open (self-hosted default). Some = every request needs a key.
    pub api_keys: Option<HashMap<String, ApiKey>>,
    pub registry: String,
    pub osv_url: Option<String>,
    pub sandbox: bool,
    pub max_tarball: u64,
    /// Requests per minute per IP (applies in both modes).
    pub ip_rpm: u32,
    /// Trust X-Forwarded-For (only behind a proxy you control).
    pub trust_proxy: bool,
    pub max_concurrent_scans: usize,
    /// How long the request waits for a fresh scan before answering 202.
    pub wait_ms: u64,
    /// OSV verdicts can change after publish (malware is often flagged later),
    /// so a cached result is re-checked against OSV after this long.
    pub osv_ttl_secs: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let api_keys = match var("NPRYX_SCAN_API_KEYS") {
            Some(path) => Some(parse_keys(&std::fs::read_to_string(&path).map_err(|e| format!("reading {path}: {e}"))?)?),
            None => None,
        };
        let sandbox = match var("NPRYX_SCAN_SANDBOX").as_deref() {
            None | Some("off") => false,
            Some("docker") => true,
            Some(other) => return Err(format!("NPRYX_SCAN_SANDBOX must be off or docker, got {other}")),
        };
        Ok(Config {
            bind: var("NPRYX_SCAN_BIND").unwrap_or_else(|| "127.0.0.1:8787".into()),
            cache_dir: var("NPRYX_SCAN_CACHE_DIR").unwrap_or_else(|| "./cache".into()).into(),
            signing_key: var("NPRYX_SCAN_SIGNING_KEY").unwrap_or_else(|| "./signing.key".into()).into(),
            api_keys,
            registry: var("NPRYX_SCAN_REGISTRY").unwrap_or_else(|| "https://registry.npmjs.org".into()),
            osv_url: match var("NPRYX_SCAN_OSV").as_deref() {
                Some("off") => None,
                Some(u) => Some(u.to_string()),
                None => Some("https://api.osv.dev/v1/query".into()),
            },
            sandbox,
            max_tarball: var("NPRYX_SCAN_MAX_TARBALL").and_then(|v| v.parse().ok()).unwrap_or(52_428_800),
            ip_rpm: var("NPRYX_SCAN_IP_RPM").and_then(|v| v.parse().ok()).unwrap_or(120),
            trust_proxy: var("NPRYX_SCAN_TRUST_PROXY").as_deref() == Some("1"),
            max_concurrent_scans: var("NPRYX_SCAN_CONCURRENCY").and_then(|v| v.parse().ok()).unwrap_or(4),
            wait_ms: 1200,
            osv_ttl_secs: 3600,
        })
    }

    /// Defaults for tests and embedding.
    pub fn for_tests(cache_dir: PathBuf, registry: String) -> Self {
        Config {
            bind: "127.0.0.1:0".into(),
            signing_key: cache_dir.join("signing.key"),
            cache_dir,
            api_keys: None,
            registry,
            osv_url: None,
            sandbox: false,
            max_tarball: 52_428_800,
            ip_rpm: 10_000,
            trust_proxy: false,
            max_concurrent_scans: 4,
            wait_ms: 5000,
            osv_ttl_secs: 3600,
        }
    }
}

/// Keys file: `<key> <requests-per-minute> <label>` per line; `#` comments.
pub fn parse_keys(text: &str) -> Result<HashMap<String, ApiKey>, String> {
    let mut out = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, char::is_whitespace);
        let key = parts.next().unwrap_or_default().to_string();
        let rpm = parts
            .next()
            .and_then(|r| r.trim().parse::<u32>().ok())
            .ok_or_else(|| format!("keys file line {}: expected `<key> <rpm> <label>`", i + 1))?;
        let label = parts.next().map(|s| s.trim().to_string()).unwrap_or_else(|| key.chars().take(6).collect());
        if key.len() < 16 {
            return Err(format!("keys file line {}: key too short (min 16 chars)", i + 1));
        }
        out.insert(key.clone(), ApiKey { key, rpm, label });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_file() {
        let k = parse_keys("# team keys\nnpryx_live_0123456789abcdef 600 acme corp\n\nnpryx_live_fedcba9876543210 60 solo\n").unwrap();
        assert_eq!(k.len(), 2);
        let a = &k["npryx_live_0123456789abcdef"];
        assert_eq!(a.rpm, 600);
        assert_eq!(a.label, "acme corp");
        assert!(parse_keys("short 10 x").is_err());
        assert!(parse_keys("npryx_live_0123456789abcdef notanumber").is_err());
    }
}
