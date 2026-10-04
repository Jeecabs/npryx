//! One scan, end to end: registry → integrity check → tarball → static
//! analysis (cached by integrity) → diff against the previous version →
//! registry signals → OSV → optional sandbox → verdict.

use std::sync::Arc;

use crate::analyze::{self, dest, PackageAnalysis};
use crate::cache::Cache;
use crate::config::Config;
use crate::model::{self, Finding, Phase, ScanResult, Severity, Source, VersionRef};
use crate::registry::{self, RegistryError, VersionMeta};
use crate::tarball::{self, TarError};

#[derive(Debug)]
pub enum Outcome {
    Done(ScanResult),
    Mismatch(ScanResult),
    NotFound,
    TooLarge,
    Upstream(String),
}

pub struct Scanner {
    pub cfg: Config,
    client: reqwest::Client,
    cache: Cache,
}

impl Scanner {
    pub fn new(cfg: Config) -> std::io::Result<Arc<Self>> {
        let cache = Cache::new(&cfg.cache_dir)?;
        let client = reqwest::Client::builder()
            .user_agent(concat!("npryx-scan/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(std::io::Error::other)?;
        Ok(Arc::new(Scanner { cfg, client, cache }))
    }

    /// A cached result, if one exists and its OSV check is fresh enough.
    pub async fn cached(&self, integrity: &str, deep: bool) -> Option<ScanResult> {
        let mut r: ScanResult = self.cache.get_result(integrity, deep)?;
        let fresh = r
            .scanned_at
            .as_deref()
            .and_then(crate::util::parse_rfc3339)
            .map(|t| (time::OffsetDateTime::now_utc() - t).whole_seconds() < self.cfg.osv_ttl_secs)
            .unwrap_or(false);
        if !fresh {
            // Malware is often reported after publish: re-check OSV, keep the rest.
            r.findings.retain(|f| f.source != Source::Osv);
            if let Some(url) = &self.cfg.osv_url {
                r.findings.extend(crate::osv::query(&self.client, url, &r.name, &r.version).await);
            }
            sort(&mut r.findings);
            r.verdict = Some(model::verdict(&r.findings));
            r.scanned_at = Some(crate::util::now_rfc3339());
            self.cache.put_result(integrity, deep, &r);
        }
        Some(r)
    }

    pub async fn scan(&self, name: &str, version: &str, integrity: &str, deep: bool) -> Outcome {
        if let Some(r) = self.cached(integrity, deep).await {
            return Outcome::Done(r);
        }
        let pk = match registry::fetch(&self.client, &self.cfg.registry, name).await {
            Ok(p) => p,
            Err(RegistryError::NotFound) => return Outcome::NotFound,
            Err(RegistryError::TooLarge) => return Outcome::TooLarge,
            Err(e) => return Outcome::Upstream(e.to_string()),
        };
        let Some(meta) = pk.version(version) else { return Outcome::NotFound };
        let Some(reg_integrity) = meta.integrity.clone() else {
            return Outcome::Upstream("registry lists no integrity for this version".into());
        };
        if !sri_equal(&reg_integrity, integrity) {
            return Outcome::Mismatch(ScanResult::mismatch(name, version, integrity, &reg_integrity));
        }

        let cur = match self.analysis(&meta, &reg_integrity, deep).await {
            Ok(a) => a,
            Err(TarError::TooLarge(_)) => return Outcome::TooLarge,
            Err(TarError::Integrity { actual, .. }) => {
                // The registry's metadata says one thing, its bytes another.
                let mut r = ScanResult::mismatch(name, version, integrity, &actual);
                if let Some(f) = r.findings.first_mut() {
                    f.title = "the tarball's bytes don't match the registry's own integrity".into();
                }
                return Outcome::Mismatch(r);
            }
            Err(e) => return Outcome::Upstream(e.to_string()),
        };
        let (analysis, tgz) = cur;

        // previous version: best effort — a failure just means no diff
        let prev_meta = pk.previous(version).and_then(|v| pk.version(&v));
        let prev = match &prev_meta {
            Some(pm) if pm.integrity.is_some() => {
                self.analysis(pm, pm.integrity.as_deref().unwrap_or_default(), false).await.ok().map(|(a, _)| (pm, a))
            }
            _ => None,
        };

        let mut result = ScanResult::done(name, version, integrity);
        result.previous = prev.as_ref().map(|(m, _)| VersionRef {
            version: m.version.clone(),
            integrity: m.integrity.clone().unwrap_or_default(),
        });
        let (mut findings, network) = crate::diff::compose(&analysis, prev.as_ref().map(|(_, a)| a));
        findings.extend(crate::diff::registry_findings(
            &meta,
            &analysis.scripts,
            prev.as_ref().map(|(m, a)| (*m, &a.scripts)),
        ));
        if let Some(url) = &self.cfg.osv_url {
            findings.extend(crate::osv::query(&self.client, url, name, version).await);
        }
        if deep {
            let report = self.sandbox(name, version, tgz.as_deref()).await;
            findings.extend(sandbox_findings(&report, &self.cfg.registry));
            result.sandbox = Some(report);
        }
        sort(&mut findings);
        result.verdict = Some(model::verdict(&findings));
        result.findings = findings;
        result.network = network;
        self.cache.put_result(integrity, deep, &result);
        Outcome::Done(result)
    }

    /// Static analysis for one version, from cache or by downloading it.
    /// Returns the tarball bytes too when `need_bytes` (for the sandbox).
    async fn analysis(&self, meta: &VersionMeta, integrity: &str, need_bytes: bool) -> Result<(PackageAnalysis, Option<Vec<u8>>), TarError> {
        if !need_bytes {
            if let Some(a) = self.cache.get_analysis::<PackageAnalysis>(integrity) {
                return Ok((a, None));
            }
        }
        let url = meta.tarball.as_deref().ok_or_else(|| TarError::Fetch("no tarball url".into()))?;
        let bytes = tarball::download(&self.client, url, self.cfg.max_tarball).await?;
        tarball::verify_sri(&bytes, integrity)?;
        let cached = if need_bytes { self.cache.get_analysis::<PackageAnalysis>(integrity) } else { None };
        let analysis = match cached {
            Some(a) => a,
            None => {
                let cap = self.cfg.max_tarball;
                let home = dest::Home { hosts: meta.repository_hosts.clone(), github_repo: meta.github_repo.clone() };
                let scripts = meta.scripts.clone();
                let bytes_for_task = bytes.clone();
                // CPU-bound: keep it off the async workers.
                let a = tokio::task::spawn_blocking(move || -> Result<PackageAnalysis, TarError> {
                    let unpacked = tarball::unpack(&bytes_for_task, cap)?;
                    Ok(analyze::analyze_package(&unpacked.files, &home, &scripts))
                })
                .await
                .map_err(|e| TarError::Corrupt(e.to_string()))??;
                self.cache.put_analysis(integrity, &a);
                a
            }
        };
        Ok((analysis, need_bytes.then_some(bytes)))
    }

    async fn sandbox(&self, name: &str, version: &str, tgz: Option<&[u8]>) -> crate::sandbox::SandboxReport {
        let skipped = |reason: &str| crate::sandbox::SandboxReport {
            status: "skipped".into(),
            reason: Some(reason.into()),
            runs: vec![],
            attempts: vec![],
            file_reads: vec![],
            duration_ms: 0,
        };
        if !self.cfg.sandbox {
            return skipped("sandbox scans are disabled on this server");
        }
        if !crate::sandbox::available() {
            return skipped("sandbox runtime (docker) is not reachable");
        }
        let Some(bytes) = tgz else { return skipped("tarball unavailable") };
        let dir = match tempfile_dir() {
            Ok(d) => d,
            Err(e) => return skipped(&format!("temp dir: {e}")),
        };
        let path = dir.join(format!("{}-{version}.tgz", name.replace('/', "__")));
        if let Err(e) = std::fs::write(&path, bytes) {
            return skipped(&format!("writing tarball: {e}"));
        }
        let input = crate::sandbox::SandboxInput {
            name: name.into(),
            version: version.into(),
            tarball: path,
            registry: self.cfg.registry.clone(),
        };
        let report = crate::sandbox::run(&input).await;
        let _ = std::fs::remove_dir_all(&dir);
        report
    }
}

fn tempfile_dir() -> std::io::Result<std::path::PathBuf> {
    let mut seed = [0u8; 8];
    getrandom::getrandom(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
    let d = std::env::temp_dir().join(format!("npryx-scan-{}", hex::encode(seed)));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// SRIs are equal if they share any (algorithm, digest) pair.
pub fn sri_equal(a: &str, b: &str) -> bool {
    let set = |s: &str| -> Vec<String> { s.split_whitespace().map(str::to_string).collect() };
    let (a, b) = (set(a), set(b));
    a.iter().any(|x| b.contains(x))
}

fn sort(f: &mut [Finding]) {
    f.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.new_since_previous.cmp(&a.new_since_previous)).then(a.id.cmp(&b.id)));
}

fn parse_phase(s: &str) -> Phase {
    match s {
        "install" => Phase::Install,
        "import" => Phase::Import,
        "runtime" | "bin" | "run" => Phase::Runtime,
        _ => Phase::Unknown,
    }
}

/// Turn a SandboxReport into findings (rule table: canary hits → confirmed;
/// non-registry egress → high; credential reads → high).
pub fn sandbox_findings(r: &crate::sandbox::SandboxReport, registry: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let reg_host = dest::host_of(registry).unwrap_or_default();
    let is_registry = |target: &str| -> bool {
        let host = dest::host_of(target).or_else(|| Some(target.split(':').next().unwrap_or(target).to_ascii_lowercase()));
        host.is_some_and(|h| h == reg_host || h == "registry.npmjs.org" || h == "registry.yarnpkg.com")
    };

    let canary: Vec<&crate::sandbox::Attempt> = r.attempts.iter().filter(|a| !a.canary_hits.is_empty()).collect();
    if !canary.is_empty() {
        let mut hits: Vec<String> = canary.iter().flat_map(|a| a.canary_hits.iter().cloned()).collect();
        hits.sort();
        hits.dedup();
        let mut targets: Vec<String> = canary.iter().map(|a| a.target.clone()).collect();
        targets.sort();
        targets.dedup();
        let first = canary[0];
        let mut f = Finding::new(
            "sandbox.canary-exfil",
            Severity::Confirmed,
            Source::Sandbox,
            "sent planted credentials off the machine",
            format!(
                "the sandbox planted fake secrets; {} left in outbound traffic to {} (during {}, {} run)",
                hits.join(", "),
                targets.join(", "),
                first.phase,
                first.run
            ),
        );
        f.phase = parse_phase(&first.phase);
        f.evidence = first.payload_preview.clone();
        f.destinations = targets;
        f.new_since_previous = true;
        out.push(f);
    }

    let egress: Vec<&crate::sandbox::Attempt> =
        r.attempts.iter().filter(|a| a.canary_hits.is_empty() && !is_registry(&a.target)).collect();
    if !egress.is_empty() {
        let mut targets: Vec<String> = egress.iter().map(|a| format!("{} {}", a.kind, a.target)).collect();
        targets.sort();
        targets.dedup();
        let mut f = Finding::new(
            "sandbox.blocked-egress",
            Severity::High,
            Source::Sandbox,
            "tried to reach the network when installed or loaded",
            format!("blocked: {}", crate::util::clip(&targets.join("; "), 400)),
        );
        f.phase = egress.iter().map(|a| parse_phase(&a.phase)).max().unwrap_or(Phase::Unknown);
        f.destinations = egress.iter().map(|a| a.target.clone()).collect();
        f.evidence = egress.iter().find_map(|a| a.payload_preview.clone());
        out.push(f);
    }

    let reads: Vec<&crate::sandbox::FileRead> = r.file_reads.iter().filter(|fr| analyze::js::sensitive_path(&fr.path).is_some()).collect();
    if !reads.is_empty() {
        let mut paths: Vec<String> = reads.iter().map(|fr| fr.path.clone()).collect();
        paths.sort();
        paths.dedup();
        let mut f = Finding::new(
            "sandbox.secret-read",
            Severity::High,
            Source::Sandbox,
            "read planted credential files",
            format!("read {}", paths.join(", ")),
        );
        f.phase = reads.iter().map(|fr| parse_phase(&fr.phase)).max().unwrap_or(Phase::Unknown);
        out.push(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{Attempt, FileRead, SandboxReport};

    #[test]
    fn sri_comparison() {
        assert!(sri_equal("sha512-abc", "sha512-abc"));
        assert!(sri_equal("sha1-x sha512-abc", "sha512-abc"));
        assert!(!sri_equal("sha512-abc", "sha512-abd"));
    }

    #[test]
    fn sandbox_report_to_findings() {
        let r = SandboxReport {
            status: "ok".into(),
            reason: None,
            runs: vec!["dev".into(), "ci".into()],
            attempts: vec![
                Attempt { kind: "http".into(), target: "https://45.77.12.9/c".into(), phase: "install".into(), run: "ci".into(), payload_preview: Some("eyJ…".into()), canary_hits: vec!["npm-token".into()] },
                Attempt { kind: "dns".into(), target: "x.oast.fun".into(), phase: "import".into(), run: "dev".into(), payload_preview: None, canary_hits: vec![] },
                Attempt { kind: "http".into(), target: "https://registry.npmjs.org/x".into(), phase: "install".into(), run: "dev".into(), payload_preview: None, canary_hits: vec![] },
            ],
            file_reads: vec![FileRead { path: "~/.npmrc".into(), phase: "install".into(), run: "dev".into() }],
            duration_ms: 1000,
        };
        let f = sandbox_findings(&r, "https://registry.npmjs.org");
        let ids: Vec<&str> = f.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["sandbox.canary-exfil", "sandbox.blocked-egress", "sandbox.secret-read"]);
        assert_eq!(f[0].severity, Severity::Confirmed);
        assert!(f[0].detail.contains("npm-token"));
        assert!(!f[1].detail.contains("registry.npmjs.org"), "registry traffic is allowed");
        assert_eq!(f[2].phase, Phase::Install);
    }
}
