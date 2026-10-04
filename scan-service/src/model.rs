//! Wire types — the `ScanResult` payload from docs/scan-api.md, field for field.

use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;
pub const ANALYZER: &str = concat!("npryx-scan/", env!("CARGO_PKG_VERSION"));

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Confirmed,
}

impl Severity {
    /// One step down — used for findings that already existed in the previous
    /// version (baseline). Never below info.
    pub fn downgrade(self) -> Severity {
        match self {
            Severity::Confirmed => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low | Severity::Info => Severity::Info,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Unknown,
    Runtime,
    Import,
    Install,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Static,
    Sandbox,
    Registry,
    Osv,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub phase: Phase,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub evidence: Option<String>,
    pub destinations: Vec<String>,
    pub new_since_previous: bool,
    pub source: Source,
}

impl Finding {
    pub fn new(id: &str, severity: Severity, source: Source, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Finding {
            id: id.to_string(),
            severity,
            title: title.into(),
            detail: detail.into(),
            phase: Phase::Unknown,
            file: None,
            line: None,
            evidence: None,
            destinations: vec![],
            new_since_previous: false,
            source,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum DestKind {
    RawIp,
    Collector,
    ChatWebhook,
    Paste,
    Tunnel,
    Registry,
    PackageHome,
    KnownTelemetry,
    Other,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Destination {
    pub value: String,
    pub kind: DestKind,
    pub phase: Phase,
    pub new_since_previous: bool,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Network {
    pub destinations: Vec<Destination>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VersionRef {
    pub version: String,
    pub integrity: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Confirmed,
    Suspected,
    Info,
    Clean,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Done,
    Pending,
    IntegrityMismatch,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanResult {
    pub schema: u32,
    pub status: Status,
    pub analyzer: String,
    pub name: String,
    pub version: String,
    pub integrity: String,
    pub registry_integrity: Option<String>,
    pub retry_after_ms: Option<u64>,
    pub scanned_at: Option<String>,
    pub previous: Option<VersionRef>,
    pub verdict: Option<Verdict>,
    pub findings: Vec<Finding>,
    pub network: Network,
    pub sandbox: Option<crate::sandbox::SandboxReport>,
}

impl ScanResult {
    fn base(name: &str, version: &str, integrity: &str, status: Status) -> Self {
        ScanResult {
            schema: SCHEMA,
            status,
            analyzer: ANALYZER.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            integrity: integrity.to_string(),
            registry_integrity: None,
            retry_after_ms: None,
            scanned_at: None,
            previous: None,
            verdict: None,
            findings: vec![],
            network: Network::default(),
            sandbox: None,
        }
    }

    pub fn pending(name: &str, version: &str, integrity: &str, retry_after_ms: u64) -> Self {
        let mut r = Self::base(name, version, integrity, Status::Pending);
        r.retry_after_ms = Some(retry_after_ms);
        r
    }

    pub fn mismatch(name: &str, version: &str, integrity: &str, registry_integrity: &str) -> Self {
        let mut r = Self::base(name, version, integrity, Status::IntegrityMismatch);
        r.registry_integrity = Some(registry_integrity.to_string());
        r.scanned_at = Some(crate::util::now_rfc3339());
        let mut f = Finding::new(
            "registry.integrity-mismatch",
            Severity::Confirmed,
            Source::Registry,
            "the registry serves different bytes for this version",
            format!(
                "you resolved {integrity} but the registry reports {registry_integrity} for {name}@{version}; npm never lets a published version change"
            ),
        );
        f.evidence = Some(registry_integrity.to_string());
        r.findings.push(f);
        r.verdict = Some(Verdict::Confirmed);
        r
    }

    pub fn done(name: &str, version: &str, integrity: &str) -> Self {
        let mut r = Self::base(name, version, integrity, Status::Done);
        r.scanned_at = Some(crate::util::now_rfc3339());
        r
    }
}

/// Any confirmed → confirmed; else any high → suspected; else any finding → info; else clean.
pub fn verdict(findings: &[Finding]) -> Verdict {
    let max = findings.iter().map(|f| f.severity).max();
    match max {
        Some(Severity::Confirmed) => Verdict::Confirmed,
        Some(Severity::High) => Verdict::Suspected,
        Some(_) => Verdict::Info,
        None => Verdict::Clean,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_ladder() {
        let f = |s| Finding::new("x", s, Source::Static, "", "");
        assert_eq!(verdict(&[]), Verdict::Clean);
        assert_eq!(verdict(&[f(Severity::Info)]), Verdict::Info);
        assert_eq!(verdict(&[f(Severity::Medium), f(Severity::High)]), Verdict::Suspected);
        assert_eq!(verdict(&[f(Severity::High), f(Severity::Confirmed)]), Verdict::Confirmed);
    }

    #[test]
    fn downgrade_never_below_info() {
        assert_eq!(Severity::High.downgrade(), Severity::Medium);
        assert_eq!(Severity::Info.downgrade(), Severity::Info);
    }

    #[test]
    fn serializes_contract_names() {
        let mut f = Finding::new("net.raw-ip", Severity::High, Source::Static, "t", "d");
        f.phase = Phase::Install;
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["severity"], "high");
        assert_eq!(v["phase"], "install");
        assert_eq!(v["source"], "static");
        let d = Destination { value: "1.2.3.4".into(), kind: DestKind::RawIp, phase: Phase::Install, new_since_previous: true, note: None };
        assert_eq!(serde_json::to_value(&d).unwrap()["kind"], "raw-ip");
        assert_eq!(serde_json::to_value(Status::IntegrityMismatch).unwrap(), "integrity_mismatch");
    }
}
