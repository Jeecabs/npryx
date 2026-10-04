//! Compare this version with the previous one. The diff is what keeps noise
//! down: behaviour the package always had is baseline (downgraded one step);
//! behaviour that's new in this release is what hijacks look like.

use std::collections::{BTreeSet, HashSet};

use crate::analyze::{PackageAnalysis, INSTALL_HOOKS};
use crate::model::{DestKind, Destination, Finding, Network, Phase, Severity, Source};
use crate::registry::VersionMeta;

fn same_finding(a: &Finding, b: &Finding) -> bool {
    if a.id != b.id {
        return false;
    }
    if a.id.starts_with("net.") && !a.destinations.is_empty() {
        let hosts = |f: &Finding| -> BTreeSet<String> {
            f.destinations.iter().filter_map(|u| crate::analyze::dest::host_of(u)).collect()
        };
        return hosts(a) == hosts(b);
    }
    a.file == b.file || (a.evidence.is_some() && a.evidence == b.evidence)
}

/// Static findings + destinations for `cur`, judged against `prev`.
pub fn compose(cur: &PackageAnalysis, prev: Option<&PackageAnalysis>) -> (Vec<Finding>, Network) {
    let mut findings = Vec::new();
    for f in &cur.findings {
        let mut f = f.clone();
        match prev {
            Some(p) if p.findings.iter().any(|old| same_finding(&f, old)) => {
                f.severity = f.severity.downgrade();
                f.new_since_previous = false;
                if f.id != "net.expected-download" {
                    f.detail.push_str(" (also in the previous version)");
                }
            }
            Some(_) => f.new_since_previous = true,
            None => f.new_since_previous = false,
        }
        findings.push(f);
    }

    let prev_hosts: HashSet<&str> = prev.map(|p| p.dests.iter().map(|d| d.host.as_str()).collect()).unwrap_or_default();
    let mut network = Network::default();
    for d in &cur.dests {
        let is_new = prev.is_some() && !prev_hosts.contains(d.host.as_str());
        network.destinations.push(Destination {
            value: d.host.clone(),
            kind: d.kind,
            phase: d.phase,
            new_since_previous: is_new,
            note: d.note.clone(),
        });
        // net.new-destination: an unclassified host that's new in this release,
        // or (first release) one contacted while installing.
        if d.kind == DestKind::Other && (is_new || (prev.is_none() && d.phase == Phase::Install)) {
            let mut f = Finding::new(
                "net.new-destination",
                Severity::Medium,
                Source::Static,
                if is_new { "talks to a host the previous version never contacted" } else { "contacts a host while installing" },
                format!("{} ({})", d.host, d.url),
            );
            f.phase = d.phase;
            f.file = Some(d.file.clone());
            f.line = (d.line > 0).then_some(d.line);
            f.destinations = vec![d.url.clone()];
            f.new_since_previous = is_new;
            findings.push(f);
        }
    }
    (findings, network)
}

/// Registry-level signals that need both manifests.
pub fn registry_findings(cur: &VersionMeta, cur_scripts: &std::collections::BTreeMap<String, String>, prev: Option<(&VersionMeta, &std::collections::BTreeMap<String, String>)>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((prev, prev_scripts)) = prev else { return out };

    let added: Vec<String> = INSTALL_HOOKS
        .iter()
        .filter(|h| cur_scripts.contains_key(**h) && !prev_scripts.contains_key(**h))
        .map(|h| format!("{h}: {}", cur_scripts[*h]))
        .collect();
    if !added.is_empty() {
        let mut f = Finding::new(
            "script.install-added",
            Severity::High,
            Source::Registry,
            "adds an install script",
            format!("{} — not present in {}", added.join("; "), prev.version),
        );
        f.phase = Phase::Install;
        f.file = Some("package.json".into());
        f.new_since_previous = true;
        out.push(f);
    }

    if prev.has_provenance && !cur.has_provenance {
        let mut f = Finding::new(
            "provenance.dropped",
            Severity::High,
            Source::Registry,
            "published without provenance this time",
            format!(
                "{} was built and signed by CI; this version wasn't — consistent with a publish from a stolen token",
                prev.version
            ),
        );
        f.new_since_previous = true;
        out.push(f);
    }

    let a: BTreeSet<&String> = cur.maintainers.iter().collect();
    let b: BTreeSet<&String> = prev.maintainers.iter().collect();
    let publisher_changed = cur.publisher.is_some() && prev.publisher.is_some() && cur.publisher != prev.publisher;
    if (a != b && !a.is_empty() && !b.is_empty()) || publisher_changed {
        let added: Vec<&str> = a.difference(&b).map(|s| s.as_str()).collect();
        let removed: Vec<&str> = b.difference(&a).map(|s| s.as_str()).collect();
        let mut parts = Vec::new();
        if !added.is_empty() {
            parts.push(format!("added {}", added.join(", ")));
        }
        if !removed.is_empty() {
            parts.push(format!("removed {}", removed.join(", ")));
        }
        if publisher_changed {
            parts.push(format!(
                "published by {} (previous release by {})",
                cur.publisher.as_deref().unwrap_or("?"),
                prev.publisher.as_deref().unwrap_or("?")
            ));
        }
        let mut f = Finding::new("maintainers.changed", Severity::Medium, Source::Registry, "maintainers changed", parts.join("; "));
        f.new_since_previous = true;
        out.push(f);
    }

    let new_deps: Vec<&String> = cur.dependencies.keys().filter(|k| !prev.dependencies.contains_key(*k)).collect();
    if !new_deps.is_empty() {
        let mut f = Finding::new(
            "deps.added",
            Severity::Low,
            Source::Registry,
            format!("adds {} dependenc{}", new_deps.len(), if new_deps.len() == 1 { "y" } else { "ies" }),
            new_deps.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
        );
        f.new_since_previous = true;
        out.push(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::DestSite;
    use std::collections::BTreeMap;

    fn finding(id: &str, sev: Severity, file: &str) -> Finding {
        let mut f = Finding::new(id, sev, Source::Static, "t", "d");
        f.file = Some(file.into());
        f
    }

    fn site(host: &str, kind: DestKind, phase: Phase) -> DestSite {
        DestSite { host: host.into(), url: format!("https://{host}/x"), kind, phase, file: "a.js".into(), line: 3, note: None }
    }

    #[test]
    fn baseline_findings_are_downgraded_new_ones_flagged() {
        let prev = PackageAnalysis { findings: vec![finding("secret.read", Severity::Medium, "a.js")], ..Default::default() };
        let cur = PackageAnalysis {
            findings: vec![finding("secret.read", Severity::Medium, "a.js"), finding("code.remote-eval", Severity::High, "b.js")],
            ..Default::default()
        };
        let (f, _) = compose(&cur, Some(&prev));
        let old = f.iter().find(|x| x.id == "secret.read").unwrap();
        assert_eq!(old.severity, Severity::Low);
        assert!(!old.new_since_previous);
        let new = f.iter().find(|x| x.id == "code.remote-eval").unwrap();
        assert_eq!(new.severity, Severity::High);
        assert!(new.new_since_previous);
    }

    #[test]
    fn new_unclassified_host_is_new_destination() {
        let prev = PackageAnalysis { dests: vec![site("api.example.com", DestKind::Other, Phase::Import)], ..Default::default() };
        let cur = PackageAnalysis {
            dests: vec![site("api.example.com", DestKind::Other, Phase::Import), site("c2.example.net", DestKind::Other, Phase::Import)],
            ..Default::default()
        };
        let (f, net) = compose(&cur, Some(&prev));
        let nd: Vec<_> = f.iter().filter(|x| x.id == "net.new-destination").collect();
        assert_eq!(nd.len(), 1);
        assert!(nd[0].detail.contains("c2.example.net"));
        assert!(net.destinations.iter().find(|d| d.value == "c2.example.net").unwrap().new_since_previous);
        assert!(!net.destinations.iter().find(|d| d.value == "api.example.com").unwrap().new_since_previous);
    }

    #[test]
    fn first_release_only_flags_install_time_hosts() {
        let cur = PackageAnalysis {
            dests: vec![site("docs.example.com", DestKind::Other, Phase::Runtime), site("x.example.com", DestKind::Other, Phase::Install)],
            ..Default::default()
        };
        let (f, _) = compose(&cur, None);
        let nd: Vec<_> = f.iter().filter(|x| x.id == "net.new-destination").collect();
        assert_eq!(nd.len(), 1);
        assert!(nd[0].detail.contains("x.example.com"));
    }

    #[test]
    fn registry_signals() {
        let prev = VersionMeta {
            version: "1.0.0".into(),
            has_provenance: true,
            maintainers: vec!["alice".into()],
            publisher: Some("alice".into()),
            dependencies: [("a".to_string(), "^1".to_string())].into(),
            ..Default::default()
        };
        let cur = VersionMeta {
            version: "1.0.1".into(),
            has_provenance: false,
            maintainers: vec!["alice".into(), "mallory".into()],
            publisher: Some("mallory".into()),
            dependencies: [("a".to_string(), "^1".to_string()), ("evil-helper".to_string(), "1".to_string())].into(),
            ..Default::default()
        };
        let cur_scripts: BTreeMap<String, String> = [("postinstall".to_string(), "node x.js".to_string())].into();
        let f = registry_findings(&cur, &cur_scripts, Some((&prev, &BTreeMap::new())));
        let ids: Vec<&str> = f.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["script.install-added", "provenance.dropped", "maintainers.changed", "deps.added"]);
        assert!(f[2].detail.contains("mallory"));
        assert!(f[3].detail.contains("evil-helper"));
        assert!(registry_findings(&cur, &cur_scripts, None).is_empty(), "no baseline, no diff findings");
    }
}
