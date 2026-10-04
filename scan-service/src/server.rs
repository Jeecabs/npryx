//! HTTP layer: auth, rate limits, in-flight dedupe, wait-then-202, signed
//! envelopes, and one JSON usage line per request (what a hosted deployment
//! meters from).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{watch, Semaphore};

use crate::model::ScanResult;
use crate::ratelimit::RateLimiter;
use crate::scan::{Outcome, Scanner};
use crate::sign::Keys;

type Slot = watch::Receiver<Option<Arc<Outcome>>>;

pub struct AppState {
    pub scanner: Arc<Scanner>,
    pub keys: Keys,
    limiter: RateLimiter,
    inflight: Mutex<HashMap<(String, bool), Slot>>,
    permits: Arc<Semaphore>,
}

impl AppState {
    pub fn new(scanner: Arc<Scanner>, keys: Keys) -> Arc<Self> {
        let n = scanner.cfg.max_concurrent_scans.max(1);
        Arc::new(AppState {
            scanner,
            keys,
            limiter: RateLimiter::default(),
            inflight: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(n)),
        })
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/scan/{name}/{version}", get(scan_plain))
        .route("/v1/scan/{scope}/{name}/{version}", get(scan_scoped))
        .with_state(state)
}

async fn pubkey(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({ "alg": "ed25519", "key_id": s.keys.key_id, "key": s.keys.public_b64() }))
}

#[derive(Deserialize)]
struct ScanQuery {
    integrity: Option<String>,
    deep: Option<String>,
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn signed(s: &AppState, status: StatusCode, r: &ScanResult) -> Response {
    let payload = serde_json::to_vec(r).unwrap_or_default();
    (status, Json(s.keys.seal(&payload))).into_response()
}

fn client_ip(headers: &HeaderMap, addr: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                return first.trim().to_string();
            }
        }
    }
    addr.map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".into())
}

fn usage(label: &str, ip: &str, name: &str, version: &str, deep: bool, cache: &str, status: u16) {
    println!(
        "{}",
        json!({
            "ts": crate::util::now_rfc3339(),
            "event": "scan",
            "key": label,
            "ip": ip,
            "package": format!("{name}@{version}"),
            "deep": deep,
            "cache": cache,
            "status": status,
        })
    );
}

async fn scan_plain(
    State(s): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((name, version)): Path<(String, String)>,
    Query(q): Query<ScanQuery>,
) -> Response {
    handle(s, Some(addr), headers, name, version, q).await
}

async fn scan_scoped(
    State(s): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((scope, name, version)): Path<(String, String, String)>,
    Query(q): Query<ScanQuery>,
) -> Response {
    if !scope.starts_with('@') {
        return error(StatusCode::BAD_REQUEST, "bad package name");
    }
    handle(s, Some(addr), headers, format!("{scope}/{name}"), version, q).await
}

async fn handle(s: Arc<AppState>, addr: Option<SocketAddr>, headers: HeaderMap, name: String, version: String, q: ScanQuery) -> Response {
    let cfg = &s.scanner.cfg;
    let ip = client_ip(&headers, addr, cfg.trust_proxy);

    // auth
    let mut label = "open".to_string();
    if let Some(keys) = &cfg.api_keys {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
            .map(str::trim);
        let Some(k) = token.and_then(|t| keys.get(t)) else {
            usage("-", &ip, &name, &version, false, "-", 401);
            return error(StatusCode::UNAUTHORIZED, "a valid API key is required (Authorization: Bearer <key>)");
        };
        label = k.label.clone();
        if let Err(wait) = s.limiter.check(&format!("key:{}", k.key), k.rpm) {
            return too_many(wait);
        }
    }
    if let Err(wait) = s.limiter.check(&format!("ip:{ip}"), cfg.ip_rpm) {
        return too_many(wait);
    }

    // validation
    let integrity = q.integrity.unwrap_or_default();
    let deep = matches!(q.deep.as_deref(), Some("1") | Some("true"));
    if !crate::util::valid_name(&name) {
        return error(StatusCode::BAD_REQUEST, "bad package name");
    }
    if !crate::util::valid_version(&version) {
        return error(StatusCode::BAD_REQUEST, "bad version");
    }
    if !crate::util::valid_integrity(&integrity) {
        return error(StatusCode::BAD_REQUEST, "integrity must be an SRI string like sha512-…");
    }

    // fast path
    if let Some(r) = s.scanner.cached(&integrity, deep).await {
        usage(&label, &ip, &name, &version, deep, "hit", 200);
        return signed(&s, StatusCode::OK, &r);
    }

    // one scan per (integrity, deep), however many people ask
    let mut rx = {
        let mut map = s.inflight.lock().unwrap_or_else(|e| e.into_inner());
        let key = (integrity.clone(), deep);
        match map.get(&key) {
            Some(rx) => rx.clone(),
            None => {
                let (tx, rx) = watch::channel(None);
                map.insert(key.clone(), rx.clone());
                let st = s.clone();
                let (n, v, i) = (name.clone(), version.clone(), integrity.clone());
                tokio::spawn(async move {
                    let outcome = match st.permits.clone().acquire_owned().await {
                        Ok(_permit) => st.scanner.scan(&n, &v, &i, deep).await,
                        Err(_) => Outcome::Upstream("shutting down".into()),
                    };
                    let _ = tx.send(Some(Arc::new(outcome)));
                    st.inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
                });
                rx
            }
        }
    };

    let waited = tokio::time::timeout(Duration::from_millis(cfg.wait_ms), rx.wait_for(|v| v.is_some())).await;
    let outcome = match waited {
        Ok(Ok(v)) => v.clone(),
        _ => None,
    };
    let Some(outcome) = outcome else {
        let retry = if deep { 15_000 } else { 2_000 };
        usage(&label, &ip, &name, &version, deep, "miss", 202);
        return signed(&s, StatusCode::ACCEPTED, &ScanResult::pending(&name, &version, &integrity, retry));
    };
    let (status, resp) = match outcome.as_ref() {
        Outcome::Done(r) => (200, signed(&s, StatusCode::OK, r)),
        Outcome::Mismatch(r) => (409, signed(&s, StatusCode::CONFLICT, r)),
        Outcome::NotFound => (404, error(StatusCode::NOT_FOUND, "no such package or version")),
        Outcome::TooLarge => (413, error(StatusCode::PAYLOAD_TOO_LARGE, "tarball over the size cap")),
        Outcome::Upstream(e) => (502, error(StatusCode::BAD_GATEWAY, e)),
    };
    usage(&label, &ip, &name, &version, deep, "miss", status);
    resp
}

fn too_many(wait: u64) -> Response {
    let mut r = error(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
        r.headers_mut().insert("retry-after", v);
    }
    r
}
