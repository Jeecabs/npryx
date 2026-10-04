//! npryx-scan: the optional remote scanner behind `npryx`.
//!
//! Remote scanning is opt-in on the client. This crate is the same service
//! whether it's the hosted instance or self-hosted; API keys are the only
//! difference. Contract: docs/scan-api.md.

pub mod analyze;
pub mod cache;
pub mod config;
pub mod diff;
pub mod model;
pub mod osv;
pub mod ratelimit;
pub mod registry;
pub mod sandbox;
pub mod scan;
pub mod server;
pub mod sign;
pub mod tarball;
pub mod util;

use std::net::SocketAddr;

/// Start the server with `cfg` on an already-bound listener.
pub async fn serve(cfg: config::Config, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    let keys = sign::Keys::load_or_create(&cfg.signing_key)?;
    let scanner = scan::Scanner::new(cfg)?;
    let state = server::AppState::new(scanner, keys);
    let app = server::router(state);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
}
