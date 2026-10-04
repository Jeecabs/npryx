use npryx_scan::{config::Config, sign::Keys};

#[tokio::main]
async fn main() {
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("npryx-scan: {e}");
            std::process::exit(2);
        }
    };
    // `npryx-scan pubkey` prints the public key for clients' NPRYX_SCAN_KEY.
    if std::env::args().nth(1).as_deref() == Some("pubkey") {
        match Keys::load_or_create(&cfg.signing_key) {
            Ok(k) => println!("{}", k.public_b64()),
            Err(e) => {
                eprintln!("npryx-scan: signing key: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let listener = match tokio::net::TcpListener::bind(&cfg.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("npryx-scan: bind {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };
    eprintln!(
        "npryx-scan {} listening on {} (keys: {}, sandbox: {})",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        if cfg.api_keys.is_some() { "required" } else { "open" },
        if cfg.sandbox { "docker" } else { "off" },
    );
    if let Err(e) = npryx_scan::serve(cfg, listener).await {
        eprintln!("npryx-scan: {e}");
        std::process::exit(1);
    }
}
