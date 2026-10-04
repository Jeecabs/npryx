//! Small shared helpers.

use sha2::{Digest, Sha256};

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

pub fn parse_rfc3339(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// npm package name: optional @scope/, URL-safe characters.
pub fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    let ok = |s: &str| {
        !s.is_empty()
            && !s.starts_with('.')
            && !s.starts_with('_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    };
    match name.strip_prefix('@') {
        Some(rest) => match rest.split_once('/') {
            Some((scope, pkg)) => ok(scope) && ok(pkg),
            None => false,
        },
        None => ok(name),
    }
}

pub fn valid_version(v: &str) -> bool {
    !v.is_empty() && v.len() <= 64 && v.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c))
}

pub fn valid_integrity(i: &str) -> bool {
    match i.split_once('-') {
        Some((alg, b64)) => {
            matches!(alg, "sha512" | "sha384" | "sha256" | "sha1")
                && !b64.is_empty()
                && b64.len() <= 128
                && b64.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
        }
        None => false,
    }
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let mut n = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

/// Truncate to `max` chars on a char boundary, adding "…".
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["cowsay", "@scope/pkg", "left-pad", "a.b_c~d"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "@scope", "../x", ".hidden", "a b", "@s/p/q"] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn versions_and_integrity() {
        assert!(valid_version("1.2.3-beta.1+build"));
        assert!(!valid_version("1.2.3; rm -rf"));
        assert!(valid_integrity("sha512-abc+/="));
        assert!(!valid_integrity("md5-abc"));
        assert!(!valid_integrity("sha512-"));
    }

    #[test]
    fn entropy_orders_randomness() {
        assert!(entropy("aaaaaaaaaa") < 0.1);
        assert!(entropy("q9Z/x8Lk2+Vb7Rt1") > 3.5);
    }
}
