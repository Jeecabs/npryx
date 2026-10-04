//! Tarball download, SRI verification and in-memory unpacking.
//!
//! The integrity is checked BEFORE anything is unpacked: the cache is keyed by
//! integrity, so verifying it is what makes a cached result trustworthy.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures::StreamExt;
use sha2::Digest;
use std::io::Read;

#[derive(Debug)]
pub enum TarError {
    TooLarge(u64),
    Integrity { expected: String, actual: String },
    Fetch(String),
    Corrupt(String),
}

impl std::fmt::Display for TarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TarError::TooLarge(n) => write!(f, "tarball exceeds size cap ({n} bytes)"),
            TarError::Integrity { expected, actual } => write!(f, "integrity mismatch: expected {expected}, got {actual}"),
            TarError::Fetch(e) => write!(f, "tarball fetch failed: {e}"),
            TarError::Corrupt(e) => write!(f, "tarball unreadable: {e}"),
        }
    }
}

/// One file from the package, path relative to the package root.
#[derive(Clone, Debug)]
pub struct PkgFile {
    pub path: String,
    pub size: u64,
    /// Present for files we analyze (text, under the per-file cap).
    pub text: Option<String>,
}

pub struct Unpacked {
    pub files: Vec<PkgFile>,
    /// Entries rejected for unsafe paths (absolute, `..`, links out of tree).
    pub rejected: Vec<String>,
}

const PER_FILE_TEXT_CAP: u64 = 4 * 1024 * 1024;

/// Check an SRI string (`sha512-…`, also sha384/sha256/sha1 for old packages).
pub fn verify_sri(bytes: &[u8], sri: &str) -> Result<(), TarError> {
    // An SRI may list several hashes separated by spaces; any match is enough.
    let mut last_actual = String::new();
    for part in sri.split_whitespace() {
        let Some((alg, expected)) = part.split_once('-') else { continue };
        let actual = match alg {
            "sha512" => B64.encode(sha2::Sha512::digest(bytes)),
            "sha384" => B64.encode(sha2::Sha384::digest(bytes)),
            "sha256" => B64.encode(sha2::Sha256::digest(bytes)),
            "sha1" => B64.encode(sha1_digest(bytes)),
            _ => continue,
        };
        if actual == expected {
            return Ok(());
        }
        last_actual = format!("{alg}-{actual}");
    }
    Err(TarError::Integrity { expected: sri.to_string(), actual: last_actual })
}

pub fn sri_sha512(bytes: &[u8]) -> String {
    format!("sha512-{}", B64.encode(sha2::Sha512::digest(bytes)))
}

/// Minimal SHA-1 (only for verifying legacy `sha1-` integrities; never for signing).
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Download with a compressed-size cap.
pub async fn download(client: &reqwest::Client, url: &str, cap: u64) -> Result<Vec<u8>, TarError> {
    let resp = client.get(url).send().await.map_err(|e| TarError::Fetch(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(TarError::Fetch(format!("HTTP {}", resp.status())));
    }
    if let Some(len) = resp.content_length() {
        if len > cap {
            return Err(TarError::TooLarge(len));
        }
    }
    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| TarError::Fetch(e.to_string()))?;
        out.extend_from_slice(&chunk);
        if out.len() as u64 > cap {
            return Err(TarError::TooLarge(out.len() as u64));
        }
    }
    Ok(out)
}

fn safe_rel_path(raw: &std::path::Path) -> Option<String> {
    use std::path::Component;
    let mut parts = Vec::new();
    for c in raw.components() {
        match c {
            Component::Normal(p) => parts.push(p.to_str()?.to_string()),
            Component::CurDir => {}
            _ => return None, // RootDir, Prefix, ParentDir
        }
    }
    // npm tarballs wrap everything in one top-level dir (usually "package/").
    if parts.len() < 2 {
        return None;
    }
    Some(parts[1..].join("/"))
}

fn is_text_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".js", ".cjs", ".mjs", ".json", ".sh", ".ts", ".cts", ".mts"].iter().any(|e| lower.ends_with(e))
}

/// gunzip + untar in memory. `cap` bounds the total unpacked size.
pub fn unpack(tgz: &[u8], cap: u64) -> Result<Unpacked, TarError> {
    let gz = flate2::read::GzDecoder::new(tgz);
    let mut archive = tar::Archive::new(gz.take(cap + 1));
    let mut files = Vec::new();
    let mut rejected = Vec::new();
    let mut total: u64 = 0;
    let entries = archive.entries().map_err(|e| TarError::Corrupt(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| TarError::Corrupt(e.to_string()))?;
        let raw_path = entry.path().map_err(|e| TarError::Corrupt(e.to_string()))?.into_owned();
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            rejected.push(raw_path.display().to_string());
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        let Some(path) = safe_rel_path(&raw_path) else {
            rejected.push(raw_path.display().to_string());
            continue;
        };
        let size = entry.size();
        total += size;
        if total > cap {
            return Err(TarError::TooLarge(total));
        }
        let text = if is_text_candidate(&path) && size <= PER_FILE_TEXT_CAP {
            let mut buf = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut buf).map_err(|e| TarError::Corrupt(e.to_string()))?;
            String::from_utf8(buf).ok()
        } else {
            std::io::copy(&mut entry, &mut std::io::sink()).map_err(|e| TarError::Corrupt(e.to_string()))?;
            None
        };
        files.push(PkgFile { path, size, text });
    }
    Ok(Unpacked { files, rejected })
}

#[cfg(test)]
pub(crate) mod testutil {
    /// Build a .tgz from (path, contents). Paths are used verbatim (so tests can
    /// include hostile ones).
    pub fn tgz(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            for (path, body) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_entry_type(tar::EntryType::Regular);
                // set_path refuses "..", so write the name bytes directly.
                let name = path.as_bytes();
                h.as_old_mut().name[..name.len()].copy_from_slice(name);
                h.set_cksum();
                b.append(&h, body.as_bytes()).unwrap();
            }
            b.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        gz.finish().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sri_sha512_and_sha1() {
        let data = b"hello";
        assert!(verify_sri(data, &sri_sha512(data)).is_ok());
        // sha1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        let sha1 = format!("sha1-{}", B64.encode(hex::decode("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").unwrap()));
        assert!(verify_sri(data, &sha1).is_ok());
        assert!(matches!(verify_sri(b"hellO", &sri_sha512(data)), Err(TarError::Integrity { .. })));
    }

    #[test]
    fn unpacks_and_strips_root() {
        let t = testutil::tgz(&[("package/package.json", "{\"name\":\"x\"}"), ("package/lib/a.js", "1")]);
        let u = unpack(&t, 1 << 20).unwrap();
        let paths: Vec<_> = u.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["package.json", "lib/a.js"]);
        assert!(u.files[1].text.is_some());
    }

    #[test]
    fn rejects_path_traversal() {
        let t = testutil::tgz(&[("package/../../etc/evil.js", "x"), ("/abs/evil.js", "y"), ("package/ok.js", "z")]);
        let u = unpack(&t, 1 << 20).unwrap();
        assert_eq!(u.files.len(), 1);
        assert_eq!(u.files[0].path, "ok.js");
        assert_eq!(u.rejected.len(), 2);
    }

    #[test]
    fn enforces_unpacked_cap() {
        let big = "a".repeat(10_000);
        let t = testutil::tgz(&[("package/big.js", &big)]);
        assert!(matches!(unpack(&t, 1000), Err(TarError::TooLarge(_))));
    }
}
