//! Filesystem cache. Everything is keyed by analyzer version + integrity, so a
//! new analyzer release naturally re-scans, and a cached entry can never be
//! served for different bytes.

use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};

pub struct Cache {
    root: PathBuf,
}

impl Cache {
    pub fn new(dir: &Path) -> std::io::Result<Self> {
        let root = dir.join(crate::model::ANALYZER.replace('/', "-"));
        std::fs::create_dir_all(root.join("analysis"))?;
        std::fs::create_dir_all(root.join("result"))?;
        Ok(Cache { root })
    }

    fn key(integrity: &str) -> String {
        crate::util::sha256_hex(integrity.as_bytes())
    }

    fn analysis_path(&self, integrity: &str) -> PathBuf {
        self.root.join("analysis").join(format!("{}.json", Self::key(integrity)))
    }

    fn result_path(&self, integrity: &str, deep: bool) -> PathBuf {
        self.root.join("result").join(format!("{}-{}.json", Self::key(integrity), deep as u8))
    }

    fn read<T: DeserializeOwned>(p: &Path) -> Option<T> {
        serde_json::from_slice(&std::fs::read(p).ok()?).ok()
    }

    fn write<T: Serialize>(p: &Path, v: &T) {
        let tmp = p.with_extension(format!("tmp{}", std::process::id()));
        if let Ok(bytes) = serde_json::to_vec(v) {
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }

    pub fn get_analysis<T: DeserializeOwned>(&self, integrity: &str) -> Option<T> {
        Self::read(&self.analysis_path(integrity))
    }

    pub fn put_analysis<T: Serialize>(&self, integrity: &str, v: &T) {
        Self::write(&self.analysis_path(integrity), v)
    }

    pub fn get_result<T: DeserializeOwned>(&self, integrity: &str, deep: bool) -> Option<T> {
        Self::read(&self.result_path(integrity, deep))
    }

    pub fn put_result<T: Serialize>(&self, integrity: &str, deep: bool, v: &T) {
        Self::write(&self.result_path(integrity, deep), v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_separation() {
        let d = tempfile::tempdir().unwrap();
        let c = Cache::new(d.path()).unwrap();
        c.put_result("sha512-a", false, &serde_json::json!({"v": 1}));
        assert_eq!(c.get_result::<serde_json::Value>("sha512-a", false).unwrap()["v"], 1);
        assert!(c.get_result::<serde_json::Value>("sha512-a", true).is_none(), "deep is a separate entry");
        assert!(c.get_result::<serde_json::Value>("sha512-b", false).is_none());
    }
}
