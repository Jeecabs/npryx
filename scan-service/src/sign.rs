//! Ed25519 signed envelopes. The signature covers the raw payload bytes, so
//! clients never need JSON canonicalisation: verify, then parse.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct Keys {
    signing: SigningKey,
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Envelope {
    pub payload: String,
    pub sig: String,
    pub key_id: String,
}

impl Keys {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let key_id = crate::util::sha256_hex(signing.verifying_key().as_bytes())[..16].to_string();
        Keys { signing, key_id }
    }

    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("system randomness");
        Self::from_seed(seed)
    }

    /// Load the base64 seed at `path`, creating it (mode 0600) on first start.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        if let Ok(text) = std::fs::read_to_string(path) {
            let bytes = B64
                .decode(text.trim())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "signing key must be 32 bytes"))?;
            return Ok(Self::from_seed(seed));
        }
        let keys = Self::generate();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        std::fs::write(path, B64.encode(keys.signing.to_bytes()) + "\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(keys)
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().as_bytes())
    }

    pub fn seal(&self, payload: &[u8]) -> Envelope {
        let sig = self.signing.sign(payload);
        Envelope { payload: B64.encode(payload), sig: B64.encode(sig.to_bytes()), key_id: self.key_id.clone() }
    }
}

/// Client-side check (used by tests; the npryx CLI does the same in JS).
pub fn open(env: &Envelope, public_b64: &str) -> Option<Vec<u8>> {
    let key: [u8; 32] = B64.decode(public_b64).ok()?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&key).ok()?;
    let sig: [u8; 64] = B64.decode(&env.sig).ok()?.try_into().ok()?;
    let payload = B64.decode(&env.payload).ok()?;
    key.verify(&payload, &Signature::from_bytes(&sig)).ok()?;
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let k = Keys::from_seed([7u8; 32]);
        let env = k.seal(br#"{"verdict":"clean"}"#);
        assert_eq!(open(&env, &k.public_b64()).unwrap(), br#"{"verdict":"clean"}"#);

        let mut forged = env.clone();
        forged.payload = B64.encode(br#"{"verdict":"confirmed"}"#);
        assert!(open(&forged, &k.public_b64()).is_none(), "payload swap must fail");

        let other = Keys::from_seed([8u8; 32]);
        assert!(open(&env, &other.public_b64()).is_none(), "wrong key must fail");
    }

    #[test]
    fn key_file_persists() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("signing.key");
        let a = Keys::load_or_create(&p).unwrap();
        let b = Keys::load_or_create(&p).unwrap();
        assert_eq!(a.public_b64(), b.public_b64());
        assert_eq!(a.key_id.len(), 16);
    }
}
