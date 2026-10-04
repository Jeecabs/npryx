//! Token buckets keyed by API key label or client IP.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// Take one token from `key`'s bucket (capacity = rpm, refilled at rpm/60
    /// per second). Err carries seconds until a token is available.
    pub fn check(&self, key: &str, rpm: u32) -> Result<(), u64> {
        self.check_at(key, rpm, Instant::now())
    }

    pub fn check_at(&self, key: &str, rpm: u32, now: Instant) -> Result<(), u64> {
        let cap = rpm.max(1) as f64;
        let rate = cap / 60.0;
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 100_000 {
            map.retain(|_, b| now.duration_since(b.last).as_secs() < 120);
        }
        let b = map.entry(key.to_string()).or_insert(Bucket { tokens: cap, last: now });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate).min(cap);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - b.tokens) / rate).ceil().max(1.0) as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_refill() {
        let rl = RateLimiter::default();
        let t0 = Instant::now();
        for _ in 0..60 {
            assert!(rl.check_at("k", 60, t0).is_ok());
        }
        let wait = rl.check_at("k", 60, t0).unwrap_err();
        assert_eq!(wait, 1);
        assert!(rl.check_at("k", 60, t0 + Duration::from_secs(1)).is_ok(), "one token per second");
        assert!(rl.check_at("other", 60, t0).is_ok(), "buckets are per key");
    }
}
