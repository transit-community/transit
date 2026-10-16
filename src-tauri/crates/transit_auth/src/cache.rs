use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Default cache lifetime. Mitigates rapid-session biometric prompt
/// fatigue on macOS while keeping the exposure window short. On
/// screen-lock / sleep events we'll evict eagerly (Phase 2a.1).
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Zeroizing TTL cache used by the registry. Generic over `K` so unit
/// tests can use simple keys, but production only ever instantiates
/// `K = SecretRef`.
///
/// Eviction strategy:
///   - Lazy on every `get` — entries past their deadline are removed
///     before the lookup.
///   - Active sweep via [`Self::evict_expired`] which the registry
///     spawns on a 10s tokio interval as belt-and-suspenders against
///     long idle periods.
///
/// `SecretString` zeroes its buffer on drop, so removing an expired
/// entry is sufficient to scrub the bytes.
pub(crate) struct ZeroizingCache<K: Eq + Hash + Clone + Send> {
    inner: Arc<Mutex<HashMap<K, Entry>>>,
    ttl: Duration,
}

struct Entry {
    value: SecretString,
    deadline: Instant,
}

impl<K: Eq + Hash + Clone + Send> ZeroizingCache<K> {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Try to read an entry. Returns `None` if missing OR expired
    /// (expired entries are removed on the way out — caller's miss
    /// triggers a fresh resolve from the backend).
    pub(crate) async fn get(&self, key: &K) -> Option<SecretString> {
        let mut guard = self.inner.lock().await;
        let now = Instant::now();
        if let Some(entry) = guard.get(key) {
            if entry.deadline > now {
                // SecretString clones cheaply (Arc internally); the
                // original stays in the cache for subsequent hits.
                return Some(SecretString::from(entry.value.expose_secret().to_owned()));
            }
        }
        // Either missing or expired. If expired, drop now so it
        // doesn't linger in memory until the next sweep.
        guard.remove(key);
        None
    }

    /// Insert / overwrite an entry. Caller passes ownership of the
    /// `SecretString`; the cache holds it until eviction and the value
    /// zeroes on drop.
    pub(crate) async fn put(&self, key: K, value: SecretString) {
        let deadline = Instant::now() + self.ttl;
        self.inner
            .lock()
            .await
            .insert(key, Entry { value, deadline });
    }

    /// Remove every entry past its deadline. Called by the background
    /// sweep task spawned in [`SecretRegistry::standard`].
    pub(crate) async fn evict_expired(&self) {
        let now = Instant::now();
        self.inner.lock().await.retain(|_, e| e.deadline > now);
    }

    /// Force-evict a specific key. Called after a successful `enroll`
    /// so the next `resolve_value` round-trips through the backend
    /// rather than handing back a (possibly stale) cached copy.
    pub(crate) async fn invalidate(&self, key: &K) {
        self.inner.lock().await.remove(key);
    }

    /// Drop every entry. Used by the (future) lock/sleep listener.
    #[allow(dead_code)] // wired up in Phase 2a.1
    pub(crate) async fn clear(&self) {
        self.inner.lock().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn hit_within_ttl() {
        let cache: ZeroizingCache<&'static str> = ZeroizingCache::new(Duration::from_secs(60));
        cache.put("k", SecretString::from("v".to_string())).await;
        sleep(Duration::from_secs(30)).await;
        let got = cache.get(&"k").await.expect("hit");
        assert_eq!(got.expose_secret(), "v");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn miss_after_ttl() {
        let cache: ZeroizingCache<&'static str> = ZeroizingCache::new(Duration::from_secs(60));
        cache.put("k", SecretString::from("v".to_string())).await;
        sleep(Duration::from_secs(61)).await;
        assert!(cache.get(&"k").await.is_none());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn evict_expired_drops_old() {
        let cache: ZeroizingCache<&'static str> = ZeroizingCache::new(Duration::from_secs(10));
        cache.put("a", SecretString::from("1".to_string())).await;
        sleep(Duration::from_secs(5)).await;
        cache.put("b", SecretString::from("2".to_string())).await;
        sleep(Duration::from_secs(6)).await;
        cache.evict_expired().await;
        assert!(cache.get(&"a").await.is_none(), "a expired, should be gone");
        assert!(cache.get(&"b").await.is_some(), "b still fresh");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn put_overwrites_and_resets_deadline() {
        let cache: ZeroizingCache<&'static str> = ZeroizingCache::new(Duration::from_secs(60));
        cache.put("k", SecretString::from("v1".to_string())).await;
        sleep(Duration::from_secs(50)).await;
        cache.put("k", SecretString::from("v2".to_string())).await;
        sleep(Duration::from_secs(20)).await;
        // The first put would have expired; the second one is still fresh.
        let got = cache.get(&"k").await.expect("fresh after overwrite");
        assert_eq!(got.expose_secret(), "v2");
    }
}
