//! The app's cache of the node's history (`snitchhiker_client::cache`), shared by the backend's two threads: pages of
//! events are answered from it when it holds them, and everything the node sends is kept in it.

use std::sync::{Arc, Mutex, PoisonError};

use snitchhiker_client::cache::{Cache, Page, cache_dir};
use snitchhiker_core::query::{Context, EventFilter};
use snitchhiker_proto::columns::EventRow;

/// Events kept at most: the newest.
const BUDGET: u64 = 2_000_000;

/// The node's epoch and its cache (`None` without a cache directory).
type Opened = (u64, Option<Cache>);

#[derive(Clone, Default)]
pub struct History {
    /// What is open, once connected.
    inner: Arc<Mutex<Option<Opened>>>,
}

impl History {
    /// Opens the cache of node `epoch` (another epoch's is dropped).
    pub fn connected(&self, epoch: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.as_ref().is_some_and(|(e, _)| *e == epoch) {
            return;
        }
        let cache =
            cache_dir(nix::unistd::getuid().as_raw()).and_then(|dir| Cache::open(&dir, epoch).ok());
        *inner = Some((epoch, cache));
    }

    fn with<T>(&self, f: impl FnOnce(&mut Cache) -> Option<T>) -> Option<T> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner
            .as_mut()
            .and_then(|(_, cache)| cache.as_mut())
            .and_then(f)
    }

    /// The page before `before` for `query`, when the cache holds it.
    pub fn page(&self, before: i64, limit: usize, query: &str) -> Option<Page> {
        let filter = if query.trim().is_empty() {
            None
        } else {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            let cx = Context {
                now_ms,
                uid_of: &crate::views::events::uid_of,
            };
            // A query the node would refuse isn't answered here either.
            Some(EventFilter::parse(query, &cx).ok()?)
        };
        self.with(|cache| {
            cache
                .page(before, limit, query, filter.as_ref())
                .ok()
                .flatten()
        })
    }

    /// Keeps a page the node answered.
    pub fn add_page(
        &self,
        rows: &[EventRow],
        strings: &[(u32, String)],
        before: i64,
        scanned_from: i64,
        query: &str,
    ) {
        self.with(|cache| {
            let before = if before == 0 { i64::MAX } else { before };
            let _ = cache.add_page(rows, strings, before, scanned_from, query);
            let _ = cache.budget(BUDGET);
            Some(())
        });
    }

    /// Keeps live events, from `after + 1` on.
    pub fn add_live(&self, rows: &[EventRow], strings: &[(u32, String)], after: Option<i64>) {
        self.with(|cache| cache.add_live(rows, strings, after).ok());
    }

    /// Forgets events the node no longer has.
    pub fn clamp(&self, oldest: i64) {
        if oldest > 0 {
            self.with(|cache| cache.clamp(oldest).ok());
        }
    }

    /// Events held.
    pub fn len(&self) -> Option<u64> {
        self.with(|cache| cache.len().ok())
    }
}
