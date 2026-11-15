//! The store behind a lock that knows which thread holds it. A thread locking it again while holding it would wait
//! for itself forever (a second `daemon.store()` in an expression whose first guard is still alive is easy to write);
//! here that panics, saying where, instead of hanging the daemon.

use std::ops::{Deref, DerefMut};
use std::panic::Location;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::store::Store;

static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// This thread's number (never 0, which means nobody).
    static THREAD: u64 = NEXT_THREAD.fetch_add(1, Ordering::Relaxed);
}

pub struct Locked {
    store: Mutex<Store>,
    holder: AtomicU64,
}

pub struct Guard<'a> {
    guard: MutexGuard<'a, Store>,
    holder: &'a AtomicU64,
}

impl Locked {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store: Mutex::new(store),
            holder: AtomicU64::new(0),
        }
    }

    /// The store, once the thread holding it lets go.
    ///
    /// # Panics
    ///
    /// When this thread holds it already: waiting would never end.
    #[track_caller]
    pub fn lock(&self) -> Guard<'_> {
        let me = THREAD.with(|thread| *thread);
        assert!(
            self.holder.load(Ordering::Acquire) != me,
            "the store is locked again by the thread that holds it, at {}: that would deadlock",
            Location::caller()
        );
        let guard = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        self.holder.store(me, Ordering::Release);
        Guard {
            guard,
            holder: &self.holder,
        }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // Before the lock itself goes (the guard field drops after this).
        self.holder.store(0, Ordering::Release);
    }
}

impl Deref for Guard<'_> {
    type Target = Store;

    fn deref(&self) -> &Store {
        &self.guard
    }
}

impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut Store {
        &mut self.guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locking_again_on_the_same_thread_panics_instead_of_hanging() {
        let locked = Locked::new(Store::in_memory().unwrap());
        {
            let _first = locked.lock();
            let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _second = locked.lock();
            }));
            assert!(again.is_err());
        }
        // Let go, it locks again; and other threads wait their turn.
        drop(locked.lock());
        let locked = std::sync::Arc::new(locked);
        let other = std::sync::Arc::clone(&locked);
        let held = locked.lock();
        let waiting = std::thread::spawn(move || drop(other.lock()));
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(held);
        waiting.join().unwrap();
    }
}
