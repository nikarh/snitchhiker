//! Step-up from another device (plan §4.3, M5): a dangerous action a remote device asks for waits for a local admin
//! (the desktop app on the node, confirmed by polkit, or root) to approve it. A remote device can't approve: it has
//! no local process for polkit to check.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use snitchhiker_proto::v1;

/// How long a request waits for an approval.
pub const WAIT: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct Approvals {
    pending: Mutex<HashMap<u64, (v1::Approval, Option<bool>)>>,
    decided: Condvar,
    next: AtomicU64,
}

impl Approvals {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, (v1::Approval, Option<bool>)>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a request; its id is set.
    pub fn open(&self, mut approval: v1::Approval) -> v1::Approval {
        approval.id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock().insert(approval.id, (approval.clone(), None));
        approval
    }

    /// Waits for request `id` to be decided, up to `timeout`; it is closed either way. `false` unless approved.
    pub fn wait(&self, id: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut pending = self.lock();
        loop {
            if let Some(decision) = pending.get(&id).and_then(|(_, d)| *d) {
                pending.remove(&id);
                return decision;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || !pending.contains_key(&id) {
                pending.remove(&id);
                return false;
            }
            pending = self
                .decided
                .wait_timeout(pending, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Decides an open request; whether there was one.
    pub fn decide(&self, id: u64, approve: bool) -> bool {
        let found = match self.lock().get_mut(&id) {
            Some((_, decision @ None)) => {
                *decision = Some(approve);
                true
            }
            _ => false,
        };
        self.decided.notify_all();
        found
    }

    /// The requests waiting.
    #[must_use]
    pub fn list(&self) -> Vec<v1::Approval> {
        self.lock()
            .values()
            .filter(|(_, d)| d.is_none())
            .map(|(a, _)| a.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_waits_for_its_decision() {
        let approvals = std::sync::Arc::new(Approvals::default());
        let opened = approvals.open(v1::Approval::default());
        assert_eq!(approvals.list().len(), 1);
        let waiting = {
            let approvals = std::sync::Arc::clone(&approvals);
            std::thread::spawn(move || approvals.wait(opened.id, Duration::from_secs(5)))
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(approvals.decide(opened.id, true));
        assert!(waiting.join().unwrap());
        assert_eq!(approvals.list().len(), 0);
        assert!(!approvals.decide(opened.id, true));
        let unanswered = approvals.open(v1::Approval::default());
        assert!(!approvals.wait(unanswered.id, Duration::from_millis(10)));
    }
}
