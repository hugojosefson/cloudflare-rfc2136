use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::model::DnsRecordKind;

type RecordKey = (String, DnsRecordKind);

#[derive(Clone, Default)]
pub(super) struct RecordLocks(Arc<Mutex<BTreeMap<RecordKey, Weak<AsyncMutex<()>>>>>);

impl RecordLocks {
    pub async fn acquire(&self, name: &str, kind: DnsRecordKind) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.0.lock().unwrap_or_else(|error| error.into_inner());
            // Remove unused locks to limit memory use for changing owner names.
            locks.retain(|_, lock| lock.strong_count() > 0);
            let key = (name.trim_end_matches('.').to_ascii_lowercase(), kind);
            let slot = locks.entry(key).or_default();
            match slot.upgrade() {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    *slot = Arc::downgrade(&lock);
                    lock
                }
            }
        };
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn locks_are_per_owner_and_type_and_release_after_cancellation() {
        let locks = RecordLocks::default();
        let first = locks.acquire("host.example.com", DnsRecordKind::Txt).await;
        for (name, kind) in [
            ("other.example.com", DnsRecordKind::Txt),
            ("host.example.com", DnsRecordKind::A),
        ] {
            let guard = tokio::time::timeout(Duration::from_millis(100), locks.acquire(name, kind))
                .await
                .unwrap();
            drop(guard);
        }
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                locks.acquire("HOST.EXAMPLE.COM.", DnsRecordKind::Txt)
            )
            .await
            .is_err()
        );
        drop(first);
        let guard = tokio::time::timeout(
            Duration::from_millis(100),
            locks.acquire("host.example.com", DnsRecordKind::Txt),
        )
        .await
        .unwrap();
        drop(guard);
        let _guard = locks.acquire("new.example.com", DnsRecordKind::Txt).await;
        assert_eq!(locks.0.lock().unwrap().len(), 1);
    }
}
