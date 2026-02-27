use crate::error::{HermesError, Result};
use crate::network::message::HermesMessage;
use iroh::EndpointAddr;
use sled::Db;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Maximum age of a queued message before it is expired and dropped (24 hours).
const MAX_MESSAGE_AGE_SECS: u64 = 86_400;

/// A single queued message with all context needed for retry.
/// (dest_ss58, dest_addr, message, retry_count, subnet_id, enqueued_at)
pub type QueueEntry = (String, EndpointAddr, HermesMessage, u32, Option<u16>, u64);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct QueuedItem {
    dest_ss58: String,
    dest_addr: EndpointAddr,
    message: HermesMessage,
    #[serde(default)]
    retry_count: u32,
    #[serde(default)]
    subnet_id: Option<u16>,
    /// Unix timestamp when the message was first enqueued.
    #[serde(default)]
    enqueued_at: u64,
}

/// A persistent offline buffer utilizing `sled` directly on disk.
#[derive(Clone)]
pub struct MessageQueue {
    db: Db,
}

impl MessageQueue {
    /// Opens or creates the sled database in the designated standard directory.
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Result<Self> {
        let db_path = storage_dir.as_ref().join("hermes_queue.db");
        let db = sled::open(db_path).map_err(HermesError::Database)?;
        Ok(Self { db })
    }

    /// Pushes a new message into the persistent queue (retry_count = 0).
    pub fn push(
        &self,
        dest_ss58: &str,
        dest_addr: EndpointAddr,
        message: &HermesMessage,
        subnet_id: Option<u16>,
    ) -> Result<()> {
        self.push_internal(dest_ss58, dest_addr, message, 0, subnet_id, now_secs())
    }

    /// Re-queues a message with an existing retry count (used by the retry worker).
    /// Preserves the original enqueue timestamp for TTL enforcement.
    pub fn push_retry(
        &self,
        dest_ss58: &str,
        dest_addr: EndpointAddr,
        message: &HermesMessage,
        retry_count: u32,
        subnet_id: Option<u16>,
        enqueued_at: u64,
    ) -> Result<()> {
        self.push_internal(dest_ss58, dest_addr, message, retry_count, subnet_id, enqueued_at)
    }

    fn push_internal(
        &self,
        dest_ss58: &str,
        dest_addr: EndpointAddr,
        message: &HermesMessage,
        retry_count: u32,
        subnet_id: Option<u16>,
        enqueued_at: u64,
    ) -> Result<()> {
        let unique_id = Uuid::new_v4().to_string();
        let key = format!("{}_{}", dest_ss58, unique_id);

        let item = QueuedItem {
            dest_ss58: dest_ss58.to_string(),
            dest_addr,
            message: message.clone(),
            retry_count,
            subnet_id,
            enqueued_at,
        };
        let encoded_bytes = serde_json::to_vec(&item)?;

        self.db
            .insert(key.as_bytes(), encoded_bytes)
            .map_err(HermesError::Database)?;
        Ok(())
    }

    /// Pops a single pending message from the queue by deleting and returning it.
    /// Automatically drops messages older than `MAX_MESSAGE_AGE_SECS`.
    /// Returns `(dest_ss58, dest_addr, message, retry_count, subnet_id, enqueued_at)` or None if the queue is empty.
    pub fn pop_next(&self) -> Result<Option<QueueEntry>> {
        let now = now_secs();
        loop {
            let entry = match self.db.iter().next() {
                Some(result) => result.map_err(HermesError::Database)?,
                None => return Ok(None),
            };

            let (key, val) = entry;
            self.db.remove(&key).map_err(HermesError::Database)?;

            let item: QueuedItem = serde_json::from_slice(&val)?;

            // TTL enforcement: drop messages older than MAX_MESSAGE_AGE_SECS
            if item.enqueued_at > 0 && now.saturating_sub(item.enqueued_at) > MAX_MESSAGE_AGE_SECS {
                tracing::debug!(
                    dest = %item.dest_ss58,
                    age_secs = now - item.enqueued_at,
                    "Dropping expired queued message"
                );
                continue;
            }

            return Ok(Some((
                item.dest_ss58,
                item.dest_addr,
                item.message,
                item.retry_count,
                item.subnet_id,
                item.enqueued_at,
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::PublicKey;
    use tempfile::tempdir;

    #[test]
    fn test_queue_push_pop_order() {
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg1 = HermesMessage {
            action: "test1".into(),
            sender_ss58: "alice".into(),
            payload: vec![1, 2, 3],
        };
        let msg2 = HermesMessage {
            action: "test2".into(),
            sender_ss58: "alice".into(),
            payload: vec![4, 5, 6],
        };

        queue.push("bob1", dest_addr.clone(), &msg1, None).unwrap();
        queue
            .push("bob2", dest_addr.clone(), &msg2, Some(42))
            .unwrap();

        let popped1 = queue.pop_next().unwrap().unwrap();
        let popped2 = queue.pop_next().unwrap().unwrap();
        let popped3 = queue.pop_next().unwrap();

        assert!(popped3.is_none());
        assert!(popped1.2.action == "test1" || popped1.2.action == "test2");
        assert!(popped2.2.action == "test1" || popped2.2.action == "test2");
        assert_ne!(popped1.2.action, popped2.2.action);
    }

    #[test]
    fn test_queue_preserves_dest_ss58() {
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg = HermesMessage {
            action: "test".into(),
            sender_ss58: "alice".into(),
            payload: vec![1],
        };

        queue
            .push("target_ss58_address", dest_addr.clone(), &msg, None)
            .unwrap();

        let (dest_ss58, _, _, _, _, _) = queue.pop_next().unwrap().unwrap();
        assert_eq!(dest_ss58, "target_ss58_address");
    }

    #[test]
    fn test_queue_retry_count_preserved() {
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg = HermesMessage {
            action: "test".into(),
            sender_ss58: "alice".into(),
            payload: vec![1],
        };

        queue
            .push_retry("target", dest_addr.clone(), &msg, 5, Some(7), now_secs())
            .unwrap();

        let (_, _, _, retry_count, subnet_id, _) = queue.pop_next().unwrap().unwrap();
        assert_eq!(retry_count, 5);
        assert_eq!(subnet_id, Some(7));
    }

    #[test]
    fn test_queue_subnet_id_none_roundtrip() {
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg = HermesMessage {
            action: "test".into(),
            sender_ss58: "alice".into(),
            payload: vec![1],
        };

        queue.push("target", dest_addr.clone(), &msg, None).unwrap();
        let (_, _, _, _, subnet_id, _) = queue.pop_next().unwrap().unwrap();
        assert_eq!(subnet_id, None);
    }

    #[test]
    fn test_queue_subnet_id_some_roundtrip() {
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg = HermesMessage {
            action: "test".into(),
            sender_ss58: "alice".into(),
            payload: vec![1],
        };

        queue
            .push("target", dest_addr.clone(), &msg, Some(42))
            .unwrap();
        let (_, _, _, _, subnet_id, _) = queue.pop_next().unwrap().unwrap();
        assert_eq!(subnet_id, Some(42));
    }

    #[test]
    fn test_queue_mixed_subnet_ids() {
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg = HermesMessage {
            action: "test".into(),
            sender_ss58: "alice".into(),
            payload: vec![1],
        };

        // Push messages with different subnet_ids
        queue.push("a", dest_addr.clone(), &msg, None).unwrap();
        queue.push("b", dest_addr.clone(), &msg, Some(1)).unwrap();
        queue
            .push("c", dest_addr.clone(), &msg, Some(65535))
            .unwrap();

        let mut subnet_ids = Vec::new();
        while let Ok(Some((_, _, _, _, sid, _))) = queue.pop_next() {
            subnet_ids.push(sid);
        }
        assert_eq!(subnet_ids.len(), 3);
        assert!(subnet_ids.contains(&None));
        assert!(subnet_ids.contains(&Some(1)));
        assert!(subnet_ids.contains(&Some(65535)));
    }

    #[test]
    fn test_queue_backward_compat_missing_subnet_id() {
        // Simulate a queued item serialized before subnet_id existed
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg = HermesMessage {
            action: "old_format".into(),
            sender_ss58: "alice".into(),
            payload: vec![1],
        };

        // Manually insert a record without the subnet_id field
        let legacy = serde_json::json!({
            "dest_ss58": "target",
            "dest_addr": serde_json::to_value(&dest_addr).unwrap(),
            "message": serde_json::to_value(&msg).unwrap(),
            "retry_count": 3
        });
        queue
            .db
            .insert(b"legacy_key", serde_json::to_vec(&legacy).unwrap())
            .unwrap();

        let (_, _, popped_msg, retry_count, subnet_id, enqueued_at) = queue.pop_next().unwrap().unwrap();
        assert_eq!(popped_msg.action, "old_format");
        assert_eq!(retry_count, 3);
        assert_eq!(subnet_id, None); // #[serde(default)] ensures None
        assert_eq!(enqueued_at, 0); // #[serde(default)] ensures 0 for legacy items
    }

    #[test]
    fn test_queue_new_message_has_zero_retries() {
        let dir = tempdir().unwrap();
        let queue = MessageQueue::new(dir.path()).unwrap();

        let dest_pubkey = PublicKey::from_bytes(&[0u8; 32]).unwrap();
        let dest_addr = EndpointAddr::from(dest_pubkey);

        let msg = HermesMessage {
            action: "test".into(),
            sender_ss58: "alice".into(),
            payload: vec![1],
        };

        queue.push("target", dest_addr.clone(), &msg, None).unwrap();

        let (_, _, _, retry_count, subnet_id, _) = queue.pop_next().unwrap().unwrap();
        assert_eq!(retry_count, 0);
        assert_eq!(subnet_id, None);
    }
}
