use iroh::PublicKey;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Verdict from the global ACL check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclVerdict {
    /// Node is explicitly allowed (or allowlist is empty = open policy).
    Allow,
    /// Node is on the blocklist — always rejected.
    Blocked,
    /// Allowlist is non-empty and the node is not on it.
    NotAllowed,
}

/// Nebula-inspired global Access Control List.
///
/// Applied to **all** ALPNs before any protocol-specific checks. The blocklist always
/// takes priority: a node that appears on both lists is blocked.
///
/// If the allowlist is empty, all non-blocked nodes are allowed (open policy).
/// If the allowlist is non-empty, only listed nodes pass.
#[derive(Clone)]
pub struct Acl {
    allowlist: Arc<RwLock<HashSet<PublicKey>>>,
    blocklist: Arc<RwLock<HashSet<PublicKey>>>,
}

impl Acl {
    pub fn new() -> Self {
        Self {
            allowlist: Arc::new(RwLock::new(HashSet::new())),
            blocklist: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Check whether a node is allowed to connect.
    pub async fn check(&self, node_id: &PublicKey) -> AclVerdict {
        let blocklist = self.blocklist.read().await;
        if blocklist.contains(node_id) {
            return AclVerdict::Blocked;
        }
        drop(blocklist);

        let allowlist = self.allowlist.read().await;
        if allowlist.is_empty() || allowlist.contains(node_id) {
            AclVerdict::Allow
        } else {
            AclVerdict::NotAllowed
        }
    }

    /// Replace the entire allowlist.
    pub async fn set_allowlist(&self, keys: HashSet<PublicKey>) {
        let mut al = self.allowlist.write().await;
        *al = keys;
    }

    /// Replace the entire blocklist.
    pub async fn set_blocklist(&self, keys: HashSet<PublicKey>) {
        let mut bl = self.blocklist.write().await;
        *bl = keys;
    }

    /// Add a single node to the blocklist.
    pub async fn block(&self, node_id: PublicKey) {
        let mut bl = self.blocklist.write().await;
        bl.insert(node_id);
    }

    /// Remove a single node from the blocklist.
    pub async fn unblock(&self, node_id: &PublicKey) {
        let mut bl = self.blocklist.write().await;
        bl.remove(node_id);
    }
}

impl Default for Acl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> PublicKey {
        let secret = iroh::SecretKey::from_bytes(&[seed; 32]);
        secret.public()
    }

    #[tokio::test]
    async fn test_empty_acl_allows_all() {
        let acl = Acl::new();
        assert_eq!(acl.check(&test_key(1)).await, AclVerdict::Allow);
        assert_eq!(acl.check(&test_key(2)).await, AclVerdict::Allow);
    }

    #[tokio::test]
    async fn test_blocklist_blocks() {
        let acl = Acl::new();
        let blocked = test_key(1);
        acl.block(blocked).await;

        assert_eq!(acl.check(&blocked).await, AclVerdict::Blocked);
        assert_eq!(acl.check(&test_key(2)).await, AclVerdict::Allow);
    }

    #[tokio::test]
    async fn test_allowlist_restricts() {
        let acl = Acl::new();
        let allowed = test_key(1);
        let not_allowed = test_key(2);

        let mut set = HashSet::new();
        set.insert(allowed);
        acl.set_allowlist(set).await;

        assert_eq!(acl.check(&allowed).await, AclVerdict::Allow);
        assert_eq!(acl.check(&not_allowed).await, AclVerdict::NotAllowed);
    }

    #[tokio::test]
    async fn test_blocklist_wins_over_allowlist() {
        let acl = Acl::new();
        let key = test_key(1);

        let mut allow = HashSet::new();
        allow.insert(key);
        acl.set_allowlist(allow).await;

        // Also block the same key
        acl.block(key).await;

        assert_eq!(acl.check(&key).await, AclVerdict::Blocked);
    }

    #[tokio::test]
    async fn test_unblock() {
        let acl = Acl::new();
        let key = test_key(1);

        acl.block(key).await;
        assert_eq!(acl.check(&key).await, AclVerdict::Blocked);

        acl.unblock(&key).await;
        assert_eq!(acl.check(&key).await, AclVerdict::Allow);
    }

    #[tokio::test]
    async fn test_set_blocklist_replaces() {
        let acl = Acl::new();
        let key1 = test_key(1);
        let key2 = test_key(2);

        acl.block(key1).await;

        let mut new_blocklist = HashSet::new();
        new_blocklist.insert(key2);
        acl.set_blocklist(new_blocklist).await;

        // key1 should no longer be blocked
        assert_eq!(acl.check(&key1).await, AclVerdict::Allow);
        assert_eq!(acl.check(&key2).await, AclVerdict::Blocked);
    }
}
