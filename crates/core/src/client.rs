use crate::acl::{Acl, AclVerdict};
use crate::config::Config;
use crate::crypto;
use crate::error::{HermesError, Result};
use crate::identity::{resolve_profile, validate_ss58};
use crate::network::message::HermesMessage;
use crate::network::node::{HermesNode, DATA_ALPN};
use crate::network::queue::MessageQueue;
use crate::store::consumer::push_file;
use crate::store::provider::{read_data_push_header, stream_data_push};

use iroh::{EndpointAddr, PublicKey, SecretKey};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::{sleep, Duration};
use url::Url;
use zeroize::Zeroize;

/// Maximum concurrent incoming QUIC connections handled simultaneously.
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

/// Maximum retries before a queued message is dropped permanently.
const MAX_RETRY_COUNT: u32 = 100;

/// Maximum control plane message size (256 KB).
const MAX_CONTROL_MSG_BYTES: usize = 262_144;

/// Maximum HTTP download size (10 GB).
const MAX_DOWNLOAD_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// The central Hermes Client that orchestrates Iroh P2P networking and the HTTP Sync-Engine.
#[derive(Clone)]
pub struct Client {
    config: Arc<Config>,
    pub(crate) node: HermesNode,
    pub(crate) queue: Option<MessageQueue>,
    http: reqwest::Client,
    pub(crate) firewall_whitelist: Arc<RwLock<HashSet<String>>>,
    pub(crate) firewall_keys: Arc<RwLock<HashSet<PublicKey>>>,
    firewall_initialized: Arc<AtomicBool>,
    acl: Acl,
    encryption_secret: Option<Arc<crypto_box::SecretKey>>,
    encryption_public: Option<crypto_box::PublicKey>,
}

impl Client {
    /// Returns the active configuration used by this Hermes client.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Initializes the Hermes Client, booting up the Iroh P2P Node.
    ///
    /// The persistent sled message queue is only opened when `config.enable_queue` is true,
    /// avoiding the exclusive file lock that prevents concurrent listen + send processes.
    pub async fn new(config: Config) -> Result<Self> {
        let mut key_bytes = std::fs::read(&config.node_secret_key_path).map_err(|e| {
            HermesError::Config(format!(
                "Failed to read secret key from {:?}: {}",
                config.node_secret_key_path, e
            ))
        })?;
        let mut key_array: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            HermesError::Config(format!(
                "Secret key at {:?} must be exactly 32 bytes, got {}",
                config.node_secret_key_path,
                key_bytes.len()
            ))
        })?;
        let secret_key = SecretKey::from_bytes(&key_array);

        // Zeroize key material immediately after use (Issue #1)
        key_bytes.zeroize();
        key_array.zeroize();

        let node = HermesNode::new(secret_key, &config.subnet_ids).await?;

        let queue = if config.enable_queue {
            Some(MessageQueue::new(&config.storage_directory)?)
        } else {
            None
        };

        // Load E2E encryption keypair if configured
        let (encryption_secret, encryption_public) =
            if let Some(ref key_path) = config.encryption_key_path {
                let sk = crypto::load_encryption_secret_key(key_path)?;
                let pk = sk.public_key();
                (Some(Arc::new(sk)), Some(pk))
            } else {
                (None, None)
            };

        let http = reqwest::Client::new();

        tracing::info!(
            ss58 = %config.ss58_address,
            subnets = ?config.subnet_ids,
            queue_enabled = config.enable_queue,
            e2ee = encryption_secret.is_some(),
            "Hermes client initialized"
        );

        Ok(Self {
            config: Arc::new(config),
            node,
            queue,
            http,
            firewall_whitelist: Arc::new(RwLock::new(HashSet::new())),
            firewall_keys: Arc::new(RwLock::new(HashSet::new())),
            firewall_initialized: Arc::new(AtomicBool::new(false)),
            acl: Acl::new(),
            encryption_secret,
            encryption_public,
        })
    }

    /// Returns a reference to the global ACL for direct manipulation.
    pub fn acl(&self) -> &Acl {
        &self.acl
    }

    /// Resolves SS58 addresses to PublicKeys and sets the ACL allowlist.
    /// Returns the number of successfully resolved keys.
    pub async fn set_acl_allowlist(&self, ss58_addresses: Vec<String>) -> usize {
        let rpc_url = self.config.rpc_url.clone();
        let mut keys = HashSet::new();

        for addr in &ss58_addresses {
            match resolve_profile(&rpc_url, addr).await {
                Ok(profile) => {
                    if let Ok(node_id_array) = profile.node_id.as_slice().try_into() {
                        let arr: [u8; 32] = node_id_array;
                        if let Ok(pubkey) = PublicKey::from_bytes(&arr) {
                            keys.insert(pubkey);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(addr = %addr, error = %e, "ACL allowlist: failed to resolve SS58");
                }
            }
        }

        let count = keys.len();
        self.acl.set_allowlist(keys).await;
        tracing::info!(
            resolved = count,
            total = ss58_addresses.len(),
            "ACL allowlist updated"
        );
        count
    }

    /// Resolves SS58 addresses to PublicKeys and sets the ACL blocklist.
    /// Returns the number of successfully resolved keys.
    pub async fn set_acl_blocklist(&self, ss58_addresses: Vec<String>) -> usize {
        let rpc_url = self.config.rpc_url.clone();
        let mut keys = HashSet::new();

        for addr in &ss58_addresses {
            match resolve_profile(&rpc_url, addr).await {
                Ok(profile) => {
                    if let Ok(node_id_array) = profile.node_id.as_slice().try_into() {
                        let arr: [u8; 32] = node_id_array;
                        if let Ok(pubkey) = PublicKey::from_bytes(&arr) {
                            keys.insert(pubkey);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(addr = %addr, error = %e, "ACL blocklist: failed to resolve SS58");
                }
            }
        }

        let count = keys.len();
        self.acl.set_blocklist(keys).await;
        tracing::info!(
            resolved = count,
            total = ss58_addresses.len(),
            "ACL blocklist updated"
        );
        count
    }

    /// Dynamically injects a list of authorized SS58 addresses into the running client's firewall.
    /// Connections from any NodeId not matching these addresses will be aggressively dropped
    /// if `config.enable_firewall` is true.
    ///
    /// Returns the number of successfully resolved keys.
    pub async fn set_firewall_whitelist(&self, ss58_addresses: Vec<String>) -> usize {
        let mut whitelist = self.firewall_whitelist.write().await;
        whitelist.clear();
        for addr in &ss58_addresses {
            whitelist.insert(addr.clone());
        }
        drop(whitelist);

        let rpc_url = self.config.rpc_url.clone();
        let mut keys = HashSet::new();

        // Resolve all SS58 addresses to their Iroh PublicKeys proactively
        for addr in &ss58_addresses {
            match resolve_profile(&rpc_url, addr).await {
                Ok(profile) => {
                    if let Ok(node_id_array) = profile.node_id.as_slice().try_into() {
                        let arr: [u8; 32] = node_id_array;
                        if let Ok(pubkey) = PublicKey::from_bytes(&arr) {
                            keys.insert(pubkey);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(addr = %addr, error = %e, "Firewall whitelist: failed to resolve SS58");
                }
            }
        }

        let resolved_count = keys.len();
        let mut f_keys = self.firewall_keys.write().await;
        *f_keys = keys;
        drop(f_keys);

        // Mark firewall as initialized so fail-closed logic activates (Issue #12)
        self.firewall_initialized.store(true, Ordering::Release);

        tracing::info!(
            resolved = resolved_count,
            total = ss58_addresses.len(),
            "Firewall whitelist dynamically updated"
        );

        resolved_count
    }

    /// Resolves the destination's Iroh EndpointAddr from their AccountProfile.
    async fn resolve_dest_addr(
        &self,
        dest_ss58: &str,
    ) -> Result<(EndpointAddr, crate::identity::AccountProfile)> {
        let profile = resolve_profile(&self.config.rpc_url, dest_ss58).await?;

        let node_id_array: [u8; 32] =
            profile.node_id.as_slice().try_into().map_err(|_| {
                HermesError::Identity("NodeId maps to incorrect byte length".into())
            })?;
        let node_id = PublicKey::from_bytes(&node_id_array)
            .map_err(|e| HermesError::Identity(format!("Invalid NodeId bytes: {}", e)))?;

        Ok((EndpointAddr::from(node_id), profile))
    }

    /// Sends a HermesMessage, buffering to the offline queue on failure (if queue is enabled).
    async fn send_or_queue(
        &self,
        dest_ss58: &str,
        dest_addr: EndpointAddr,
        msg: HermesMessage,
        subnet_id: Option<u16>,
    ) {
        if let Err(e) = self
            .node
            .send_message(dest_addr.clone(), msg.clone(), subnet_id)
            .await
        {
            if let Some(ref queue) = self.queue {
                tracing::debug!(dest = %dest_ss58, error = %e, "Direct send failed, queuing for retry");
                if let Err(qe) = queue.push(dest_ss58, dest_addr, &msg, subnet_id) {
                    tracing::warn!(dest = %dest_ss58, error = %qe, "Failed to enqueue message for offline retry");
                }
            } else {
                tracing::warn!(dest = %dest_ss58, error = %e, "Direct send failed (no queue available)");
            }
        }
    }

    /// Primary action: Securely encrypt and stream a file directly to the destination via QUIC.
    pub async fn send_file(&self, _dest_ss58: &str, _file_path: &str) -> Result<String> {
        Err(HermesError::Unimplemented(
            "AES-GCM encrypted direct P2P streaming is not yet implemented. \
             Use `send_file_unencrypted` for direct P2P or `send_file_unencrypted_to_store` for Sync-Engine.".into()
        ))
    }

    /// Helper to resolve an EndpointAddr either from an explicit NodeId string or by falling back to the blockchain profile
    async fn resolve_or_override(
        &self,
        dest_ss58: &str,
        peer_node_id: Option<&str>,
    ) -> Result<EndpointAddr> {
        if let Some(node_id_str) = peer_node_id {
            // Use the explicit node ID provided by the user for offline testing
            let node_id: iroh::PublicKey = node_id_str.parse().map_err(|e| {
                HermesError::Identity(format!("Invalid explicit peer-node-id: {}", e))
            })?;
            Ok(EndpointAddr::from(node_id))
        } else {
            // Fallback to resolving the profile from the blockchain
            let (addr, _) = self.resolve_dest_addr(dest_ss58).await?;
            Ok(addr)
        }
    }

    /// Pushes a file directly to the destination peer over QUIC (DATA_ALPN).
    /// No intermediary HTTP server — pure P2P streaming.
    ///
    /// If `peer_node_id` is provided, it overrides the on-chain identity lookup.
    pub async fn send_file_unencrypted(
        &self,
        dest_ss58: &str,
        file_path: &str,
        peer_node_id: Option<&str>,
    ) -> Result<String> {
        validate_ss58(dest_ss58)?;
        let dest_addr = self.resolve_or_override(dest_ss58, peer_node_id).await?;

        let filename = push_file(
            &self.node.endpoint,
            dest_addr,
            &self.config.ss58_address,
            file_path,
        )
        .await?;

        Ok(filename)
    }

    /// Download and decrypt a payload using the DH-encrypted AES key material to a specific dir.
    pub async fn receive_file(
        &self,
        _hash: &str,
        _encrypted_keys: &[u8],
        _ephemeral_pub: &[u8],
        _dh_nonce: &[u8],
        _out_dir: &str,
    ) -> Result<String> {
        Err(HermesError::Unimplemented(
            "AES-GCM encrypted receiving is not yet implemented. \
             Use the data callback on `spawn_listener` for direct P2P, or `receive_file_unencrypted_from_store` for Sync-Engine.".into()
        ))
    }

    /// Pull-based unencrypted file download (future feature).
    pub async fn receive_file_unencrypted(&self, _hash: &str, _out_dir: &str) -> Result<String> {
        Err(HermesError::Unimplemented(
            "Pull-based direct P2P receiving is not yet implemented. \
             Use the data callback on `spawn_listener` for push-based P2P receiving, \
             or `receive_file_unencrypted_from_store` for Sync-Engine."
                .into(),
        ))
    }

    /// DEPRECATED: The Hippius Sync-Engine has been temporarily removed from the SDK.
    pub async fn send_file_to_store(&self, _dest_ss58: &str, _file_path: &str) -> Result<String> {
        Err(HermesError::Unimplemented(
            "The Sync-Engine is disabled. Use `send_file_via_s3` or direct P2P methods.".into(),
        ))
    }

    /// DEPRECATED: The Hippius Sync-Engine has been temporarily removed from the SDK.
    pub async fn send_file_unencrypted_to_store(
        &self,
        _dest_ss58: &str,
        _file_path: &str,
        _peer_node_id: Option<&str>,
    ) -> Result<String> {
        Err(HermesError::Unimplemented(
            "The Sync-Engine is disabled. Use `send_file_via_s3` or direct P2P methods.".into(),
        ))
    }

    /// DEPRECATED: The Hippius Sync-Engine has been temporarily removed from the SDK.
    pub async fn receive_file_from_store(
        &self,
        _hash: &str,
        _encrypted_keys: &[u8],
        _ephemeral_pub: &[u8],
        _dh_nonce: &[u8],
        _out_dir: &str,
    ) -> Result<String> {
        Err(HermesError::Unimplemented(
            "The Sync-Engine is disabled. Use `download_file_http` or direct P2P methods.".into(),
        ))
    }

    /// DEPRECATED: The Hippius Sync-Engine has been temporarily removed from the SDK.
    pub async fn receive_file_unencrypted_from_store(
        &self,
        _hash: &str,
        _out_dir: &str,
    ) -> Result<String> {
        Err(HermesError::Unimplemented(
            "The Sync-Engine is disabled. Use `download_file_http` or direct P2P methods.".into(),
        ))
    }

    /// Uploads a file to the Hippius S3 backend, generates a Pre-Signed URL, and sends
    /// the URL via the Iroh Control Plane directly to the destination.
    pub async fn send_file_via_s3(
        &self,
        dest_ss58: &str,
        file_path: &str,
        peer_node_id: Option<&str>,
    ) -> Result<()> {
        validate_ss58(dest_ss58)?;
        let s3_config = self.config.s3.as_ref().ok_or_else(|| {
            HermesError::Config("S3 is not configured in hermes_config.json".into())
        })?;

        let dest_addr = self.resolve_or_override(dest_ss58, peer_node_id).await?;

        // 1. Upload to S3 natively
        let object_key = crate::store::upload::upload_file_to_s3(s3_config, file_path).await?;

        // 2. Generate a Pre-Signed GET URL valid for 24 hours
        let presigned_url =
            crate::store::upload::generate_presigned_get(s3_config, &object_key, 86400).await?;

        let meta = serde_json::json!({
            "action": "s3_download",
            "file_name": object_key,
            "url": presigned_url
        });

        // 3. Send the secure URL directly over Iroh QUIC avoiding public relays
        let msg = HermesMessage {
            action: "process_data_s3".into(),
            sender_ss58: self.config.ss58_address.clone(),
            payload: serde_json::to_vec(&meta)?,
        };

        self.send_or_queue(dest_ss58, dest_addr, msg, None).await;

        Ok(())
    }

    /// Downloads a heavy payload natively from a Pre-Signed HTTP URL.
    ///
    /// Validates the URL against SSRF attacks and enforces a 10 GB size limit.
    pub async fn download_file_http(&self, url: &str, dest_path: &str) -> Result<()> {
        validate_download_url(url)?;

        let response = self.http.get(url).send().await?;
        let mut response = response.error_for_status().map_err(HermesError::Http)?;

        let mut file = tokio::fs::File::create(dest_path).await?;
        let mut total_written: u64 = 0;

        while let Some(chunk) = response.chunk().await.map_err(HermesError::Http)? {
            total_written += chunk.len() as u64;
            if total_written > MAX_DOWNLOAD_BYTES {
                // Clean up partial file before returning error
                drop(file);
                let _ = tokio::fs::remove_file(dest_path).await;
                return Err(HermesError::Payload(format!(
                    "Download exceeded maximum size limit of {} bytes",
                    MAX_DOWNLOAD_BYTES
                )));
            }
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
        }

        Ok(())
    }

    /// Spawns an async loop to drain the Sled queue and retry sending offline messages.
    /// Groups by destination to avoid hammering offline peers. Messages exceeding
    /// MAX_RETRY_COUNT are dropped. Failed destinations are skipped for the remainder
    /// of each sweep to prevent head-of-line blocking.
    ///
    /// No-op if the message queue is not enabled.
    pub fn spawn_retry_worker(&self) {
        if self.queue.is_none() {
            tracing::debug!("Retry worker not started: message queue is disabled");
            return;
        }

        let client = self.clone();
        tokio::spawn(async move {
            let retry_semaphore = Arc::new(Semaphore::new(50));
            let queue = client.queue.as_ref().expect("checked above");

            loop {
                // Drain everything currently in the queue
                let mut items = Vec::new();
                while let Ok(Some(item)) = queue.pop_next() {
                    items.push(item);
                }

                if !items.is_empty() {
                    let failed_dests = Arc::new(tokio::sync::Mutex::new(HashSet::<String>::new()));
                    let mut handles = Vec::new();

                    for (dest_ss58, dest_addr, msg, retry_count, subnet_id, enqueued_at) in items {
                        // Drop messages that have exceeded the retry limit
                        if retry_count >= MAX_RETRY_COUNT {
                            tracing::warn!(dest = %dest_ss58, retries = retry_count, "Dropping message after max retries");
                            continue;
                        }

                        let c = client.clone();
                        let fd = failed_dests.clone();

                        // Issue #8: handle semaphore closure gracefully
                        let permit = match retry_semaphore.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!("Retry semaphore closed, stopping retry worker");
                                break;
                            }
                        };

                        handles.push(tokio::spawn(async move {
                            let _permit = permit;

                            // Skip destinations already known to be offline this sweep
                            {
                                let dests = fd.lock().await;
                                if dests.contains(&dest_ss58) {
                                    if let Some(ref q) = c.queue {
                                        if let Err(e) = q.push_retry(&dest_ss58, dest_addr, &msg, retry_count, subnet_id, enqueued_at) {
                                            tracing::warn!(dest = %dest_ss58, error = %e, "Failed to re-queue skipped message");
                                        }
                                    }
                                    return;
                                }
                            }

                            if let Err(e) = c.node.send_message(dest_addr.clone(), msg.clone(), subnet_id).await {
                                tracing::debug!(dest = %dest_ss58, error = %e, retry = retry_count + 1, "Retry send failed");
                                {
                                    let mut dests = fd.lock().await;
                                    dests.insert(dest_ss58.clone());
                                }
                                if let Some(ref q) = c.queue {
                                    if let Err(qe) = q.push_retry(&dest_ss58, dest_addr, &msg, retry_count + 1, subnet_id, enqueued_at) {
                                        tracing::warn!(dest = %dest_ss58, error = %qe, "Failed to re-queue message after retry failure");
                                    }
                                }
                            }
                        }));
                    }

                    // Wait for all retry tasks before next sweep
                    for handle in handles {
                        if let Err(e) = handle.await {
                            tracing::warn!(error = %e, "Retry task panicked");
                        }
                    }
                }

                // Sleep before initiating the next full sweep
                sleep(Duration::from_secs(60)).await;
            }
        });
    }

    /// Spawns an async loop to accept incoming Iroh QUIC streams and route them.
    ///
    /// - **Control ALPN connections** are routed to `control_callback` after identity verification.
    /// - **Data ALPN connections** are routed to `data_callback` (if provided) for direct P2P file reception.
    ///
    /// If `data_callback` is `None`, incoming data connections are silently dropped.
    pub fn spawn_listener<F, D>(&self, control_callback: F, data_callback: Option<D>)
    where
        F: Fn(HermesMessage) + Send + Sync + 'static,
        D: Fn(String, String, String, u64) + Send + Sync + 'static,
    {
        let endpoint = self.node.endpoint.clone();
        let registered_alpns = self.node.registered_alpns.clone();
        let rpc_url = self.config.rpc_url.clone();
        let storage_dir = self.config.storage_directory.clone();
        let control_callback = Arc::new(control_callback);
        let data_callback = data_callback.map(Arc::new);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let firewall_keys = self.firewall_keys.clone();
        let firewall_initialized = self.firewall_initialized.clone();
        let enable_firewall = self.config.enable_firewall;
        let skip_identity_verification = self.config.skip_identity_verification;
        let acl = self.acl.clone();
        let enc_secret = self.encryption_secret.clone();
        let enc_public = self
            .encryption_public
            .as_ref()
            .map(|pk| Arc::new(pk.clone()));

        tracing::info!("Spawning QUIC listener");

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let cb = control_callback.clone();
                let dcb = data_callback.clone();
                let rpc = rpc_url.clone();
                let alpns = registered_alpns.clone();
                let storage = storage_dir.clone();
                let f_keys = firewall_keys.clone();
                let fw_init = firewall_initialized.clone();
                let acl = acl.clone();
                let e_secret = enc_secret.clone();
                let e_public = enc_public.clone();
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!("Connection dropped: at semaphore limit");
                        continue;
                    }
                };

                tokio::spawn(async move {
                    let _permit = permit; // Held until this handler completes

                    let connecting = match incoming.accept() {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Failed to accept incoming connection: {}", e);
                            return;
                        }
                    };
                    let connection = match connecting.await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Connection handshake failed: {}", e);
                            return;
                        }
                    };

                    let remote_pub = connection.remote_id();
                    let alpn = connection.alpn();

                    // Defense-in-depth: reject connections whose ALPN doesn't match
                    if !alpns.iter().any(|a| a == alpn) {
                        tracing::warn!(
                            alpn = %String::from_utf8_lossy(alpn),
                            "ALPN mismatch, rejecting connection"
                        );
                        return;
                    }

                    // === Layer 1: Global ACL check (Issue #3) ===
                    // Applied to ALL ALPNs — blocklist > allowlist
                    match acl.check(&remote_pub).await {
                        AclVerdict::Allow => {}
                        AclVerdict::Blocked => {
                            tracing::warn!(
                                node_id = %remote_pub,
                                alpn = %String::from_utf8_lossy(alpn),
                                "ACL: blocked node rejected"
                            );
                            return;
                        }
                        AclVerdict::NotAllowed => {
                            tracing::debug!(
                                node_id = %remote_pub,
                                alpn = %String::from_utf8_lossy(alpn),
                                "ACL: node not in allowlist, rejected"
                            );
                            return;
                        }
                    }

                    // === Layer 2: Subnet firewall (Issues #2, #6, #12) ===
                    let is_subnet_alpn = alpn.starts_with(b"hippius-hermes/subnet/");

                    if enable_firewall && is_subnet_alpn {
                        // Fail-closed: if firewall hasn't been initialized yet, deny all
                        if !fw_init.load(Ordering::Acquire) {
                            tracing::warn!(
                                node_id = %remote_pub,
                                "Firewall not yet initialized, fail-closed: dropping subnet connection"
                            );
                            return;
                        }

                        let allowed_keys = f_keys.read().await;
                        if !allowed_keys.contains(&remote_pub) {
                            tracing::warn!(
                                node_id = %remote_pub,
                                alpn = %String::from_utf8_lossy(alpn),
                                "Firewall: unauthorized subnet connection dropped"
                            );
                            return;
                        }
                    }

                    // === Route by ALPN ===
                    if alpn == DATA_ALPN {
                        // Direct P2P data transfer
                        let dcb = match dcb {
                            Some(ref cb) => cb.clone(),
                            None => {
                                tracing::warn!("No data callback registered, dropping");
                                return;
                            }
                        };

                        let remote_pub = connection.remote_id();

                        // Issue #4: Read header FIRST, verify identity, THEN stream to disk
                        let (connection, recv, header) = match read_data_push_header(connection).await {
                            Ok(result) => result,
                            Err(e) => {
                                tracing::warn!(error = %e, "DATA_ALPN: failed to read header");
                                return;
                            }
                        };

                        // Verify sender identity before writing any file to disk
                        let verified = if skip_identity_verification {
                            tracing::warn!(
                                "DATA_ALPN: Identity verification SKIPPED (config flag)"
                            );
                            true
                        } else {
                            match resolve_profile(&rpc, &header.sender_ss58).await {
                                Ok(profile) => {
                                    let expected: [u8; 32] =
                                        match profile.node_id.as_slice().try_into() {
                                            Ok(arr) => arr,
                                            Err(_) => {
                                                tracing::warn!(
                                                "DATA_ALPN: NodeId maps to incorrect byte length"
                                            );
                                                return;
                                            }
                                        };
                                    match PublicKey::from_bytes(&expected) {
                                        Ok(expected_pub) => {
                                            if expected_pub != remote_pub {
                                                tracing::warn!(
                                                "DATA_ALPN: Identity spoofing detected! {} != {}",
                                                expected_pub,
                                                remote_pub
                                            );
                                                false
                                            } else {
                                                true
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "DATA_ALPN: Invalid NodeId bytes: {}",
                                                e
                                            );
                                            false
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("DATA_ALPN: Failed to resolve profile: {}", e);
                                    false
                                }
                            }
                        };

                        if !verified {
                            tracing::warn!(
                                "DATA_ALPN: Dropped data push due to verification failure"
                            );
                            connection.close(iroh::endpoint::VarInt::from_u32(1), b"rejected");
                            return;
                        }

                        // Identity verified — now stream to disk
                        match stream_data_push(recv, &header, &storage).await {
                            Ok((sender_ss58, filename, local_path, file_size)) => {
                                connection.close(iroh::endpoint::VarInt::from_u32(0), b"done");
                                dcb(sender_ss58, filename, local_path, file_size);
                            }
                            Err(e) => {
                                connection.close(iroh::endpoint::VarInt::from_u32(2), b"error");
                                tracing::warn!(error = %e, "DATA_ALPN: stream_data_push failed");
                            }
                        }
                    } else {
                        // Control plane message
                        let remote_pub = connection.remote_id();

                        let (_send, mut recv) = match connection.accept_bi().await {
                            Ok(bi) => bi,
                            Err(_) => return,
                        };

                        // Issue #5: 256 KB limit instead of 10 MB
                        match recv.read_to_end(MAX_CONTROL_MSG_BYTES).await {
                            Ok(buf) => match serde_json::from_slice::<HermesMessage>(&buf) {
                                Ok(mut msg) => {
                                    let verified = if skip_identity_verification {
                                        true
                                    } else {
                                        match resolve_profile(&rpc, &msg.sender_ss58).await {
                                            Ok(profile) => {
                                                let expected: [u8; 32] =
                                                    match profile.node_id.as_slice().try_into() {
                                                        Ok(arr) => arr,
                                                        Err(_) => return,
                                                    };
                                                match PublicKey::from_bytes(&expected) {
                                                    Ok(expected_pub) => expected_pub == remote_pub,
                                                    Err(_) => false,
                                                }
                                            }
                                            Err(_) => false,
                                        }
                                    };

                                    if verified {
                                        // Decrypt E2E encrypted messages if we have keys
                                        if msg.action == "encrypted_message" {
                                            match (&e_secret, &e_public) {
                                                (Some(sk), Some(pk)) => {
                                                    match crypto::open(&msg.payload, pk, sk) {
                                                        Ok(plaintext) => {
                                                            match serde_json::from_slice::<
                                                                HermesMessage,
                                                            >(
                                                                &plaintext
                                                            ) {
                                                                Ok(inner) => {
                                                                    tracing::info!(
                                                                        action = %inner.action,
                                                                        sender = %inner.sender_ss58,
                                                                        "Decrypted E2E message"
                                                                    );
                                                                    msg = inner;
                                                                }
                                                                Err(e) => {
                                                                    tracing::warn!(error = %e, "E2E: decrypted payload is not a valid HermesMessage");
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(error = %e, "E2E: failed to decrypt sealed box");
                                                            return;
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    tracing::warn!("Received encrypted_message but no encryption key configured");
                                                    return;
                                                }
                                            }
                                        }
                                        cb(msg);
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Control plane: failed to deserialize message");
                                }
                            },
                            Err(e) => {
                                tracing::warn!(error = %e, "Control plane: failed to read message");
                            }
                        }
                    }
                });
            }
        });
    }

    /// Sends an E2E encrypted control plane message to a destination.
    ///
    /// The inner message is serialized, sealed with NaCl SealedBox (ephemeral X25519 DH +
    /// XSalsa20-Poly1305), and wrapped in an outer `HermesMessage` with action `"encrypted_message"`.
    /// The recipient's X25519 public key is resolved from their on-chain AccountProfile.
    pub async fn send_message_encrypted(
        &self,
        dest_ss58: &str,
        action: &str,
        payload: Vec<u8>,
        peer_node_id: Option<&str>,
    ) -> Result<()> {
        validate_ss58(dest_ss58)?;

        // Resolve the destination endpoint address
        let dest_addr = self.resolve_or_override(dest_ss58, peer_node_id).await?;

        // Resolve the recipient's on-chain encryption public key
        let profile = resolve_profile(&self.config.rpc_url, dest_ss58).await?;
        let recipient_pub = crypto::parse_onchain_encryption_key(&profile.encryption_key)?;

        // Build the inner plaintext message
        let inner_msg = HermesMessage {
            action: action.to_string(),
            sender_ss58: self.config.ss58_address.clone(),
            payload,
        };
        let plaintext = serde_json::to_vec(&inner_msg)?;

        // Seal with NaCl SealedBox
        let ciphertext = crypto::seal(&plaintext, &recipient_pub)?;

        // Wrap in outer envelope
        let outer_msg = HermesMessage {
            action: "encrypted_message".to_string(),
            sender_ss58: self.config.ss58_address.clone(),
            payload: ciphertext,
        };

        self.send_or_queue(dest_ss58, dest_addr, outer_msg, None)
            .await;

        Ok(())
    }

    /// Pushes a local model directly to the PullWeights registry using this client's configured API key.
    pub async fn push_model(&self, org: &str, model: &str, file_path: &str) -> Result<String> {
        let api_key = self.config.pullweights_api_key.as_deref().ok_or_else(|| {
            HermesError::Config("Missing `pullweights_api_key` in Hermes Config.".into())
        })?;

        crate::store::pullweights::push_model(&self.http, api_key, org, model, file_path).await
    }

    /// Pulls a model from the PullWeights registry to a local directory using this client's configured API key.
    pub async fn pull_model(
        &self,
        org: &str,
        model: &str,
        tag: &str,
        download_dir: &str,
    ) -> Result<String> {
        let api_key = &self.config.pullweights_api_key;
        crate::store::pullweights::pull_model(&self.http, api_key, org, model, tag, download_dir)
            .await
    }
}

/// Validates a download URL against SSRF attacks.
///
/// Blocks: non-HTTPS schemes, cloud metadata IPs (169.254.169.254), loopback,
/// and private network ranges.
fn validate_download_url(url: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|e| HermesError::Ssrf(format!("Invalid URL: {}", e)))?;

    // Only allow HTTPS
    if parsed.scheme() != "https" {
        return Err(HermesError::Ssrf(format!(
            "Only HTTPS URLs are allowed, got: {}",
            parsed.scheme()
        )));
    }

    // Check host for blocked IPs
    if let Some(host) = parsed.host_str() {
        // Try to parse as IP directly
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_blocked_ip(&ip) {
                return Err(HermesError::Ssrf(format!("Blocked IP address: {}", ip)));
            }
        }
    } else {
        return Err(HermesError::Ssrf("URL has no host".into()));
    }

    Ok(())
}

/// Returns true if an IP address is in a blocked range (metadata, loopback, private, link-local, multicast).
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // Cloud metadata endpoint
            if v4.octets() == [169, 254, 169, 254] {
                return true;
            }
            // Loopback
            if v4.is_loopback() {
                return true;
            }
            // Unspecified (0.0.0.0)
            if v4.is_unspecified() {
                return true;
            }
            // Multicast
            if v4.is_multicast() {
                return true;
            }
            // Broadcast
            if v4.is_broadcast() {
                return true;
            }
            // Private ranges
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // Link-local 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // Loopback (::1)
            if v6.is_loopback() {
                return true;
            }
            // Unspecified (::)
            if v6.is_unspecified() {
                return true;
            }
            // Multicast (ff00::/8)
            if v6.is_multicast() {
                return true;
            }
            let segments = v6.segments();
            // Link-local (fe80::/10)
            if segments[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // Unique local address (fc00::/7)
            if segments[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // IPv4-mapped IPv6 (::ffff:0:0/96) — check the embedded IPv4
            if segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
                let v4 = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                );
                return is_blocked_ip(&IpAddr::V4(v4));
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_download_url_https_allowed() {
        assert!(validate_download_url("https://example.com/file.bin").is_ok());
    }

    #[test]
    fn test_validate_download_url_http_blocked() {
        assert!(validate_download_url("http://example.com/file.bin").is_err());
    }

    #[test]
    fn test_validate_download_url_metadata_ip_blocked() {
        assert!(validate_download_url("https://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn test_validate_download_url_loopback_blocked() {
        assert!(validate_download_url("https://127.0.0.1/secret").is_err());
    }

    #[test]
    fn test_validate_download_url_private_10_blocked() {
        assert!(validate_download_url("https://10.0.0.1/internal").is_err());
    }

    #[test]
    fn test_validate_download_url_private_172_blocked() {
        assert!(validate_download_url("https://172.16.0.1/internal").is_err());
    }

    #[test]
    fn test_validate_download_url_private_192_blocked() {
        assert!(validate_download_url("https://192.168.1.1/internal").is_err());
    }

    #[test]
    fn test_validate_download_url_invalid() {
        assert!(validate_download_url("not a url").is_err());
    }

    #[test]
    fn test_is_blocked_ip_v6_loopback() {
        assert!(is_blocked_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_v6_link_local() {
        assert!(is_blocked_ip(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_v6_multicast() {
        assert!(is_blocked_ip(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_v6_unique_local() {
        assert!(is_blocked_ip(&"fc00::1".parse().unwrap()));
        assert!(is_blocked_ip(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_v6_unspecified() {
        assert!(is_blocked_ip(&"::".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_v6_mapped_v4_private() {
        // ::ffff:127.0.0.1 — IPv4-mapped loopback
        assert!(is_blocked_ip(&"::ffff:127.0.0.1".parse().unwrap()));
        // ::ffff:10.0.0.1 — IPv4-mapped private
        assert!(is_blocked_ip(&"::ffff:10.0.0.1".parse().unwrap()));
        // ::ffff:192.168.1.1 — IPv4-mapped private
        assert!(is_blocked_ip(&"::ffff:192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_v6_mapped_v4_public_allowed() {
        // ::ffff:8.8.8.8 — IPv4-mapped public should be allowed
        assert!(!is_blocked_ip(&"::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_v6_public_allowed() {
        // 2001:4860:4860::8888 — Google's public IPv6 DNS
        assert!(!is_blocked_ip(&"2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ip_public_v4_allowed() {
        assert!(!is_blocked_ip(&"8.8.8.8".parse().unwrap()));
    }
}
