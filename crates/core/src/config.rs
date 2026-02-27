use crate::error::{HermesError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

fn default_rpc_url() -> String {
    "wss://rpc.hippius.network:443".to_string()
}

/// Optional S3 backend credentials for pushing datasets directly to Hippius S3
/// overriding the Arion HTTP API.
#[derive(Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket", &self.bucket)
            .field("access_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Complete configuration required to initialize a Hermes node.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the 32-byte Ed25519 secret key file used as the Iroh node identity.
    /// The NodeId derived from this key must match what is registered on-chain
    /// in the AccountProfile pallet for this node's SS58 address.
    pub node_secret_key_path: PathBuf,
    pub ss58_address: String,
    pub api_token: String,
    pub storage_directory: PathBuf,
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    /// Subnet netuids this node participates in. Controls which per-subnet
    /// ALPNs are registered (e.g. `hippius-hermes/subnet/42`). The cross-subnet
    /// ALPN `hippius-hermes/1` is always registered regardless.
    #[serde(default)]
    pub subnet_ids: Vec<u16>,
    /// Optional S3 configuration to upload 100GB+ datasets natively via rust-s3
    /// pointing to the decentralized Hippius backend.
    #[serde(default)]
    pub s3: Option<S3Config>,
    /// Whether to aggressively drop all incoming node connections that do not
    /// match a locally injected SS58 whitelist.
    #[serde(default)]
    pub enable_firewall: bool,
    /// Optional PullWeights API key for downloading and uploading machine learning models
    /// directly to the pullweights.com/api registry instead of Hippius S3.
    #[serde(default)]
    pub pullweights_api_key: Option<String>,
    /// Skip on-chain identity verification for incoming P2P data transfers.
    /// When true, files are accepted without verifying the sender's on-chain profile.
    #[serde(default)]
    pub skip_identity_verification: bool,
    /// Enable the persistent sled message queue for offline buffering.
    /// Only needed for listener mode; send-only commands should leave this false
    /// to avoid sled's exclusive file lock conflicting with a running listener.
    #[serde(default)]
    pub enable_queue: bool,
    /// Path to a 32-byte X25519 secret key file for E2E encrypted messaging.
    /// When set, the client can decrypt incoming `encrypted_message` payloads
    /// and encrypt outgoing messages to peers whose encryption key is on-chain.
    #[serde(default)]
    pub encryption_key_path: Option<PathBuf>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("node_secret_key_path", &self.node_secret_key_path)
            .field("ss58_address", &self.ss58_address)
            .field("api_token", &"[REDACTED]")
            .field("storage_directory", &self.storage_directory)
            .field("rpc_url", &self.rpc_url)
            .field("subnet_ids", &self.subnet_ids)
            .field("s3", &self.s3)
            .field("enable_firewall", &self.enable_firewall)
            .field(
                "pullweights_api_key",
                &self.pullweights_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Config {
    /// Loads the configuration securely from a JSON file.
    ///
    /// On Unix, warns if the file is readable by group or others (mode should be 0600).
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        // Warn if config file has overly permissive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:o}", mode),
                        "Config file is readable by group/others. Consider: chmod 600 {}",
                        path.display()
                    );
                }
            }
        }

        let content = fs::read_to_string(path)
            .map_err(|e| HermesError::Config(format!("Failed to read config file: {}", e)))?;
        let config: Config = serde_json::from_str(&content)
            .map_err(|e| HermesError::Config(format!("Failed to parse config file: {}", e)))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_deserialize_without_subnet_ids() {
        let json = r#"{
            "node_secret_key_path": "/etc/hermes/iroh.key",
            "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "api_token": "test-token",
            "storage_directory": "/tmp/hermes"
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.subnet_ids.is_empty());
        assert_eq!(config.rpc_url, "wss://rpc.hippius.network:443");
    }

    #[test]
    fn test_config_deserialize_with_subnet_ids() {
        let json = r#"{
            "node_secret_key_path": "/etc/hermes/iroh.key",
            "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "api_token": "test-token",
            "storage_directory": "/tmp/hermes",
            "subnet_ids": [1, 42, 255]
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.subnet_ids, vec![1, 42, 255]);
    }

    #[test]
    fn test_config_deserialize_empty_subnet_ids() {
        let json = r#"{
            "node_secret_key_path": "/etc/hermes/iroh.key",
            "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "api_token": "test-token",
            "storage_directory": "/tmp/hermes",
            "subnet_ids": []
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.subnet_ids.is_empty());
    }

    #[test]
    fn test_config_serialize_roundtrip() {
        let config = Config {
            node_secret_key_path: "/etc/hermes/iroh.key".into(),
            ss58_address: "5GrwvaEF".into(),
            api_token: "token".into(),
            storage_directory: "/tmp".into(),
            rpc_url: "wss://rpc.hippius.network:443".into(),
            subnet_ids: vec![42, 69],
            s3: None,
            enable_firewall: false,
            pullweights_api_key: None,
            skip_identity_verification: false,
            enable_queue: false,
            encryption_key_path: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.subnet_ids, vec![42, 69]);
        assert_eq!(
            deserialized.node_secret_key_path,
            PathBuf::from("/etc/hermes/iroh.key")
        );
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let config = Config {
            node_secret_key_path: "/etc/hermes/iroh.key".into(),
            ss58_address: "5GrwvaEF".into(),
            api_token: "super-secret-token".into(),
            storage_directory: "/tmp".into(),
            rpc_url: "wss://rpc.hippius.network:443".into(),
            subnet_ids: vec![],
            s3: Some(S3Config {
                bucket: "my-bucket".into(),
                access_key: "AKIAIOSFODNN7EXAMPLE".into(),
                secret_key: "wJalrXUtnFEMI/K7MDENG".into(),
            }),
            enable_firewall: false,
            pullweights_api_key: Some("pw-secret-key-123".into()),
            skip_identity_verification: false,
            enable_queue: false,
            encryption_key_path: None,
        };
        let debug_output = format!("{:?}", config);
        assert!(!debug_output.contains("super-secret-token"));
        assert!(!debug_output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!debug_output.contains("wJalrXUtnFEMI/K7MDENG"));
        assert!(!debug_output.contains("pw-secret-key-123"));
        assert!(debug_output.contains("[REDACTED]"));
        // Non-secret fields should still be visible
        assert!(debug_output.contains("5GrwvaEF"));
        assert!(debug_output.contains("my-bucket"));
    }

    #[test]
    fn test_config_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let json = r#"{
            "node_secret_key_path": "/etc/hermes/iroh.key",
            "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "api_token": "test-token",
            "storage_directory": "/tmp/hermes",
            "subnet_ids": [7, 42]
        }"#;
        fs::write(&path, json).unwrap();
        let config = Config::from_file(&path).unwrap();
        assert_eq!(config.subnet_ids, vec![7, 42]);
    }

    #[test]
    fn test_config_deserialize_with_s3() {
        let json = r#"{
            "node_secret_key_path": "/etc/hermes/iroh.key",
            "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "api_token": "test-token",
            "storage_directory": "/tmp/hermes",
            "s3": {
                "bucket": "my-bucket",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        let s3 = config.s3.expect("s3 config should be present");
        assert_eq!(s3.bucket, "my-bucket");
        assert_eq!(s3.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(s3.secret_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    #[test]
    fn test_config_from_file_missing_subnet_ids_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let json = r#"{
            "node_secret_key_path": "/etc/hermes/iroh.key",
            "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "api_token": "test-token",
            "storage_directory": "/tmp/hermes"
        }"#;
        fs::write(&path, json).unwrap();
        let config = Config::from_file(&path).unwrap();
        assert!(config.subnet_ids.is_empty());
    }
}
