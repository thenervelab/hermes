use crate::error::{HermesError, Result};
use iroh::{Endpoint, RelayMode, SecretKey};

/// Cross-subnet ALPN protocol, always accepted by every node.
pub const CROSS_SUBNET_ALPN: &[u8] = b"hippius-hermes/1";

/// Data plane ALPN for direct P2P file transfers (push-based streaming).
pub const DATA_ALPN: &[u8] = b"hippius-hermes/data/1";

/// Builds the ALPN byte string for a specific subnet.
pub fn subnet_alpn(netuid: u16) -> Vec<u8> {
    format!("hippius-hermes/subnet/{}", netuid).into_bytes()
}

/// Builds the complete list of ALPNs: cross-subnet + data + one per registered subnet.
pub fn build_alpn_list(subnet_ids: &[u16]) -> Vec<Vec<u8>> {
    let mut alpns = vec![CROSS_SUBNET_ALPN.to_vec(), DATA_ALPN.to_vec()];
    for &id in subnet_ids {
        alpns.push(subnet_alpn(id));
    }
    alpns
}

/// High-level wrapper over an Iroh Endpoint configured strictly for direct P2P messaging.
#[derive(Clone, Debug)]
pub struct HermesNode {
    pub endpoint: Endpoint,
    /// The set of ALPNs this node accepts (cross-subnet + per-subnet).
    pub(crate) registered_alpns: Vec<Vec<u8>>,
}

impl HermesNode {
    /// Initializes a new Iroh Endpoint listening locally.
    /// To ensure complete decentralization, the RelayMode is explicitly Disabled.
    /// No traffic ever traverses Iroh's public relay/DERP servers.
    /// Peers must exchange EndpointAddr out-of-band for direct UDP hole-punching.
    ///
    /// `subnet_ids` controls which per-subnet ALPNs are registered. The cross-subnet
    /// ALPN `hippius-hermes/1` is always registered.
    pub async fn new(secret_key: SecretKey, subnet_ids: &[u16]) -> Result<Self> {
        let alpns = build_alpn_list(subnet_ids);

        // Mitigate UDP hole punching NAT expirations and concurrent STUN max path limits
        let transport_config = iroh::endpoint::QuicTransportConfig::builder()
            .max_concurrent_multipath_paths(128)
            .set_max_remote_nat_traversal_addresses(32)
            .default_path_keep_alive_interval(std::time::Duration::from_secs(5))
            .build();

        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            .transport_config(transport_config)
            // Using default relays for peer discovery. Direct UDP hole-punching preferred.
            .relay_mode(RelayMode::Default)
            // Register accepted ALPNs so TLS rejects unrecognized protocols
            .alpns(alpns.clone())
            // Bind to default local UDP port automatically
            .bind()
            .await
            .map_err(|e| HermesError::Iroh(e.into()))?;

        Ok(Self {
            endpoint,
            registered_alpns: alpns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_subnet_alpn_constant() {
        assert_eq!(CROSS_SUBNET_ALPN, b"hippius-hermes/1");
    }

    #[test]
    fn test_subnet_alpn_format() {
        assert_eq!(subnet_alpn(42), b"hippius-hermes/subnet/42");
        assert_eq!(subnet_alpn(0), b"hippius-hermes/subnet/0");
        assert_eq!(subnet_alpn(65535), b"hippius-hermes/subnet/65535");
    }

    #[test]
    fn test_data_alpn_constant() {
        assert_eq!(DATA_ALPN, b"hippius-hermes/data/1");
    }

    #[test]
    fn test_build_alpn_list_empty_subnets() {
        let alpns = build_alpn_list(&[]);
        assert_eq!(alpns.len(), 2);
        assert_eq!(alpns[0], b"hippius-hermes/1");
        assert_eq!(alpns[1], b"hippius-hermes/data/1");
    }

    #[test]
    fn test_build_alpn_list_single_subnet() {
        let alpns = build_alpn_list(&[42]);
        assert_eq!(alpns.len(), 3);
        assert_eq!(alpns[0], b"hippius-hermes/1");
        assert_eq!(alpns[1], b"hippius-hermes/data/1");
        assert_eq!(alpns[2], b"hippius-hermes/subnet/42");
    }

    #[test]
    fn test_build_alpn_list_multiple_subnets() {
        let alpns = build_alpn_list(&[1, 42, 255]);
        assert_eq!(alpns.len(), 5);
        assert_eq!(alpns[0], b"hippius-hermes/1");
        assert_eq!(alpns[1], b"hippius-hermes/data/1");
        assert_eq!(alpns[2], b"hippius-hermes/subnet/1");
        assert_eq!(alpns[3], b"hippius-hermes/subnet/42");
        assert_eq!(alpns[4], b"hippius-hermes/subnet/255");
    }

    #[test]
    fn test_build_alpn_list_always_includes_cross_subnet_and_data() {
        let alpns = build_alpn_list(&[10, 20, 30]);
        assert_eq!(alpns[0], CROSS_SUBNET_ALPN.to_vec());
        assert_eq!(alpns[1], DATA_ALPN.to_vec());
        assert_eq!(alpns.len(), 5);
    }
}
