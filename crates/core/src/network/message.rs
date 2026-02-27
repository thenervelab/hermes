use crate::error::{HermesError, Result};
use crate::network::node::{subnet_alpn, HermesNode, CROSS_SUBNET_ALPN};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

/// Generic Hermes envelope sent over the connection.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HermesMessage {
    /// The action triggering this message
    pub action: String,

    /// The sender's SS58 address
    pub sender_ss58: String,

    /// The actual payload
    pub payload: Vec<u8>,
}

impl HermesNode {
    /// Connects directly to a destination node and sends a HermesMessage over a new QUIC Bi-directional stream.
    ///
    /// `subnet_id` selects the ALPN for the outgoing connection:
    /// - `None` → cross-subnet `hippius-hermes/1`
    /// - `Some(netuid)` → per-subnet `hippius-hermes/subnet/<netuid>`
    pub async fn send_message(
        &self,
        dest_addr: EndpointAddr,
        message: HermesMessage,
        subnet_id: Option<u16>,
    ) -> Result<()> {
        let serialized = serde_json::to_vec(&message)?;

        let alpn = match subnet_id {
            Some(id) => subnet_alpn(id),
            None => CROSS_SUBNET_ALPN.to_vec(),
        };

        let connection = self
            .endpoint
            .connect(dest_addr, &alpn)
            .await
            .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to connect: {}", e)))?;

        let (mut send, _recv): (iroh::endpoint::SendStream, iroh::endpoint::RecvStream) =
            connection.open_bi().await.map_err(|e| {
                HermesError::Iroh(anyhow::anyhow!("Failed to open bi stream: {}", e))
            })?;

        send.write_all(&serialized)
            .await
            .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to write: {}", e)))?;

        send.finish()
            .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to finish stream: {}", e)))?;

        // Wait for the receiver to read the message and close the connection.
        // Without this, the sender process may exit and tear down the QUIC
        // connection before the data is fully flushed to the peer.
        connection.closed().await;

        Ok(())
    }
}
