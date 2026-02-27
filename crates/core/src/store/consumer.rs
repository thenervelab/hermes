use crate::error::{HermesError, Result};
use crate::network::node::DATA_ALPN;
use iroh::{Endpoint, EndpointAddr};
use std::path::Path;
use tokio::io::AsyncReadExt;

/// Size of each chunk when streaming file bytes over QUIC.
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB

/// Header sent at the start of a direct P2P file push.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DataPushHeader {
    pub sender_ss58: String,
    pub filename: String,
    pub file_size: u64,
}

/// Pushes a file directly to a remote peer over a QUIC bi-stream on DATA_ALPN.
///
/// Wire format:
///   [4 bytes: header_len (u32 BE)]
///   [header_len bytes: JSON header]
///   [remaining bytes: raw file data streamed in 64KB chunks]
pub async fn push_file(
    endpoint: &Endpoint,
    dest_addr: EndpointAddr,
    sender_ss58: &str,
    file_path: &str,
) -> Result<String> {
    let path = Path::new(file_path);
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HermesError::Payload("Invalid file path: no filename".into()))?
        .to_string();

    let metadata = tokio::fs::metadata(path).await.map_err(HermesError::Io)?;
    let file_size = metadata.len();

    let header = DataPushHeader {
        sender_ss58: sender_ss58.to_string(),
        filename: filename.clone(),
        file_size,
    };
    let header_json = serde_json::to_vec(&header)?;

    // Connect to receiver on the data ALPN
    let connection = endpoint
        .connect(dest_addr, DATA_ALPN)
        .await
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Data push connect failed: {}", e)))?;

    tracing::info!(
        "P2P Connection Established. Remote Node: {}, Protocol: {}",
        connection.remote_id(),
        String::from_utf8_lossy(connection.alpn())
    );

    let (mut send, _recv) = connection
        .open_bi()
        .await
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to open bi-stream: {}", e)))?;

    // Write length-prefixed header
    let header_len = (header_json.len() as u32).to_be_bytes();
    send.write_all(&header_len)
        .await
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to write header length: {}", e)))?;
    send.write_all(&header_json)
        .await
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to write header: {}", e)))?;

    // Stream file data in chunks
    let mut file = tokio::fs::File::open(path).await.map_err(HermesError::Io)?;
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf).await.map_err(HermesError::Io)?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n])
            .await
            .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to write file data: {}", e)))?;
    }

    send.finish()
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to finish stream: {}", e)))?;

    // Wait for the receiver to process the stream before dropping the connection.
    // The receiver needs the connection alive to accept_bi() and read the data.
    tracing::info!("File data sent, waiting for receiver to process...");
    connection.closed().await;
    tracing::info!("Receiver closed connection, transfer complete");

    Ok(filename)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization_roundtrip() {
        let header = DataPushHeader {
            sender_ss58: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            filename: "gradients.bin".to_string(),
            file_size: 104857600,
        };
        let json = serde_json::to_vec(&header).unwrap();
        let decoded: DataPushHeader = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.sender_ss58, header.sender_ss58);
        assert_eq!(decoded.filename, header.filename);
        assert_eq!(decoded.file_size, header.file_size);
    }

    #[test]
    fn test_header_json_format() {
        let header = DataPushHeader {
            sender_ss58: "5Abc".to_string(),
            filename: "test.bin".to_string(),
            file_size: 1024,
        };
        let json_str = serde_json::to_string(&header).unwrap();
        assert!(json_str.contains("sender_ss58"));
        assert!(json_str.contains("filename"));
        assert!(json_str.contains("file_size"));
    }
}
