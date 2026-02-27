use crate::error::{HermesError, Result};
use crate::store::consumer::DataPushHeader;
use iroh::endpoint::Connection;
use iroh::endpoint::RecvStream;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Maximum header size to prevent abuse (1 MB).
const MAX_HEADER_SIZE: u32 = 1_048_576;

/// Sanitizes a filename to prevent path traversal attacks.
/// Strips directory components and rejects empty/dot-only names.
fn sanitize_filename(raw: &str) -> Result<String> {
    let name = Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| HermesError::Payload("Invalid filename in data push header".into()))?;

    if name.is_empty() || name == "." || name == ".." {
        return Err(HermesError::Payload(
            "Invalid filename in data push header".into(),
        ));
    }

    Ok(name)
}

/// Phase 1: Reads only the length-prefixed JSON header from a DATA_ALPN connection.
///
/// Returns the receive stream (for subsequent file streaming) and the parsed header.
/// No file is written to disk at this stage — the caller can verify identity first.
pub async fn read_data_push_header(connection: Connection) -> Result<(RecvStream, DataPushHeader)> {
    let (_, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to accept bi-stream: {}", e)))?;

    // Read 4-byte header length (u32 BE)
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to read header length: {}", e)))?;
    let header_len = u32::from_be_bytes(len_buf);

    if header_len > MAX_HEADER_SIZE {
        return Err(HermesError::Payload(format!(
            "Data push header too large: {} bytes (max {})",
            header_len, MAX_HEADER_SIZE
        )));
    }

    // Read header JSON
    let mut header_buf = vec![0u8; header_len as usize];
    recv.read_exact(&mut header_buf)
        .await
        .map_err(|e| HermesError::Iroh(anyhow::anyhow!("Failed to read header: {}", e)))?;

    let header: DataPushHeader = serde_json::from_slice(&header_buf)?;

    Ok((recv, header))
}

/// Phase 2: Streams the file data from an already-opened receive stream to disk.
///
/// The filename is prefixed with a UUID to prevent collisions.
/// Returns: (sender_ss58, filename, local_path, file_size)
pub async fn stream_data_push(
    mut recv: RecvStream,
    header: &DataPushHeader,
    storage_dir: &Path,
) -> Result<(String, String, String, u64)> {
    let sanitized = sanitize_filename(&header.filename)?;
    let filename = format!("{}_{}", Uuid::new_v4(), sanitized);

    // Ensure storage directory exists
    tokio::fs::create_dir_all(storage_dir)
        .await
        .map_err(HermesError::Io)?;

    let dest_path: PathBuf = storage_dir.join(&filename);

    // Stream file bytes to disk
    let mut file = tokio::fs::File::create(&dest_path)
        .await
        .map_err(HermesError::Io)?;

    let mut total_written: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024]; // 64 KB chunks

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                file.write_all(&buf[..n]).await.map_err(HermesError::Io)?;
                total_written += n as u64;
            }
            Ok(None) => break, // Stream finished
            Err(e) => {
                // Clean up partial file on error
                let _ = tokio::fs::remove_file(&dest_path).await;
                return Err(HermesError::Iroh(anyhow::anyhow!(
                    "Failed to read file data: {}",
                    e
                )));
            }
        }
    }

    file.flush().await.map_err(HermesError::Io)?;

    let local_path = dest_path.to_string_lossy().to_string();

    Ok((
        header.sender_ss58.clone(),
        filename,
        local_path,
        total_written,
    ))
}

/// Legacy convenience wrapper that reads header + streams in one call.
///
/// Prefer using `read_data_push_header` + `stream_data_push` separately in new code
/// to allow identity verification between the two phases.
pub async fn handle_data_push(
    connection: Connection,
    storage_dir: &Path,
) -> Result<(String, String, String, u64)> {
    let (recv, header) = read_data_push_header(connection).await?;
    stream_data_push(recv, &header, storage_dir).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename_normal() {
        assert_eq!(sanitize_filename("gradients.bin").unwrap(), "gradients.bin");
    }

    #[test]
    fn test_sanitize_filename_strips_directory() {
        assert_eq!(sanitize_filename("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(sanitize_filename("/tmp/evil/file.txt").unwrap(), "file.txt");
    }

    #[test]
    fn test_sanitize_filename_rejects_dots() {
        assert!(sanitize_filename("..").is_err());
        assert!(sanitize_filename(".").is_err());
    }

    #[test]
    fn test_sanitize_filename_rejects_empty() {
        assert!(sanitize_filename("").is_err());
    }

    #[test]
    fn test_sanitize_filename_with_spaces() {
        assert_eq!(sanitize_filename("my file.txt").unwrap(), "my file.txt");
    }

    #[test]
    fn test_uuid_prefix_in_filename() {
        let sanitized = sanitize_filename("test.bin").unwrap();
        let prefixed = format!("{}_{}", Uuid::new_v4(), sanitized);
        assert!(prefixed.ends_with("_test.bin"));
        // UUID v4 is 36 chars + underscore + filename
        assert!(prefixed.len() > 36 + 1 + "test.bin".len() - 1);
    }
}
