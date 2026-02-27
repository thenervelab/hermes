use crate::error::{HermesError, Result};
use reqwest::Client;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

/// Downloads a file directly from Hippius Sync-Engine, streaming it incrementally to disk.
pub async fn download_file_from_store(
    client: &Client,
    base_url: &str,
    hash: &str,
    out_dir: &str,
) -> Result<String> {
    let url = format!("{}/api/download/{}", base_url.trim_end_matches('/'), hash);
    let res = client
        .get(&url)
        .send()
        .await?
        .error_for_status()
        .map_err(HermesError::Http)?;

    // Protect against path traversal by enforcing only the filename component
    let safe_hash = Path::new(hash)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    let out_path = format!("{}/{}", out_dir, safe_hash);
    let mut file = File::create(&out_path).await?;

    let mut stream = res;

    // Stream chunks directly to disk without buffering entirely into RAM
    while let Some(chunk) = stream.chunk().await? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    Ok(out_path)
}
