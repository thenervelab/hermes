use crate::error::{HermesError, Result};
use reqwest::{Body, Client};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

const PULLWEIGHTS_BASE_URL: &str = "https://pullweights.com/api/v1/models";

#[derive(Serialize)]
struct PushInitRequest {
    filename: String,
    size: u64,
}

#[derive(Serialize)]
struct PushFinalizeRequest {
    upload_id: String,
}

/// Pushes a local model file directly to the PullWeights registry.
/// Standard flow:
/// 1. Request presigned URL via `/v1/models/:org/:name/push/init`
/// 2. Stream PUT file to S3
/// 3. Finalize via `/v1/models/:org/:name/push/finalize`
pub async fn push_model(
    client: &Client,
    api_key: &str,
    org: &str,
    model: &str,
    file_path: &str,
) -> Result<String> {
    let path = Path::new(file_path);
    let file = File::open(path).await.map_err(HermesError::Io)?;
    let metadata = file.metadata().await.map_err(HermesError::Io)?;

    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let init_url = format!("{}/{}/{}/push/init", PULLWEIGHTS_BASE_URL, org, model);

    // 1. Init Upload
    let init_res = client
        .post(&init_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&PushInitRequest {
            filename: filename.clone(),
            size: metadata.len(),
        })
        .send()
        .await?;

    let init_res = init_res.error_for_status().map_err(HermesError::Http)?;
    let init_json: Value = init_res.json().await?;

    let upload_url = init_json["upload_url"]
        .as_str()
        .ok_or_else(|| HermesError::Payload("Missing 'upload_url' in Push Init response".into()))?;

    let upload_id = init_json["upload_id"]
        .as_str()
        .ok_or_else(|| HermesError::Payload("Missing 'upload_id' in Push Init response".into()))?;

    tracing::info!("Push Init successful. Upload ID: {}", upload_id);

    // 2. Stream File to Presigned URL
    // We reopen/re-read the file to ensure the stream starts at 0
    let file_stream = File::open(path).await.map_err(HermesError::Io)?;
    let stream = ReaderStream::new(file_stream);
    let body = Body::wrap_stream(stream);

    let put_res = client
        .put(upload_url)
        .header("Content-Length", metadata.len())
        .body(body)
        .send()
        .await?;

    put_res.error_for_status().map_err(|e| {
        HermesError::Payload(format!("Failed to upload model bytes to storage: {}", e))
    })?;

    tracing::info!("Model bytes uploaded successfully to storage.");

    // 3. Finalize Upload
    let finalize_url = format!("{}/{}/{}/push/finalize", PULLWEIGHTS_BASE_URL, org, model);

    let finalize_res = client
        .post(&finalize_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&PushFinalizeRequest {
            upload_id: upload_id.to_string(),
        })
        .send()
        .await?;

    let finalize_res = finalize_res.error_for_status().map_err(HermesError::Http)?;
    let finalize_json: Value = finalize_res.json().await?;

    let version_hash = finalize_json["hash"]
        .as_str()
        .unwrap_or("unknown_hash")
        .to_string();

    tracing::info!("Push Finalize successful. Hash: {}", version_hash);

    Ok(version_hash)
}

/// Retrieves a model's download links from the PullWeights registry and streams the file to disk.
pub async fn pull_model(
    client: &Client,
    api_key: &Option<String>,
    org: &str,
    model: &str,
    tag: &str,
    download_dir: &str,
) -> Result<String> {
    let manifest_url = format!(
        "{}/{}/{}/manifest/{}",
        PULLWEIGHTS_BASE_URL, org, model, tag
    );

    let mut req = client.get(&manifest_url);
    if let Some(token) = api_key {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let manifest_res = req.send().await?;
    let manifest_res = manifest_res.error_for_status().map_err(HermesError::Http)?;
    let manifest_json: Value = manifest_res.json().await?;

    let download_url = manifest_json["download_url"].as_str().ok_or_else(|| {
        HermesError::Payload("Missing 'download_url' in Pull Manifest response".into())
    })?;

    let filename = manifest_json["filename"]
        .as_str()
        .unwrap_or("model.safetensors");
    let target_path = Path::new(download_dir).join(filename);

    tracing::info!("Pulling model from registry...");

    let mut stream_res = client.get(download_url).send().await?.error_for_status()?;

    let mut file = tokio::fs::File::create(&target_path)
        .await
        .map_err(HermesError::Io)?;

    while let Some(chunk) = stream_res.chunk().await? {
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .map_err(HermesError::Io)?;
    }

    tracing::info!("Model downloaded to {:?}", target_path);

    Ok(target_path.to_string_lossy().to_string())
}
