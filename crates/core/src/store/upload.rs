use crate::config::S3Config;
use crate::error::{HermesError, Result};
use reqwest::{multipart, Body, Client};
use s3::creds::Credentials;
use s3::region::Region;
use s3::Bucket;
use std::path::Path;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

/// Uploads a file stream directly from disk to the Hippius Sync-Engine to bypass RAM.
pub async fn upload_file_to_store(
    client: &Client,
    base_url: &str,
    api_token: &str,
    account_ss58: &str,
    file_path: &str,
) -> Result<String> {
    let path = Path::new(file_path);
    let file = File::open(path).await?;

    // Create a zero-copy byte stream from the file handle using tokio_util
    let stream = ReaderStream::new(file);
    let body = Body::wrap_stream(stream);

    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let part = multipart::Part::stream(body).file_name(file_name);
    let form = multipart::Form::new()
        .text("account_ss58", account_ss58.to_string())
        .part("file", part);

    let url = if base_url.ends_with("/upload") {
        base_url.to_string()
    } else {
        format!("{}/upload", base_url.trim_end_matches('/'))
    };

    let res = client
        .post(&url)
        .header("Authorization", format!("Token {}", api_token))
        .header("X-API-Key", api_token)
        .multipart(form)
        .send()
        .await?;

    let res = res.error_for_status().map_err(HermesError::Http)?;
    let json: serde_json::Value = res.json().await?;

    let hash = json["hash"]
        .as_str()
        .ok_or_else(|| HermesError::Payload("Missing hash in response".into()))?
        .to_string();

    Ok(hash)
}

/// Uploads a file stream directly from disk to the Hippius S3 backend
/// returning the S3 object key on success.
pub async fn upload_file_to_s3(s3_config: &S3Config, file_path: &str) -> Result<String> {
    let path = Path::new(file_path);
    let mut file = File::open(path).await?;

    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let region = Region::Custom {
        region: "decentralized".to_string(),
        endpoint: "https://s3.hippius.com".to_string(),
    };

    let credentials = Credentials::new(
        Some(&s3_config.access_key),
        Some(&s3_config.secret_key),
        None,
        None,
        None,
    )
    .map_err(|e| HermesError::Config(format!("Invalid S3 credentials: {}", e)))?;

    let bucket = Bucket::new(&s3_config.bucket, region, credentials)
        .map_err(|e| HermesError::Config(format!("Failed S3 bucket init: {}", e)))?
        .with_path_style();

    let res = bucket
        .put_object_stream(&mut file, &file_name)
        .await
        .map_err(|e| HermesError::Payload(format!("S3 Upload failed: {}", e)))?;

    if res.status_code() != 200 {
        return Err(HermesError::Payload(format!(
            "S3 Upload HTTP {}",
            res.status_code()
        )));
    }

    Ok(file_name)
}

/// Generates a Pre-Signed GET URL for a specific object key in the Hippius S3 backend.
/// The URL can be given to unauthorized nodes (like miners) to download the file directly.
pub async fn generate_presigned_get(
    s3_config: &S3Config,
    file_name: &str,
    expiration_secs: u32,
) -> Result<String> {
    let region = Region::Custom {
        region: "decentralized".to_string(),
        endpoint: "https://s3.hippius.com".to_string(),
    };

    let credentials = Credentials::new(
        Some(&s3_config.access_key),
        Some(&s3_config.secret_key),
        None,
        None,
        None,
    )
    .map_err(|e| HermesError::Config(format!("Invalid S3 credentials: {}", e)))?;

    let bucket = Bucket::new(&s3_config.bucket, region, credentials)
        .map_err(|e| HermesError::Config(format!("Failed S3 bucket init: {}", e)))?
        .with_path_style();

    // Generate a presigned URL valid for `expiration_secs`
    let url = bucket
        .presign_get(file_name, expiration_secs, None)
        .await
        .map_err(|e| HermesError::Payload(format!("Failed to presign S3 url: {}", e)))?;

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_upload_file_to_s3_missing_file() {
        let s3_config = S3Config {
            bucket: "hippius-arion".to_string(),
            access_key: "test-key".to_string(),
            secret_key: "test-secret".to_string(),
        };

        let result = upload_file_to_s3(&s3_config, "/tmp/non_existent_hippius_file.bin").await;
        // Should fast-fail on the tokio File::open before initializing S3
        assert!(result.is_err());
    }
}
