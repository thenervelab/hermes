#![allow(non_local_definitions)]

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use hippius_hermes_core::client::Client as CoreClient;
use hippius_hermes_core::config::Config as CoreConfig;
use hippius_hermes_core::network::message::HermesMessage;
use pyo3::types::PyBytes;

#[pyclass(name = "Config")]
#[derive(Clone)]
pub struct PyConfig {
    inner: CoreConfig,
}

#[pymethods]
impl PyConfig {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (node_secret_key_path, ss58_address, api_token, storage_directory, rpc_url=None, subnet_ids=None, s3_bucket=None, s3_access_key=None, s3_secret_key=None, enable_firewall=None, pullweights_api_key=None, enable_queue=None, encryption_key_path=None))]
    fn new(
        node_secret_key_path: String,
        ss58_address: String,
        api_token: String,
        storage_directory: String,
        rpc_url: Option<String>,
        subnet_ids: Option<Vec<u16>>,
        s3_bucket: Option<String>,
        s3_access_key: Option<String>,
        s3_secret_key: Option<String>,
        enable_firewall: Option<bool>,
        pullweights_api_key: Option<String>,
        enable_queue: Option<bool>,
        encryption_key_path: Option<String>,
    ) -> Self {
        let s3 = match (s3_bucket, s3_access_key, s3_secret_key) {
            (Some(bucket), Some(access_key), Some(secret_key)) => {
                Some(hippius_hermes_core::config::S3Config {
                    bucket,
                    access_key,
                    secret_key,
                })
            }
            _ => None,
        };
        Self {
            inner: CoreConfig {
                node_secret_key_path: PathBuf::from(node_secret_key_path),
                ss58_address,
                api_token,
                storage_directory: PathBuf::from(storage_directory),
                rpc_url: rpc_url.unwrap_or_else(|| "wss://rpc.hippius.network:443".to_string()),
                subnet_ids: subnet_ids.unwrap_or_default(),
                s3,
                enable_firewall: enable_firewall.unwrap_or(false),
                pullweights_api_key,
                skip_identity_verification: false,
                enable_queue: enable_queue.unwrap_or(false),
                encryption_key_path: encryption_key_path.map(PathBuf::from),
            },
        }
    }

    /// Loads the configuration securely from a JSON file.
    #[staticmethod]
    fn from_file(path: String) -> PyResult<Self> {
        let inner = CoreConfig::from_file(&path)
            .map_err(|e| PyRuntimeError::new_err(format!("Config error: {}", e)))?;
        Ok(Self { inner })
    }
}

#[pyclass(name = "HermesClient")]
pub struct PyHermesClient {
    // Arc to strictly enforce thread-safe Python sharing
    inner: Arc<CoreClient>,
}

#[pymethods]
impl PyHermesClient {
    /// Asynchronously initialize the core Hermes node and attach it to Python.
    #[staticmethod]
    fn create(py: Python<'_>, config: PyConfig) -> PyResult<&PyAny> {
        let conf = config.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let client = CoreClient::new(conf).await.map_err(|e| {
                PyRuntimeError::new_err(format!("Failed to start Hermes core: {}", e))
            })?;

            Ok(PyHermesClient {
                inner: Arc::new(client),
            })
        })
    }

    /// Dynamically injects a list of authorized SS58 addresses into the running client's firewall.
    /// Connections from any NodeId not matching these addresses will be aggressively dropped
    /// if `config.enable_firewall` is true.
    ///
    /// Returns the number of successfully resolved keys.
    fn set_firewall_whitelist<'a>(
        &self,
        py: Python<'a>,
        ss58_addresses: Vec<String>,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let count = client.set_firewall_whitelist(ss58_addresses).await;
            Ok(count)
        })
    }

    /// Sets the global ACL allowlist from a list of SS58 addresses.
    /// Returns the number of successfully resolved keys.
    fn set_acl_allowlist<'a>(
        &self,
        py: Python<'a>,
        ss58_addresses: Vec<String>,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let count = client.set_acl_allowlist(ss58_addresses).await;
            Ok(count)
        })
    }

    /// Sets the global ACL blocklist from a list of SS58 addresses.
    /// Returns the number of successfully resolved keys.
    fn set_acl_blocklist<'a>(
        &self,
        py: Python<'a>,
        ss58_addresses: Vec<String>,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let count = client.set_acl_blocklist(ss58_addresses).await;
            Ok(count)
        })
    }

    /// Send an AES-GCM encrypted file directly to a peer (not yet implemented).
    fn send_file<'a>(
        &self,
        py: Python<'a>,
        dest_ss58: String,
        file_path: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let hash = client
                .send_file(&dest_ss58, &file_path)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Hermes delivery failed: {}", e)))?;
            Ok(hash)
        })
    }

    /// Receive and decrypt a file using DH key material (not yet implemented).
    fn receive_file<'a>(
        &self,
        py: Python<'a>,
        hash: String,
        encrypted_keys: Vec<u8>,
        ephemeral_pub: Vec<u8>,
        dh_nonce: Vec<u8>,
        out_dir: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let path = client
                .receive_file(&hash, &encrypted_keys, &ephemeral_pub, &dh_nonce, &out_dir)
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("Hermes payload decryption failed: {}", e))
                })?;

            Ok(path)
        })
    }

    /// Send a file directly to a peer via QUIC (direct P2P, no Sync-Engine).
    fn send_file_unencrypted<'a>(
        &self,
        py: Python<'a>,
        dest_ss58: String,
        file_path: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let filename = client
                .send_file_unencrypted(&dest_ss58, &file_path, None)
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("Direct P2P transfer failed: {}", e))
                })?;
            Ok(filename)
        })
    }

    /// Pull-based direct P2P receiving (not yet implemented).
    fn receive_file_unencrypted<'a>(
        &self,
        py: Python<'a>,
        hash: String,
        out_dir: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let path = client
                .receive_file_unencrypted(&hash, &out_dir)
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("Hermes payload download failed: {}", e))
                })?;

            Ok(path)
        })
    }

    /// Upload an encrypted file to the Hippius Sync-Engine.
    fn send_file_to_store<'a>(
        &self,
        py: Python<'a>,
        dest_ss58: String,
        file_path: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let hash = client
                .send_file_to_store(&dest_ss58, &file_path)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Hermes delivery failed: {}", e)))?;
            Ok(hash)
        })
    }

    /// Download and decrypt an encrypted file from the Hippius Sync-Engine.
    fn receive_file_from_store<'a>(
        &self,
        py: Python<'a>,
        hash: String,
        encrypted_keys: Vec<u8>,
        ephemeral_pub: Vec<u8>,
        dh_nonce: Vec<u8>,
        out_dir: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let path = client
                .receive_file_from_store(
                    &hash,
                    &encrypted_keys,
                    &ephemeral_pub,
                    &dh_nonce,
                    &out_dir,
                )
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("Hermes payload decryption failed: {}", e))
                })?;

            Ok(path)
        })
    }

    /// Upload an unencrypted file to the Hippius Sync-Engine.
    fn send_file_unencrypted_to_store<'a>(
        &self,
        py: Python<'a>,
        dest_ss58: String,
        file_path: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let hash = client
                .send_file_unencrypted_to_store(&dest_ss58, &file_path, None)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Hermes delivery failed: {}", e)))?;
            Ok(hash)
        })
    }

    /// Download an unencrypted file from the Hippius Sync-Engine.
    fn receive_file_unencrypted_from_store<'a>(
        &self,
        py: Python<'a>,
        hash: String,
        out_dir: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let path = client
                .receive_file_unencrypted_from_store(&hash, &out_dir)
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("Hermes payload download failed: {}", e))
                })?;

            Ok(path)
        })
    }

    /// Uploads a file natively to S3, generates a 24-hour Pre-Signed URL, and sends the URL
    /// as a control message via the Iroh protocol to the destination SS58 address.
    fn send_file_via_s3<'a>(
        &self,
        py: Python<'a>,
        dest_ss58: String,
        file_path: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            client
                .send_file_via_s3(&dest_ss58, &file_path, None)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("S3 sending failed: {}", e)))?;
            Ok(())
        })
    }

    /// Downloads a heavy tensor payload directly from a Pre-Signed HTTP URL.
    fn download_file_http<'a>(
        &self,
        py: Python<'a>,
        url: String,
        dest_path: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            client
                .download_file_http(&url, &dest_path)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("HTTP Download failed: {}", e)))?;
            Ok(())
        })
    }

    /// Pushes a local model directly to the PullWeights registry.
    fn push_model<'a>(
        &self,
        py: Python<'a>,
        org: String,
        model: String,
        file_path: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let hash = client
                .push_model(&org, &model, &file_path)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("PullWeights Push failed: {}", e)))?;

            Ok(hash)
        })
    }

    /// Pulls a model from the PullWeights registry to a local directory.
    fn pull_model<'a>(
        &self,
        py: Python<'a>,
        org: String,
        model: String,
        tag: String,
        download_dir: String,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let path = client
                .pull_model(&org, &model, &tag, &download_dir)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("PullWeights Pull failed: {}", e)))?;

            Ok(path)
        })
    }

    /// Send an E2E encrypted control message to a peer using NaCl SealedBox.
    #[pyo3(signature = (dest_ss58, action, payload, peer_node_id=None))]
    fn send_message_encrypted<'a>(
        &self,
        py: Python<'a>,
        dest_ss58: String,
        action: String,
        payload: Vec<u8>,
        peer_node_id: Option<String>,
    ) -> PyResult<&'a PyAny> {
        let client = self.inner.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let peer_id_str = peer_node_id.as_deref();
            client
                .send_message_encrypted(&dest_ss58, &action, payload, peer_id_str)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("Encrypted send failed: {}", e)))?;
            Ok(())
        })
    }

    /// Fires up the relentless background Sled queue retries out of band.
    fn start_retry_worker(&self) {
        self.inner.spawn_retry_worker();
    }

    /// Starts the QUIC listener with separate callbacks for control messages and direct P2P data.
    ///
    /// `callback` receives control messages: `(action: str, sender_ss58: str, payload: bytes)`
    /// `on_data` (optional) receives direct P2P files: `(sender_ss58: str, filename: str, local_path: str, file_size: int)`
    #[pyo3(signature = (callback, on_data=None))]
    fn start_listener(&self, callback: PyObject, on_data: Option<PyObject>) {
        let control_cb = move |msg: HermesMessage| {
            Python::with_gil(|py| {
                let payload_bytes = PyBytes::new(py, &msg.payload);
                if let Err(e) = callback.call1(py, (msg.action, msg.sender_ss58, payload_bytes)) {
                    eprintln!("[-] Python Hermes control callback crash: {}", e);
                }
            });
        };

        let data_cb = on_data.map(|py_cb| {
            move |sender_ss58: String, filename: String, local_path: String, file_size: u64| {
                Python::with_gil(|py| {
                    if let Err(e) = py_cb.call1(py, (sender_ss58, filename, local_path, file_size))
                    {
                        eprintln!("[-] Python Hermes data callback crash: {}", e);
                    }
                });
            }
        });

        let client = self.inner.clone();

        // Spawn the listener within the existing tokio runtime initialized by `create`
        pyo3_asyncio::tokio::get_runtime().spawn(async move {
            client.spawn_listener(control_cb, data_cb);
        });
    }
}

/// A pure-Rust M2M Control and Data Plane over Iroh and Substrate.
#[pymodule]
fn core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyConfig>()?;
    m.add_class::<PyHermesClient>()?;
    Ok(())
}
