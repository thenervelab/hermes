# Hippius Hermes

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Crate](https://img.shields.io/crates/v/hippius-hermes-core.svg)](https://crates.io/crates/hippius-hermes-core)

Bittensor cross-subnet Machine-to-Machine (M2M) communication protocol built on [Iroh](https://iroh.computer) QUIC transport.

## Features

- **Direct P2P** — NAT-traversed UDP hole-punching via Iroh, no relay servers
- **Data Plane Options** — Native S3 integration or direct QUIC streaming for large payloads
- **Offline buffering** — Persistent `sled` queue with automatic retry and exponential backoff
- **Deterministic identity** — Ed25519 keys tied to on-chain SS58 addresses via the AccountProfile pallet
- **End-to-end encryption** — AES-GCM data encryption with DH key exchange (in progress)
- **Subnet-scoped routing** — Per-subnet ALPN filtering for targeted cross-subnet messaging
- **Global ACL + Firewall** — Nebula-inspired blocklist/allowlist ACL + fail-closed subnet firewall
- **PullWeights integration** — Push and pull ML models directly from the PullWeights registry
- **Python + Rust** — Native Rust core with PyO3 bindings via `maturin`

## Install

**Python** (requires Rust toolchain for building):

```bash
pip install hippius-hermes
```

**Rust**:

```toml
[dependencies]
hippius-hermes-core = "0.1"
```

## Quick Start

### Python

```python
import asyncio
from hermes import Config, HermesClient

async def main():
    config = Config(
        node_secret_key_path="/etc/hermes/iroh.key",
        ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        api_token="your-api-token",
        storage_directory=".hermes_data",
        subnet_ids=[42],
    )
    client = await HermesClient.create(config)
    client.start_retry_worker()

    # Send via direct P2P natively
    filename = await client.send_file_unencrypted(
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
        "./model_weights.safetensors",
    )
    print(f"Sent: {filename}")

asyncio.run(main())
```

### Rust

```rust
use hippius_hermes_core::{Client, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_file("hermes_config.json")?;
    let client = Client::new(config).await?;

    client.spawn_retry_worker();
    client.spawn_listener(
        |msg| println!("Control: {} from {}", msg.action, msg.sender_ss58),
        Some(|sender, filename, path, size| {
            println!("Data: {} ({} bytes) from {}", filename, size, sender);
        }),
    );

    // Setup S3 or use send_file_unencrypted for direct QUIC transfer.
    let hash = client
        .send_file_unencrypted("5FHneW46...", "./weights.safetensors", None)
        .await?;
    println!("Sent file: {hash}");

    Ok(())
}
```

### CLI

A built-in Rust CLI is also available in `crates/cli`:

```bash
# Start the listener (uses hermes_config.json by default)
cargo run --bin hippius-hermes-cli -- listen

# Send a file directly via P2P
cargo run --bin hippius-hermes-cli -- send-direct --dest-ss58 5Grw... --file-path ./model.bin
```

## Configuration

Create a `hermes_config.json`:

```json
{
    "node_secret_key_path": "/etc/hermes/iroh.key",
    "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    "api_token": "your-hippius-api-token",
    "storage_directory": "/var/hermes",
    "subnet_ids": [42]
}
```

Optional fields with defaults:
- `rpc_url` — Substrate RPC endpoint (default: `wss://rpc.hippius.network:443`)
- `subnet_ids` — Subnet netuids to accept traffic from (default: `[]`)
- `s3` — Native S3 credentials (`bucket`, `access_key`, `secret_key`) for direct uploads
- `enable_firewall` — Drop connections from non-whitelisted nodes (default: `false`)
- `pullweights_api_key` — PullWeights model registry API key

## Architecture

See [hippius-hermes.md](hippius-hermes.md) for the full architecture specification.

## Development

```bash
# Rust core
cargo build
cargo test
cargo clippy

# Python bindings
cd crates/python
pip install maturin
maturin develop --release
```

## License

[MIT](LICENSE)
