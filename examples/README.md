# Hippius Hermes Examples

This directory contains standalone, executable reference implementations of the Hippius Hermes M2M protocol demonstrating both the **Data Plane** (heavy uploads via S3 or QUIC) and the **Control Plane** (encrypted Iroh messaging).

## 🚀 Prerequisite: Node Registration
Before running **any** examples, your node identity must be generated and registered on the Substrate blockchain.

1. Generate your secret key: `cargo run --bin hippius-hermes-cli -- keygen --out-path hermes.key`
2. Create your `hermes_config.json` (see `hermes_config.example.json`).
3. Register your node on-chain using the interactive Substrate signer:
```bash
cargo run --bin hippius-hermes-cli -- --config hermes_config.json register --ss58 <YOUR-WALLET-ADDRESS>
```

---

## Python (Asyncio)

The Python examples leverage the PyO3 SDK to natively wrap the Tokio/Rust QUIC networking into a standard Python `asyncio` event loop.

### 🌟 Quick Start for Subnet Owners
If you are building a Bittensor Subnet and want the fastest integration path for a Miner or Validator, look at **`subnet_integration.py`**. It demonstrates a complete end-to-end event loop:
1. Registering the background listener.
2. Receiving tasks and securely downloading/decrypting heavy 10GB payloads natively.
3. Running ML compute.
4. Sending the heavy gradients back to the Validator via P2P.
```bash
python python/subnet_integration.py
```

---

### 1. Sender (Broadcast Data & Keys)
Demonstrates pushing a simulated massive payload, followed by a direct P2P Iroh message containing the AES decryption keys.
```bash
python python/send_payload.py
```

### 2. Receiver (Listen for P2P Streams)
Demonstrates registering a Python callback hook onto the internal Rust asynchronous loop. This daemon idly awaits incoming Substrate connections and seamlessly decodes incoming files or key control messages.
```bash
python python/receive_payload.py
```

---

### 🔓 Unencrypted Fast-Lane
If your gradients or payloads do not require privacy and just need to be distributed rapidly with P2P signaling:
- **Send Unencrypted**: `python python/send_unencrypted.py`
- **Receive Unencrypted**: `python python/receive_unencrypted.py`

*(Notice how these examples use the `hermes_config.json` file for initialization instead of purely environment variables!)*

---

## Native Rust

For ultimate multi-threaded performance (e.g., when building a native custom Validator logic layer entirely in Rust), the core library `hippius-hermes-core` can be imported directly.

### 1. Sender (Broadcast Data & Keys)
```bash
cd rust
cargo run --bin send_payload
```

### 2. Receiver (Listen for P2P Streams)
```bash
cd rust
cargo run --bin receive_payload
```

## Requirements
1. **Config File Initialization:**
   Instead of using environment variables, you can copy the provided template to `hermes_config.json` in the root directory:
   ```bash
   cp examples/hermes_config.example.json hermes_config.json
   ```
   ```json
   {
       "node_secret_key_path": "/path/to/your/iroh.key",
       "ss58_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
       "api_token": "sk-your-hippius-token-here",
       "storage_directory": ".hermes_data",
       "subnet_ids": []
   }
   ```
   Load it natively via `Config.from_file("hermes_config.json")`.

2. **Environment Variables (Alternative):**
   ```bash
   export HIPPIUS_API_TOKEN="sk-your-token"
   export NODE_SECRET_KEY_PATH="/path/to/iroh.key"
   ```
