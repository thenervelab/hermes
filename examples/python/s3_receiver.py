import asyncio
import os
import tempfile
from hermes import Config, HermesClient

# Only accept messages and files from these specific Bittensor SS58 addresses
AUTHORIZED_SENDERS = [
    "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", # Validator Alice
]

async def main():
    print("[*] Initializing Hermes Client for S3 Receiving...")

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hermes_config.json")
    config = Config.from_file(config_path)

    # Boot the async client
    client = await HermesClient.create(config)
    await client.set_firewall_whitelist(AUTHORIZED_SENDERS)

    print("\n[+] Connected to Hermes! Listening for incoming connections...")

    def on_message(action: str, sender_ss58: str, payload_bytes: bytes):
        """Control plane messages (e.g. metadata, notifications)"""
        print(f"\n[>>>] CONTROL MESSAGE from AUTHORIZED sender {sender_ss58} | Action: {action}")
        
        # When compiling the S3 architecture, the `payload_bytes` will be JSON containing a Pre-Signed URL
        import json
        try:
            payload = json.loads(payload_bytes.decode('utf-8'))
            if payload.get("action") == "s3_download":
                url = payload.get("url")
                filename = payload.get("file_name")
                print(f"      [S3 PRESIGNED URL GOTTEN] Valid for 24 hours: {filename}")
                
                # Asynchronously download the file to disk using the Rust core's `reqwest` stream!
                # Because the listener callbacks are synchronous blocking Python functions, 
                # we must schedule the async download on the main loop.
                asyncio.create_task(handle_download(client, url, filename))
        except Exception as e:
            print(f"      [RAW PAYLOAD]: {payload_bytes[:100]}... Error parsing: {e}")

    async def handle_download(client: HermesClient, url: str, filename: str):
        # Determine paths
        # Real-world usage: out_dir = config.storage_directory
        out_dir = os.path.join(os.path.dirname(__file__), ".s3_downloads")
        os.makedirs(out_dir, exist_ok=True)
        dest_path = os.path.join(out_dir, filename)

        print(f"\n[*] Starting async native HTTP download from Hippius S3 to {dest_path}")
        try:
            await client.download_file_http(url, dest_path)
            size_mb = os.path.getsize(dest_path) / (1024 * 1024)
            print(f"[+] Successfully downloaded payload! Size: {size_mb:.2f} MB")
        except Exception as e:
            print(f"[-] Failed to download from S3: {e}")

    def on_file(sender_ss58: str, filename: str, local_path: str, file_size: int):
        """Standard Data plane messages (Direct QUIC push P2P streaming)"""
        pass # Disregarded for the S3 polling example

    # Register the control plane callback to await the S3 payload
    client.start_listener(on_message, on_data=on_file)

    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\n[-] Shutting down.")

if __name__ == "__main__":
    asyncio.run(main())
