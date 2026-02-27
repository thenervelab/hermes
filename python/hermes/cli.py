import asyncio
import click
import os
from .core import Config, HermesClient

def load_config() -> Config:
    """Loads default Hermes config from environment variables."""
    key_path = os.environ.get("NODE_SECRET_KEY_PATH", "/path/to/iroh.key")
    ss58 = os.environ.get("SS58_ADDRESS", "")
    token = os.environ.get("HIPPIUS_API_TOKEN", "")

    # Store sled db locally or globally in ~/.hermes
    db_dir = os.environ.get("HERMES_DATA_DIR", os.path.join(os.getcwd(), ".hermes_data"))

    return Config(key_path, ss58, token, db_dir)


@click.group()
def main():
    """Hippius Hermes: Massive P2P Encrypted Data Transfer"""
    pass

@main.command()
@click.argument('dest_ss58', type=str)
@click.argument('filepath', type=click.Path(exists=True))
def send(dest_ss58, filepath):
    """
    Sends an unencrypted file via Iroh P2P blobs and notifies the target node.
    """
    async def _run():
        config = load_config()
        print("[*] Initializing Hermes Core Engine & Iroh Networking...")
        client = await HermesClient.create(config)

        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"[*] File loaded: {filepath} ({file_size_mb:.2f} MB)")
        print(f"[*] Relaying strictly to Substrate node: {dest_ss58}")

        print(f"[*] Initializing Iroh Zero-Copy Blob Stream & QUIC Control Plane...")
        try:
            hash_res = await client.send_file_unencrypted(dest_ss58, filepath)
            print(f"\n[+] SUCCESS! File exported to local Iroh blob and ticket transmitted.")
            print(f"[+] Payload Ticket: {hash_res}")
        except Exception as e:
            print(f"\n[-] FAILED to dispatch payload: {e}")

    asyncio.run(_run())

@main.command()
@click.argument('dest_ss58', type=str)
@click.argument('filepath', type=click.Path(exists=True))
def store(dest_ss58, filepath):
    """
    Streams an unencrypted file to the Hippius Sync-Engine and notifies the target node.
    """
    async def _run():
        config = load_config()
        print("[*] Initializing Hermes Core Engine & Iroh Networking...")
        client = await HermesClient.create(config)

        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"[*] File loaded: {filepath} ({file_size_mb:.2f} MB)")
        print(f"[*] Target Substrate node for notification: {dest_ss58}")

        print(f"[*] Streaming to Hippius Sync-Engine & Dispatching notification via QUIC...")
        try:
            hash_res = await client.send_file_unencrypted_to_store(dest_ss58, filepath)
            print(f"\n[+] SUCCESS! File synced on Arion.")
            print(f"[+] Payload Content Hash: {hash_res}")
        except Exception as e:
            print(f"\n[-] FAILED to dispatch payload: {e}")

    asyncio.run(_run())

@main.command()
def daemon():
    """Starts the Hermes network queue background processor for offline messaging."""
    async def _run():
        config = load_config()
        print("[*] Spawning Hermes Worker Daemon...")
        client = await HermesClient.create(config)

        print("[+] Iroh Node Bound. Listening for NAT punchthroughs...")
        client.start_retry_worker()

        try:
            while True:
                await asyncio.sleep(60*60)
        except KeyboardInterrupt:
            print("\n[-] Daemon stopped.")

    asyncio.run(_run())

if __name__ == '__main__':
    main()
