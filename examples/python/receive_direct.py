import asyncio
import os
from hermes import Config, HermesClient

async def main():
    print("[*] Initializing Hermes Client for Direct P2P Receiving...")

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hermes_config.json")
    config = Config.from_file(config_path)

    client = await HermesClient.create(config)
    print("[+] Connected to Hermes! Listening for direct P2P files.")

    def on_message(action: str, sender_ss58: str, payload_bytes: bytes):
        """Control plane messages (Metadata notifications, etc.)"""
        print(f"\n[>>>] CONTROL MESSAGE from {sender_ss58} | Action: {action}")

    def on_file(sender_ss58: str, filename: str, local_path: str, file_size: int):
        """Direct P2P file received."""
        size_mb = file_size / (1024 * 1024)
        print(f"\n[>>>] DIRECT P2P FILE RECEIVED")
        print(f"  Sender:    {sender_ss58}")
        print(f"  Filename:  {filename}")
        print(f"  Size:      {size_mb:.2f} MB")
        print(f"  Saved to:  {local_path}")

    # Register both callbacks:
    #   on_message: control plane (signaling, metadata)
    #   on_file:    data plane (direct P2P file transfers)
    client.start_listener(on_message, on_data=on_file)

    print("[*] Waiting for incoming direct P2P files...")
    print("[*] Files will be saved to the configured storage_directory.")
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\n[-] Shutting down.")

if __name__ == "__main__":
    asyncio.run(main())
