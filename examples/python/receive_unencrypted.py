import asyncio
import os
import json
from hermes import Config, HermesClient

async def main():
    print("[*] Initializing Hermes Client for Unencrypted Receiving...")

    # Load from the new JSON config file directly!
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hermes_config.json")
    config = Config.from_file(config_path)

    client = await HermesClient.create(config)
    print("[+] Connected to Hermes! Iroh Networking Online.")

    def on_message_received(action: str, sender_ss58: str, payload_bytes: bytes):
        print(f"\n[>>>] INCOMING MESSAGE FROM {sender_ss58} | Action: {action}")
        
        # Direct P2P transfers are handled by `on_data` callback instead of pulling MANUALLY here
        # But for control messages, we can listen for action == "process_data_unencrypted"
        if action == "process_data_unencrypted":
            meta = json.loads(payload_bytes.decode('utf-8'))
            file_hash = meta.get('hash')
            
            print(f"[*] Extracting Public Data Reference: {file_hash}")
            print(f"[*] Awaiting asynchronous direct payload transfer completion...")

    def on_file_received(sender_ss58: str, filename: str, local_path: str, file_size: int):
        file_size_mb = file_size / (1024 * 1024)
        print(f"\n[SUCCESS] Downloaded {file_size_mb:.2f} MB of tensor data gracefully to {local_path}.")

    client.start_listener(on_message_received, on_data=on_file_received)
    
    print("[*] Waiting for incoming public gradients...")
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\n[-] Shutting down.")

if __name__ == "__main__":
    asyncio.run(main())
