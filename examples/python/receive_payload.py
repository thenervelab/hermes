import asyncio
import os
import json
from hermes import Config, HermesClient

ASCII_ART = r"""
    __  ___                 _                 __  __                             
   / / / (_)___  ____  ____(_)__  _______    / / / /__  _________ ___  ___  _____
  / /_/ / / __ \/ __ \/ __ \ / / / / ___/   / /_/ / _ \/ ___/ __ `__ \/ _ \/ ___/
 / __  / / /_/ / /_/ / /_/ / / /_/ (__  )  / __  /  __/ /  / / / / / /  __(__  ) 
/_/ /_/_/ .___/ .___/ .___/_/\__,_/____/  /_/ /_/\___/_/  /_/ /_/ /_/\___/____/  
       /_/   /_/   /_/                                                           

    [ Hippius Hermes - P2P Mass Data Messenger ]
"""

def on_message_received(action: str, sender_ss58: str, payload_bytes: bytes):
    """Callback fired directly from the Rust engine's multi-threaded QUIC sockets into Python."""
    print(f"\n[>>>] INCOMING SECURE MESSAGE FROM {sender_ss58}")
    print(f"      Action: {action}")

    try:
        meta = json.loads(payload_bytes.decode('utf-8'))
        file_hash = meta.get('hash', 'UNKNOWN')
        encrypted_keys = meta.get('encrypted_keys', [])

        print(f"      HCFS Hash/URL: {file_hash}")
        print(f"      Cipher Key Payload: <{len(encrypted_keys)} bytes>")
        print(f"[*] Secure Control Message verified. If this is a direct P2P payload, check your local data dir!")

    except Exception as e:
        print(f"      Raw Payload: {payload_bytes}")

async def main():
    print(ASCII_ART)
    print("[*] Initializing Hermes Listener Daemon...")

    key_path = os.environ.get("NODE_SECRET_KEY_PATH", "/path/to/iroh.key")
    ss58_address = os.environ.get("SS58_ADDRESS", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
    api_token = os.environ.get("HIPPIUS_API_TOKEN", "your_hippius_api_token")
    data_dir = os.path.join(os.getcwd(), ".hermes_data")

    config = Config(key_path, ss58_address, api_token, data_dir)

    client = await HermesClient.create(config)
    print("[+] Core Engine and Iroh Networking Online!")

    print("[*] Binding Iroh QUIC Router to local port. Awaiting incoming Substrate connections...")

    client.start_listener(on_message_received)

    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\n[-] Shutting down Hermes QUIC listener.")

if __name__ == "__main__":
    asyncio.run(main())
