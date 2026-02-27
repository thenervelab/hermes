import asyncio
import os
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

async def main():
    print(ASCII_ART)
    print("[*] Initializing Hermes Client...")

    key_path = os.environ.get("NODE_SECRET_KEY_PATH", "/path/to/iroh.key")
    ss58_address = os.environ.get("SS58_ADDRESS", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
    api_token = os.environ.get("HIPPIUS_API_TOKEN", "your_hippius_api_token")
    data_dir = os.path.join(os.getcwd(), ".hermes_data")

    config = Config(key_path, ss58_address, api_token, data_dir)

    client = await HermesClient.create(config)
    print("[+] Core Engine and Iroh Networking Online!")

    destination_ss58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" # Alice

    # Write sample data to a temporary file (the API works with files, not raw bytes)
    os.makedirs(data_dir, exist_ok=True)
    sample_file = os.path.join(data_dir, "sample_payload.bin")
    with open(sample_file, "wb") as f:
        f.write(b"Hello from Hippius Python SDK! Imagine this is a 5GB safetensors gradient file.")

    print(f"[*] Preparing to transmit payload to {destination_ss58}...")

    try:
        filename = await client.send_file_unencrypted(destination_ss58, sample_file)
        print(f"\n[SUCCESS] Payload dispatched directly via P2P.")
        print(f"[SUCCESS] Remote Received File: {filename}")
    except Exception as e:
        print(f"[-] Transmission failed or peer offline: {e}")
    finally:
        if os.path.exists(sample_file):
            os.remove(sample_file)

if __name__ == "__main__":
    asyncio.run(main())
