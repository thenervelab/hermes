import asyncio
import os
from hermes import Config, HermesClient

async def main():
    print("[*] Initializing Hermes Client for Unencrypted Transfer...")

    # Load from the new JSON config file directly!
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hermes_config.json")
    config = Config.from_file(config_path)

    client = await HermesClient.create(config)
    print("[+] Connected to Hermes! Iroh Networking Online.")

    # A recipient's SS58 identifier
    dest_ss58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" # Alice

    # Raw Tensor byte array simulation -> Written straight to disk
    test_file = "public_weights.safetensors"
    with open(test_file, "wb") as f:
        f.write(b"Massive public gradient workload that doesn't need privacy. Safetensors.")
    
    file_size = os.path.getsize(test_file)
    print(f"[*] Blasting {file_size} bytes unencrypted directly to HCFS out-of-core...")
    
    try:
        # Notice we use the `send_file_unencrypted` method
        filename = await client.send_file_unencrypted(dest_ss58, test_file)
        
        print(f"[SUCCESS] Payload pushed.")
        print(f"[*] Remote Filename: {filename}")
        print(f"[*] Target subnet worker has received it over Iroh P2P.")
    except Exception as e:
        print(f"[-] Transmission failed: {e}")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    asyncio.run(main())
