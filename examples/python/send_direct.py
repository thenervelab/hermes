import asyncio
import os
from hermes import Config, HermesClient

async def main():
    print("[*] Initializing Hermes Client for Direct P2P Transfer...")

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hermes_config.json")
    config = Config.from_file(config_path)

    client = await HermesClient.create(config)
    print("[+] Connected to Hermes! Direct P2P ready.")

    # A recipient's SS58 identifier
    dest_ss58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"  # Alice

    # Create a test file (simulating gradient data)
    test_file = "gradients.bin"
    with open(test_file, "wb") as f:
        f.write(os.urandom(1024 * 1024))  # 1 MB of random data

    file_size = os.path.getsize(test_file)
    print(f"[*] Sending {file_size} bytes directly via QUIC P2P (no Sync-Engine)...")

    try:
        # Direct P2P: file streams over QUIC to the receiver
        filename = await client.send_file_unencrypted(dest_ss58, test_file)

        print(f"[SUCCESS] File pushed directly to peer.")
        print(f"[*] Filename: {filename}")
        print(f"[*] No HTTP intermediary — pure QUIC streaming.")
    except Exception as e:
        print(f"[-] Direct transfer failed: {e}")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    asyncio.run(main())
