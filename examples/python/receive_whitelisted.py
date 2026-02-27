import asyncio
import os
from hermes import Config, HermesClient

# Only accept incoming QUIC connections from these specific Bittensor SS58 addresses
AUTHORIZED_SENDERS = [
    "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", # Alice
    "5FHneW46xGXgs5mUiveU4sbTy76qSy8pi4ZdChM3Jp1r7h3n", # Bob
]

async def main():
    print("[*] Initializing Hermes Client for Direct P2P Receiving...")
    print(f"[*] Enforcing strict QUIC firewall: Only {len(AUTHORIZED_SENDERS)} authorized senders are allowed.")
    print("[!] Ensure 'enable_firewall': true is set in your hermes_config.json")

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hermes_config.json")
    config = Config.from_file(config_path)

    client = await HermesClient.create(config)
    
    # Push the Bittensor Metagraph active whitelist into the Rust core firewall
    # Unauthorized NodeIds will be aggressively dropped before streams are allocated
    await client.set_firewall_whitelist(AUTHORIZED_SENDERS)

    print("\n[+] Connected to Hermes! Listening for authenticated incoming connections...")

    def on_message(action: str, sender_ss58: str, payload_bytes: bytes):
        """Control plane messages (e.g. metadata, notifications)"""
        print(f"\n[>>>] CONTROL MESSAGE from AUTHORIZED sender {sender_ss58} | Action: {action}")
        print(f"      Payload Size: {len(payload_bytes)} bytes")

    def on_file(sender_ss58: str, filename: str, local_path: str, file_size: int):
        """Data plane messages (Direct P2P file transfers)"""
        # We no longer need to manually delete untrusted files stringently!
        # The Rust core drops unauthorized connections before bytes are even written.
        size_mb = file_size / (1024 * 1024)
        print(f"\n[>>>] AUTHORIZED DIRECT P2P FILE RECEIVED")
        print(f"  Sender:    {sender_ss58}")
        print(f"  Filename:  {filename}")
        print(f"  Size:      {size_mb:.2f} MB")
        print(f"  Saved to:  {local_path}")

    # Register both callbacks
    client.start_listener(on_message, on_data=on_file)

    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\n[-] Shutting down.")

if __name__ == "__main__":
    asyncio.run(main())
