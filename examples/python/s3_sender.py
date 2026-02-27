import asyncio
import os
from hermes import Config, HermesClient

async def main():
    print("[*] Initializing Hermes Client for S3 Sending...")
    
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "hermes_config.json")
    config = Config.from_file(config_path)

    client = await HermesClient.create(config)
    print("\n[+] Connected to Hermes!")

    # Provide the destination Bittensor MINER address
    dest_miner_ss58 = "5FHneW46xGXgs5mUiveU4sbTy76qSy8pi4ZdChM3Jp1r7h3n" 
    
    # Large test payload
    large_payload_path = "./massive_gradient_tensor.bin"
    
    # Create dummy file if it doesn't exist just for the example
    if not os.path.exists(large_payload_path):
        with open(large_payload_path, "wb") as f:
            f.write(os.urandom(10 * 1024 * 1024)) # 10MB test file

    print(f"\n[>>>] Uploading {large_payload_path} to S3 and Presigning URL...")
    
    # The Rust engine will locally upload the file to your S3 bucket,
    # generate a cryptographically signed GET URL valid for 24 hours,
    # and securely beam that URL to the miner over the Iroh QUIC network.
    await client.send_file_via_s3(dest_miner_ss58, large_payload_path)
    
    print("\n[+] Success! Pre-Signed URL sent securely to the miner.")
    
    # Give background tasks time to flush
    await asyncio.sleep(2)

if __name__ == "__main__":
    asyncio.run(main())
