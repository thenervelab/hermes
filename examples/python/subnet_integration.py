import asyncio
import os
import json
from hermes import Config, HermesClient

'''
[ Hippius Hermes - Easy Subnet Integration Example ]

This example demonstrates how a typical Bittensor Subnet Miner or Validator
would integrate Hermes into their main event loop. It covers:
1. Booting the Hermes client natively.
2. Registering an asynchronous background listener for tasks/gradients.
3. Automatically receiving direct P2P payloads.
4. Sending output tensors back across the P2P network.
'''

async def main():
    print("[*] Initializing Hermes Client for Subnet 42...")

    key_path = os.environ.get("NODE_SECRET_KEY_PATH", "/path/to/iroh.key")
    ss58_address = os.environ.get("SS58_ADDRESS", "")
    api_token = os.environ.get("HIPPIUS_API_TOKEN", "your_hippius_api_token")
    data_dir = os.path.join(os.getcwd(), ".hermes_data")

    config = Config(key_path, ss58_address, api_token, data_dir)

    client = await HermesClient.create(config)
    print("[+] Connected to Hermes! Iroh Networking Online.")

    # Shared queue to pass received tasks from the background Iroh listener to the main thread
    task_queue = asyncio.Queue()

    # Callback fired directly from the Rust engine's multi-threaded QUIC sockets
    def on_message_received(action: str, sender_ss58: str, payload_bytes: bytes):
        print(f"\n[>>>] INCOMING MESSAGE FROM {sender_ss58} | Action: {action}")
        try:
            meta = json.loads(payload_bytes.decode('utf-8'))

            # Subnet routing: dispatch based on the `action` field
            if action == "process_data_unencrypted_store":
                # Push the task onto our local async queue for the heavy worker thread
                asyncio.run_coroutine_threadsafe(
                    task_queue.put((sender_ss58, meta)),
                    asyncio.get_running_loop()
                )
        except Exception as e:
            print(f"[-] Malformed payload: {e}")

    def on_file_received(sender_ss58: str, filename: str, local_path: str, file_size: int):
        print(f"\n[>>>] INCOMING DATA FROM {sender_ss58} | File: {filename}")
        # Push the task onto our local async queue for the heavy worker thread
        asyncio.run_coroutine_threadsafe(
            task_queue.put((sender_ss58, local_path)),
            asyncio.get_running_loop()
        )

    # Bind the listener onto the relentless Rust loop
    print("[*] Binding Listener...")
    client.start_listener(on_message_received, on_data=on_file_received)

    # ---------------------------------------------------------
    # Main Subnet Worker Loop
    # ---------------------------------------------------------
    print("[*] Subnet Miner is now pending tasks...")
    try:
        while True:
            # Await the next heavy request from a Validator
            sender_ss58, local_path = await task_queue.get()

            print(f"\n[*] Worker starting task from Validator {sender_ss58}...")
            print(f"[*] Processing data from {local_path}...")

            try:

                # ... < YOUR SUBNET ML INFERENCE LOGIC HERE > ...
                print("[*] Computing ML gradients...")
                await asyncio.sleep(2) # Simulating heavy compute

                output_gradients_file = "output_gradients.safetensors"
                with open(output_gradients_file, "wb") as f:
                    f.write(b"Simulated 10GB Tensor Result Matrix")

                # 2. SENDING DATA: Push output back to Validator via P2P
                print("[*] Pushing output gradients back to Validator via P2P...")

                output_filename = await client.send_file_unencrypted(sender_ss58, output_gradients_file)
                print(f"[SUCCESS] Handled task fully! Responder Output File: {output_filename}")

            except Exception as e:
                print(f"[-] Data Plane Error during Transfer: {e}")
            finally:
                if 'output_gradients_file' in locals() and os.path.exists(output_gradients_file):
                    os.remove(output_gradients_file)

            task_queue.task_done()

    except KeyboardInterrupt:
        print("\n[-] Shutting down Hermes Worker.")

if __name__ == "__main__":
    asyncio.run(main())
