"""
Hippius Hermes - End-to-End Encryption (E2EE) Example
=====================================================

This script demonstrates how to securely exchange payloads between two peers
using the X25519 static Diffie-Hellman encryption keys registered natively
on the Hippius Substrate blockchain.

Requirements:
    pip install pynacl substrate-interface

Context:
    During `hippius-hermes-cli register`, a static X25519 keypair is generated.
    The public half is registered as the `encryption_key` inside the `AccountProfile` pallet.
    
    Standard Hermes core clients (Rust/C++) natively extract this `encryption_key`
    via Substrate RPC automatically when initiating a connection to an SS58 address.
    
    This Python script is provided strictly as a STANDALONE EXAMPLE for external senders
    (e.g., a node.js web backend or raw python script) to manually query the chain,
    derive the forward-secret shared keys, and construct a secure TweetNaCl payload.
"""

import os
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import HexEncoder, RawEncoder
from substrateinterface import SubstrateInterface
import nacl.utils

# ==============================================================================
# SENDER: Alice wants to send a secure file to Bob (the Hermes Node)
# ==============================================================================

print("--- EXTERNAL SENDER (Alice) ---")
print("Note: The Hermes Core handles this autonomously for standard nodes.")

# 1. Alice connects to the Hippius Blockchain RPC.
substrate = SubstrateInterface(
    url="wss://rpc1.hippius.com", # or ws://127.0.0.1:9944 for local dev
)

# 2. Alice queries the AccountProfile storage for Bob's SS58 address.
bob_ss58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" # Replace with target
result = substrate.query("AccountProfile", "AccountProfiles", [bob_ss58])

print(f"[*] Looked up SS58 on-chain: {bob_ss58}")

if result.value is None:
    print(f"[!] Target {bob_ss58} has not registered a Hermes Node.")
    exit(1)

# Extract the hex-encoded encryption key from the chain state
bob_public_key_hex_str = result.value['encryption_key']
# Strip the "0x" prefix if present and convert to bytes
bob_public_key_hex = bob_public_key_hex_str.replace("0x", "").encode("utf-8")

print(f"[*] Retrieved Bob's Public Key from Substrate: {bob_public_key_hex[:8].decode()}...")

# 3. Alice generates an EPHEMERAL (throwaway) X25519 keypair for Perfect Forward Secrecy.
alice_ephemeral_private = PrivateKey.generate()
alice_ephemeral_public = alice_ephemeral_private.public_key

print(f"[*] Alice generated ephemeral public key: {alice_ephemeral_public.encode(encoder=HexEncoder).decode('utf-8')[:8]}...")

# 3. Alice creates a secure Box using her Ephemeral Private Key and Bob's Public Key.
bob_public_key_obj = PublicKey(bob_public_key_hex, encoder=HexEncoder)
alice_box = Box(alice_ephemeral_private, bob_public_key_obj)

# 4. Alice encrypts her sensitive payload.
# Note: In a real system, she packages `alice_ephemeral_public_bytes` alongside the 
# `encrypted_payload` in a JSON wrapper so Bob knows which public key to decrypt with!
message = b"Top secret intelligence report for the Hippius Network."

# PyNaCl's Box automatically generates a secure random 24-byte nonce and prepends it to the cyphertext.
encrypted_message = alice_box.encrypt(message)

print(f"[*] Message Encrypted! Ciphertext length: {len(encrypted_message)} bytes")


# ==============================================================================
# RECEIVER: Bob (The Hermes Node) receives the payload and decrypts it
# ==============================================================================

print("\n--- RECEIVER (Bob - Hermes Node) ---")

# 1. Bob receives the `encrypted_message` and Alice's `ephemeral_public_key` over the P2P network.
received_ciphertext = encrypted_message
received_alice_ephemeral_public_bytes = alice_ephemeral_public.encode(encoder=RawEncoder)

# 2. Bob loads his STATIC private X25519 key from disk (e.g., `hermes_encryption.key`).
# For this demo, we'll pretend Bob generated the key Alice used above.
# In reality: with open("hermes_encryption.key", "rb") as f: bob_private_key_bytes = f.read()

# [Mocking Bob's key config to make the demo run]
# A proper demo would generate Bob's key first, but since Alice mocked his public hex above, 
# we'll catch the decryption failure in the try/except since we don't hold Bob's mock private key!
print("[*] Bob loads `hermes_encryption.key` from disk...")

try:
    # 3. Bob reconstructs the Box using HIS private key and ALICE'S provided ephemeral public key.
    # bob_private_key_obj = PrivateKey(bob_private_key_bytes, encoder=RawEncoder)
    # received_alice_pub_obj = PublicKey(received_alice_ephemeral_public_bytes, encoder=RawEncoder)
    
    # bob_box = Box(bob_private_key_obj, received_alice_pub_obj)
    
    # 4. Bob decrypts the payload!
    # plaintext = bob_box.decrypt(received_ciphertext)
    
    # print(f"✅ Decrypted Successfully: {plaintext.decode('utf-8')}")
    pass
except Exception as e:
    print(f"[*] (Expected Failure in Mock Demo without Bob's real Private Key: {e})")

# ==============================================================================
# FULL DEMO EXECUTION
# ==============================================================================
print("\n--- FULL E2EE ROUNDTRIP DEMONSTRATION ---")

# Generate Bob's Static Key (What `hippius-hermes-cli register` does internally)
bob_static_private = PrivateKey.generate()
bob_static_public = bob_static_private.public_key
print(f"1. Bob (Hermes) registered public key: {bob_static_public.encode(encoder=HexEncoder).decode('utf-8')}")

# Generate Alice's Ephemeral Key
alice_ephemeral_priv = PrivateKey.generate()
alice_ephemeral_pub = alice_ephemeral_priv.public_key
print(f"2. Alice (Client) generated ephemeral key: {alice_ephemeral_pub.encode(encoder=HexEncoder).decode('utf-8')}")

# Alice Encrypts
alice_box_live = Box(alice_ephemeral_priv, bob_static_public)
live_msg = b"Secure P2P delivery mechanism verified."
live_encrypted = alice_box_live.encrypt(live_msg)
print(f"3. Alice encrypted payload (Nonce + Ciphertext): {len(live_encrypted)} bytes")

# Bob Decrypts
bob_box_live = Box(bob_static_private, alice_ephemeral_pub)
live_decrypted = bob_box_live.decrypt(live_encrypted)
print(f"4. Bob decrypted payload! ✅ Result: '{live_decrypted.decode('utf-8')}'")
