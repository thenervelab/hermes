use anyhow::Result;
use clap::{Parser, Subcommand};
use dialoguer::Password;
use hippius_hermes_core::{Client, Config};
use sp_core::blake2_256;
use sp_core::crypto::Pair as CryptoPair;
use sp_core::ed25519;
use sp_core::{crypto::Ss58Codec, H256};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to hermes_config.json
    #[arg(short, long, default_value = "hermes_config.json")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a random Iroh SecretKey for a new node
    Keygen {
        #[arg(short, long, default_value = "iroh.key")]
        out_path: PathBuf,
    },

    /// Read an existing Iroh SecretKey and print its public NodeId
    BackupKey {
        #[arg(short, long, default_value = "iroh.key")]
        key_path: PathBuf,
    },

    /// Start the Hermes listener to receive control messages and P2P files
    Listen,

    /// Send an unencrypted file directly to a peer via QUIC P2P
    SendDirect {
        /// Destination SS58 Address
        #[arg(short, long)]
        dest_ss58: String,

        /// Explicit Peer NodeId for offline testing (overrides mock on-chain lookup)
        #[arg(long)]
        peer_node_id: Option<String>,

        /// Path to the file to send
        #[arg(short, long)]
        file_path: PathBuf,
    },

    /// Send an AES-GCM encrypted file to a peer (Not yet implemented in core)
    Send {
        #[arg(short, long)]
        dest_ss58: String,
        #[arg(short, long)]
        file_path: PathBuf,
    },

    /// Push a local model directly to the PullWeights API registry
    PushModel {
        #[arg(long)]
        org: String,
        #[arg(long)]
        model: String,
        #[arg(short, long)]
        file_path: PathBuf,
    },

    /// Pull a model from the PullWeights API registry
    PullModel {
        #[arg(long)]
        org: String,
        #[arg(long)]
        model: String,
        #[arg(long)]
        tag: String,
        #[arg(long, default_value = ".")]
        download_dir: PathBuf,
    },

    /// Upload a file to Hippius S3 and print the object key + presigned URL
    UploadS3 {
        /// Path to the file to upload
        #[arg(short, long)]
        file_path: PathBuf,

        /// Presigned URL expiration in seconds (default 24h)
        #[arg(short, long, default_value = "86400")]
        expiration: u32,
    },

    /// Upload a file to S3, then send the presigned URL to a peer via Iroh control message
    SendViaS3 {
        /// Destination SS58 Address
        #[arg(short, long)]
        dest_ss58: String,

        /// Path to the file to upload and send
        #[arg(short, long)]
        file_path: PathBuf,

        /// Explicit Peer NodeId (overrides on-chain lookup)
        #[arg(long)]
        peer_node_id: Option<String>,
    },

    /// Download a file from a URL (SSRF-protected, HTTPS only)
    DownloadUrl {
        /// The URL to download from
        #[arg(short, long)]
        url: String,

        /// Local path to save the downloaded file
        #[arg(short, long)]
        dest_path: PathBuf,
    },

    /// Send an E2E encrypted control message to a peer via NaCl SealedBox
    SendEncrypted {
        /// Destination SS58 Address
        #[arg(short, long)]
        dest_ss58: String,

        /// Action string for the inner message
        #[arg(short, long)]
        action: String,

        /// Message text payload
        #[arg(short, long)]
        message: String,

        /// Explicit Peer NodeId (overrides on-chain lookup)
        #[arg(long)]
        peer_node_id: Option<String>,
    },

    /// Generate offline payloads to register this node to a Substrate SS58 account
    Register {
        /// Your Validator or Main Wallet SS58 Address
        #[arg(long)]
        ss58: String,

        /// Optional username to claim
        #[arg(long)]
        username: Option<String>,

        /// Submission method: 'api' (feeless) or 'chain' (requires Substrate tokens)
        #[arg(long, default_value = "api")]
        method: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let client = match &cli.command {
        Commands::Keygen { out_path } => {
            use rand::RngCore;
            let mut secret_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
            let secret_key = iroh::SecretKey::from_bytes(&secret_bytes);
            let secret_bytes = secret_key.to_bytes();
            std::fs::write(out_path, secret_bytes)?;

            println!(
                "[+] Generated secure random Iroh SecretKey at: {}",
                out_path.display()
            );
            println!("[+] NodeId (Public Key): {}", secret_key.public());
            println!("[!] Share this NodeId with senders so they can holepunch to you offline.");
            return Ok(());
        }
        Commands::BackupKey { key_path } => {
            if !key_path.exists() {
                anyhow::bail!("Key file not found at: {}", key_path.display());
            }
            let secret_bytes = std::fs::read(key_path)?;
            if secret_bytes.len() != 32 {
                anyhow::bail!("Invalid key file length. Expected 32 bytes.");
            }
            let secret_array: [u8; 32] = secret_bytes.try_into().unwrap();
            let secret_key = iroh::SecretKey::from_bytes(&secret_array);
            println!("[+] NodeId (Public Key): {}", secret_key.public());
            return Ok(());
        }
        Commands::Listen
        | Commands::SendDirect { .. }
        | Commands::PushModel { .. }
        | Commands::PullModel { .. }
        | Commands::Send { .. }
        | Commands::UploadS3 { .. }
        | Commands::SendViaS3 { .. }
        | Commands::DownloadUrl { .. }
        | Commands::SendEncrypted { .. } => {
            // Verify config exists
            if !cli.config.exists() {
                anyhow::bail!("Config file not found at: {}", cli.config.display());
            }

            // Load config
            let config_path = cli.config.to_string_lossy().to_string();
            let mut config = Config::from_file(&config_path)?;

            // Only enable the sled queue for the listener — avoids lock conflicts
            if matches!(cli.command, Commands::Listen) {
                config.enable_queue = true;
            }

            Client::new(config).await?
        }
        Commands::Register { .. } => {
            // We don't need the full Hermes Client for offline registration
            let config_path = cli.config.to_string_lossy().to_string();
            let config = Config::from_file(&config_path)?;
            Client::new(config).await? // Technically starts Iroh, but we can exit early below
        }
    };

    match &cli.command {
        Commands::Listen => {
            println!("[*] Starting Hermes CLI Listener...");
            client.spawn_retry_worker();

            client.spawn_listener(
                |msg| {
                    println!(
                        "\n[>>>] CONTROL MESSAGE from {} | Action: {}",
                        msg.sender_ss58, msg.action
                    );
                    // Print payload safely
                    if let Ok(s) = String::from_utf8(msg.payload.clone()) {
                        println!("  Payload: {}", s);
                    } else {
                        println!("  Payload: {} bytes", msg.payload.len());
                    }
                },
                Some(
                    |sender: String, filename: String, local_path: String, size: u64| {
                        let size_mb = size as f64 / (1024.0 * 1024.0);
                        println!("\n[>>>] DIRECT P2P FILE RECEIVED");
                        println!("  Sender:    {}", sender);
                        println!("  Filename:  {}", filename);
                        println!("  Size:      {:.2} MB", size_mb);
                        println!("  Saved to:  {}", local_path);
                    },
                ),
            );

            println!("[+] Listening for P2P connections and Sync-Engine traffic...");
            tokio::signal::ctrl_c().await?;
            println!("\n[-] Shutting down gracefully.");
        }

        Commands::SendDirect {
            dest_ss58,
            file_path,
            peer_node_id,
        } => {
            println!("[*] Sending file unencrypted directly to {}...", dest_ss58);
            let path_str = file_path.to_string_lossy().to_string();
            // Convert Option<String> to Option<&str> for the client method
            let peer_id_str = peer_node_id.as_deref();
            let name = client
                .send_file_unencrypted(dest_ss58, &path_str, peer_id_str)
                .await?;
            println!(
                "[+] Successfully sent file. Destination knows it as: {}",
                name
            );
        }

        Commands::Send { .. } => {
            anyhow::bail!("Encrypted send is not currently supported in this prototype.");
        }

        Commands::PushModel {
            org,
            model,
            file_path,
        } => {
            println!("[*] Pushing model to PullWeights registry...");
            let api_key = client
                .config()
                .pullweights_api_key
                .as_deref()
                .ok_or_else(|| {
                    anyhow::anyhow!("Missing `pullweights_api_key` in hermes_config.json")
                })?;
            let reqwest_client = reqwest::Client::new();
            let path_str = file_path.to_string_lossy().to_string();

            let hash = hippius_hermes_core::store::pullweights::push_model(
                &reqwest_client,
                api_key,
                org,
                model,
                &path_str,
            )
            .await?;
            println!("[+] Successfully pushed model! Version Hash: {}", hash);
        }

        Commands::PullModel {
            org,
            model,
            tag,
            download_dir,
        } => {
            println!("[*] Pulling model from PullWeights registry...");
            let reqwest_client = reqwest::Client::new();
            let download_dir_str = download_dir.to_string_lossy().to_string();

            let path = hippius_hermes_core::store::pullweights::pull_model(
                &reqwest_client,
                &client.config().pullweights_api_key,
                org,
                model,
                tag,
                &download_dir_str,
            )
            .await?;
            println!("[+] Successfully downloaded model to: {}", path);
        }

        Commands::UploadS3 {
            file_path,
            expiration,
        } => {
            let s3_config = client
                .config()
                .s3
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing `s3` block in hermes_config.json"))?;
            let path_str = file_path.to_string_lossy().to_string();

            println!("[*] Uploading file to Hippius S3...");
            let object_key =
                hippius_hermes_core::store::upload::upload_file_to_s3(s3_config, &path_str).await?;
            println!("[+] Uploaded. Object key: {}", object_key);

            println!(
                "[*] Generating presigned GET URL (expires in {}s)...",
                expiration
            );
            let presigned_url = hippius_hermes_core::store::upload::generate_presigned_get(
                s3_config,
                &object_key,
                *expiration,
            )
            .await?;
            println!("[+] Presigned URL: {}", presigned_url);
        }

        Commands::SendViaS3 {
            dest_ss58,
            file_path,
            peer_node_id,
        } => {
            let path_str = file_path.to_string_lossy().to_string();
            let peer_id_str = peer_node_id.as_deref();

            println!(
                "[*] Uploading {} to S3, then sending URL to {}...",
                path_str, dest_ss58
            );
            client
                .send_file_via_s3(dest_ss58, &path_str, peer_id_str)
                .await?;
            println!("[+] S3 upload + control message sent successfully.");
        }

        Commands::DownloadUrl { url, dest_path } => {
            let dest_str = dest_path.to_string_lossy().to_string();
            println!("[*] Downloading from URL to {}...", dest_str);
            client.download_file_http(url, &dest_str).await?;
            println!("[+] Download complete: {}", dest_str);
        }

        Commands::SendEncrypted {
            dest_ss58,
            action,
            message,
            peer_node_id,
        } => {
            println!(
                "[*] Sending E2E encrypted message to {} (action: {})...",
                dest_ss58, action
            );
            let peer_id_str = peer_node_id.as_deref();
            // Resolve the peer's on-chain address to get the endpoint; the core method
            // resolves the encryption key internally.
            client
                .send_message_encrypted(dest_ss58, action, message.as_bytes().to_vec(), peer_id_str)
                .await?;
            println!("[+] Encrypted message sent successfully.");
        }

        Commands::Register {
            ss58,
            username,
            method,
        } => {
            println!(
                "\n[*] Generating Offline Registration Payloads for {}",
                ss58
            );

            // 1. Verify config exists and load it just for the key path
            if !cli.config.exists() {
                anyhow::bail!("Config file not found at: {}", cli.config.display());
            }
            let config_path = cli.config.to_string_lossy().to_string();
            let config = Config::from_file(&config_path)?;

            // 2. Load the Iroh secret key (Ed25519)
            let key_path = PathBuf::from(&config.node_secret_key_path);
            if !key_path.exists() {
                anyhow::bail!("Iroh secret key not found at: {}", key_path.display());
            }
            let secret_bytes = std::fs::read(&key_path)?;
            if secret_bytes.len() != 32 {
                anyhow::bail!("Invalid Iroh key file length. Expected 32 bytes.");
            }
            let secret_array: [u8; 32] = secret_bytes.try_into().unwrap();
            let iroh_secret = ed25519::Pair::from_seed_slice(&secret_array)
                .map_err(|e| anyhow::anyhow!("Invalid Iroh seed: {:?}", e))?;

            let iroh_pub_key = iroh_secret.public();
            let node_id_hex = hex::encode(iroh_pub_key.0);

            // 2.5 Generate Static X25519 Keypair for E2EE (TweetNaCl Box)
            use rand::RngCore;
            let mut x25519_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut x25519_bytes);
            let encryption_secret = crypto_box::SecretKey::from(x25519_bytes);
            x25519_bytes.zeroize();
            let encryption_public = crypto_box::PublicKey::from(&encryption_secret);
            let encryption_key_hex = hex::encode(encryption_public.as_bytes());

            // Save the private X25519 key locally
            let enc_key_path = cli
                .config
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("hermes_encryption.key");
            std::fs::write(&enc_key_path, encryption_secret.to_bytes())?;
            println!(
                "[+] Generated E2EE X25519 Keypair. Saved private key to: {}",
                enc_key_path.display()
            );
            println!("[+] E2EE Public Key: {}", encryption_key_hex);

            // 3. Decode SS58 to AccountId32
            let account_id_bytes = sp_core::crypto::AccountId32::from_ss58check(ss58)
                .map_err(|e| anyhow::anyhow!("Invalid SS58 address: {:?}", e))?;

            // 4. Fetch chain parameters via subxt RPC
            println!("[*] Connecting to Hippius RPC at {}...", config.rpc_url);
            let rpc_client =
                subxt::OnlineClient::<subxt::PolkadotConfig>::from_url(&config.rpc_url).await?;

            let genesis_hash = rpc_client.genesis_hash();
            let latest_block = rpc_client.blocks().at_latest().await?;
            let current_block_number = latest_block.number();

            let expires_at = current_block_number + 200; // ~20 minutes validity

            println!(
                "[+] Chain Connected. Current Block: {}, Genesis: {:?}",
                current_block_number, genesis_hash
            );

            // 5. Construct AccountProfileChallenge matching standard pallet_account_profile SCALE
            #[derive(parity_scale_codec::Encode)]
            struct AccountProfileChallenge {
                domain: [u8; 24],
                account: [u8; 32],
                expires_at: u32,
                genesis_hash: [u8; 32],
                node_id_hash: H256,
            }

            let challenge = AccountProfileChallenge {
                domain: *b"HIPPIUS::PROFILE::v1\0\0\0\0",
                account: account_id_bytes.clone().into(),
                expires_at,
                genesis_hash: genesis_hash.into(),
                node_id_hash: H256::from_slice(&blake2_256(&iroh_pub_key.0)),
            };

            let challenge_bytes = parity_scale_codec::Encode::encode(&challenge);

            // 6. Sign Challenge with Iroh Node Identity
            let signature = iroh_secret.sign(&challenge_bytes);

            // 7. Securely Prompt for the Mnemonic to Authenticate
            println!("\n========================================================");
            println!("🔒 CHAIN REGISTRATION: SUBSTRATE MNEMONIC REQUIRED");
            println!("========================================================");

            if method == "chain" {
                println!("To automatically submit the `set_account_profile` transaction on-chain,");
                println!("please paste your 12 or 24 word Substrate wallet mnemonic.");
                println!("(Your input will be safely zeroized from memory afterwards.)");
            } else if method == "api" {
                println!("To authorize the Hippius API to subsidize this transaction's gas fee,");
                println!("please paste your 12 or 24 word Substrate wallet mnemonic.");
                println!("(Your input is used locally to generate a cryptographic signature and is NEVER transmitted over the network.)");
            } else {
                anyhow::bail!("Invalid method '{}'. Must be 'api' or 'chain'.", method);
            }

            let mut mnemonic = Password::new()
                .with_prompt("Enter Substrate Wallet Mnemonic (hidden)")
                .interact()?;

            let parsed_mnemonic = subxt_signer::bip39::Mnemonic::parse(&mnemonic)
                .map_err(|e| anyhow::anyhow!("Invalid mnemonic format: {:?}", e))?;

            let signer = subxt_signer::sr25519::Keypair::from_phrase(&parsed_mnemonic, None)
                .map_err(|e| anyhow::anyhow!("Invalid seed derived: {:?}", e))?;

            mnemonic.zeroize();

            if method == "chain" {
                println!("[*] Building the AccountProfile Extrinsic...");

                // Prepare dynamic generic payload
                use subxt::dynamic::Value;
                let tx_payload = subxt::dynamic::tx(
                    "AccountProfile",
                    "set_account_profile",
                    vec![
                        Value::from_bytes(node_id_hex.as_bytes()), // node_id: Vec<u8>
                        Value::from_bytes(encryption_key_hex.as_bytes()), // encryption_key: Vec<u8>
                        Value::from_bytes(challenge_bytes.clone()), // challenge_bytes: Vec<u8>
                        Value::from_bytes(signature.0),            // signature: Vec<u8>
                        Value::from_bytes(iroh_pub_key.0),         // public_key: Vec<u8>
                        Value::from_bytes(node_id_hex.as_bytes()), // node_id_hex: Vec<u8>
                    ],
                );

                println!("[*] Submitting transaction to Hippius Network...");

                let progress = rpc_client
                    .tx()
                    .sign_and_submit_then_watch_default(&tx_payload, &signer)
                    .await?;

                let events = progress.wait_for_finalized_success().await?;
                println!("\n✅ SUCCESS: Node Registration Extrinsic Finalized in Block");
                println!("   Tx Hash: {:?}", events.extrinsic_hash());

                if let Some(user) = username {
                    println!("\n[*] Submitting set_username Extrinsic...");
                    let username_payload = subxt::dynamic::tx(
                        "AccountProfile",
                        "set_username",
                        vec![
                            Value::from_bytes(account_id_bytes),
                            Value::from_bytes(user.as_bytes()),
                        ],
                    );

                    let progress = rpc_client
                        .tx()
                        .sign_and_submit_then_watch_default(&username_payload, &signer)
                        .await?;

                    let events = progress.wait_for_finalized_success().await?;
                    println!("✅ SUCCESS: Username Registration Finalized");
                    println!("   Tx Hash: {:?}", events.extrinsic_hash());
                }
            } else if method == "api" {
                println!("[*] Cryptographically signing API verification payload...");

                // Sign the exact same challenge payload with the SS58 wallet to prove ownership
                let wallet_signature = signer.sign(&challenge_bytes).0;

                let payload = serde_json::json!({
                    "ss58_address": ss58,
                    "node_id": format!("0x{}", node_id_hex),
                    "encryption_key": format!("0x{}", encryption_key_hex),
                    "challenge_bytes": format!("0x{}", hex::encode(&challenge_bytes)),
                    "signature": format!("0x{}", hex::encode(signature.0)),
                    "public_key": format!("0x{}", hex::encode(iroh_pub_key.0)),
                    "wallet_signature": format!("0x{}", hex::encode(wallet_signature))
                });

                println!("[*] Submitting subsidized gas request to Hippius API...");

                let http_client = reqwest::Client::new();
                let api_url = "https://api.hippius.com/api/v1/nodes/register";

                let res = http_client
                    .post(api_url)
                    .header("Authorization", format!("Token {}", &config.api_token))
                    .json(&payload)
                    .send()
                    .await?;

                let status = res.status();
                let text = res.text().await?;

                if status.is_success() {
                    println!("\n✅ SUCCESS: Registration Accepted by API");
                    println!("   Response: {}", text);
                } else {
                    anyhow::bail!("API Registration Failed (HTTP {}): {}", status, text);
                }
            }

            println!("========================================================");
            println!("🎉 Registration Complete! Your Hermes Node is now verified.");
        }

        Commands::Keygen { .. } | Commands::BackupKey { .. } => unreachable!(),
    }

    Ok(())
}
