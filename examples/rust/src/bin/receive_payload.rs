use hippius_hermes_core::{Client, config::Config};
use std::path::PathBuf;

const ASCII_ART: &str = r#"
    __  ___                 _                 __  __                             
   / / / (_)___  ____  ____(_)__  _______    / / / /__  _________ ___  ___  _____
  / /_/ / / __ \/ __ \/ __ \ / / / / ___/   / /_/ / _ \/ ___/ __ `__ \/ _ \/ ___/
 / __  / / /_/ / /_/ / /_/ / / /_/ (__  )  / __  /  __/ /  / / / / / /  __(__  ) 
/_/ /_/_/ .___/ .___/ .___/_/\__,_/____/  /_/ /_/\___/_/  /_/ /_/ /_/\___/____/  
       /_/   /_/   /_/                                                           

    [ Hippius Hermes - P2P Mass Data Messenger ]
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("{}", ASCII_ART);
    println!("[*] Initializing Hermes Native Core Listener...");

    let config = Config {
        node_secret_key_path: "iroh.key".into(),
        ss58_address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
        api_token: "your_hippius_api_token".to_string(),
        storage_directory: PathBuf::from(".hermes_data"),
        rpc_url: "wss://rpc.hippius.network:443".to_string(),
        subnet_ids: vec![],
        enable_firewall: false,
        s3: None,
        pullweights_api_key: None,
        skip_identity_verification: false,
        enable_queue: false,
        encryption_key_path: None,
    };

    let client = Client::new(config).await?;
    println!("[+] Core Engine and Iroh Networking Online!");
    println!("[*] Binding Iroh QUIC Router to local port. Awaiting incoming Substrate connections...");

    // Hand over Rust callback closure directly into the rust tokio loop
    client.spawn_listener(
        |msg| {
            println!(
                "\n[>>>] INCOMING SECURE MESSAGE FROM {}",
                msg.sender_ss58
            );
            println!("      Action: {}", msg.action);

            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                let hash = meta["hash"].as_str().unwrap_or("UNKNOWN");
                let mut num_keys = 0;
                if let Some(arr) = meta["encrypted_keys"].as_array() {
                    num_keys = arr.len();
                }

                println!("      HCFS Hash: {}", hash);
                println!("      Cipher Key Payload: <{} bytes>", num_keys);
                println!("[*] To read the massive gradients, your worker would now cleanly download from https://arion.hippius.com/download/{}", hash);
                println!("[*] And decrypt it locally using your Wallet's Private Key!");
            } else {
                println!("      Raw Payload Bytes: {} bytes", msg.payload.len());
            }
        },
        None::<fn(String, String, String, u64)>,
    );

    // Keep the main process thread alive
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    }
}
