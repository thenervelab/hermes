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
    println!("[*] Initializing Hermes Core Client...");

    let data_dir = PathBuf::from(".hermes_data");

    let config = Config {
        node_secret_key_path: "iroh.key".into(),
        ss58_address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
        api_token: "your_hippius_api_token".to_string(),
        storage_directory: data_dir.clone(),
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

    let dest_ss58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"; // Alice

    // Write sample data to a temp file (the API works with files, not raw bytes)
    std::fs::create_dir_all(&data_dir)?;
    let sample_file = data_dir.join("sample_payload.bin");
    std::fs::write(&sample_file, b"Hello from Hippius Native Rust SDK! Imagine this is a 5GB tensor file.")?;

    println!("[*] Preparing to transmit payload to {}...", dest_ss58);

    match client.send_file_unencrypted(dest_ss58, sample_file.to_str().unwrap(), None).await {
        Ok(filename) => {
            println!("\n[SUCCESS] Payload sent directly via P2P QUIC.");
            println!("[SUCCESS] Filename: {}", filename);
        }
        Err(e) => {
            println!("[-] Transmission failed or buffered offline: {}", e);
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(&sample_file);

    Ok(())
}
