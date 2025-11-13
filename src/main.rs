use std::error::Error;
use clap::{Parser, ValueEnum};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

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
        return Err(format!("Failed to get metadata from {}: {}", path, response.status()).into());
    }
    
    Ok(response.text()?)
}

fn process_aws() -> Result<(), Box<dyn Error>> {
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
        &format!("iam/security-credentials/{}", role_name)
    )?;
    
    // Parse JSON
    let credentials: AwsCredentials = serde_json::from_str(&credentials_json)?;
    
    // Write to file
    std::fs::write("aws_token", &credentials_json)?;
    println!("\nCredentials saved to aws_token");
    
    // Display export commands
    println!("\n=== Export these environment variables ===");
    println!("export AWS_ACCESS_KEY_ID={}", credentials.access_key_id);
    println!("export AWS_SECRET_ACCESS_KEY={}", credentials.secret_access_key);
    println!("export AWS_SESSION_TOKEN={}", credentials.token);
    println!("\nNow run: aws sts get-caller-identity");
    
    Ok(())
}

fn main() {
    let args = Args::parse();
    
    let result = match args.cloud {
        CloudProvider::AWS => process_aws(),
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
