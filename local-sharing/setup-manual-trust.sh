#!/bin/bash
set -e

echo "Setting up manual trust between Device1 and Device2"
echo "=================================================="

# First, make sure we have the cert-manager container running
if ! docker ps | grep -q cert-manager; then
  echo "cert-manager container not running. Start the environment first."
  exit 1
fi

# Check if we have shared certificates
if [ ! -f shared-certs/device1_cert.pem ] || [ ! -f shared-certs/device2_cert.pem ]; then
  echo "Certificates not found in shared-certs directory."
  echo "Make sure both devices have generated certificates and they've been copied to shared-certs."
  exit 1
fi

# Create a NodeJS script to establish trust through the API
cat > trust-device.js << 'EOF'
const http = require('http');
const https = require('https');
const fs = require('fs');

// Usage: node trust-device.js <device-host> <device-port> <use-ssl> <target-device-id> <certificate-file>
const deviceHost = process.argv[2];
const devicePort = process.argv[3];
const useSSL = process.argv[4] === 'true';
const targetDeviceId = process.argv[5];
const certFile = process.argv[6];

// Read the certificate
const cert = fs.readFileSync(certFile, 'utf8');
console.log(`Read certificate from ${certFile}, length: ${cert.length}`);

// Calculate certificate fingerprint
const crypto = require('crypto');
const fingerprint = crypto.createHash('sha256').update(cert).digest('hex');
console.log(`Certificate fingerprint: ${fingerprint}`);

// Create a HTTP/HTTPS request to establish trust
const postData = JSON.stringify({
  deviceId: targetDeviceId,
  certificate: cert,
  fingerprint: fingerprint
});

const options = {
  hostname: deviceHost,
  port: devicePort,
  path: '/trust',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(postData)
  },
  rejectUnauthorized: false // Allow self-signed certs during trust establishment
};

const protocol = useSSL ? https : http;

const req = protocol.request(options, (res) => {
  console.log(`STATUS: ${res.statusCode}`);
  let data = '';
  
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log(`Response: ${data}`);
  });
});

req.on('error', (e) => {
  console.error(`Problem with request: ${e.message}`);
});

console.log('Sending trust request...');
req.write(postData);
req.end();
EOF

chmod +x trust-device.js

echo "Waiting for devices to be ready..."
sleep 5

# Extract device IDs from logs
echo "Extracting Device1 ID..."
DEVICE1_ID=$(docker logs device1 2>&1 | grep -o "deviceId.*" | head -1 | cut -d':' -f2 | tr -d ' ,"')
echo "Device1 ID: $DEVICE1_ID"

echo "Extracting Device2 ID..."
DEVICE2_ID=$(docker logs device2 2>&1 | grep -o "deviceId.*" | head -1 | cut -d':' -f2 | tr -d ' ,"')
echo "Device2 ID: $DEVICE2_ID"

if [ -z "$DEVICE1_ID" ] || [ -z "$DEVICE2_ID" ]; then
  echo "Failed to extract device IDs from logs. Make sure the containers are running properly."
  exit 1
fi

echo "Setting up Device2 to trust Device1..."
docker cp trust-device.js device2:/app/
docker cp shared-certs/device1_cert.pem device2:/app/
docker exec device2 node /app/trust-device.js localhost 8767 true "$DEVICE1_ID" /app/device1_cert.pem

echo "Setting up Device1 to trust Device2..."
docker cp trust-device.js device1:/app/
docker cp shared-certs/device2_cert.pem device1:/app/
docker exec device1 node /app/trust-device.js localhost 8765 true "$DEVICE2_ID" /app/device2_cert.pem

echo "Manual trust setup complete."
echo "You can now test secure communication between devices."

# Check if certificates are trusted
echo "Verifying trust relationships..."
echo "Device1 trusts:"
docker exec device1 node -e "const fs = require('fs'); const files = fs.readdirSync('/app/keys').filter(f => f.includes('trust')); console.log(files);"

echo "Device2 trusts:"
docker exec device2 node -e "const fs = require('fs'); const files = fs.readdirSync('/app/keys').filter(f => f.includes('trust')); console.log(files);"
