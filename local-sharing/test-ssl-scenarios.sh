#!/bin/bash
set -e

echo "LocalSharing SSL Testing Scenarios"
echo "=================================="

# Create necessary directories
mkdir -p device1-data device2-data device3-data device1-keys device2-keys shared-certs

echo "Starting containers with different SSL configurations..."
docker-compose up -d

echo "Waiting for services to be ready..."
sleep 30  # Give more time for certificates to be generated

echo -e "\n---- TESTING SCENARIO 1: Automatic Certificate Exchange ----"
echo "Device1 and Device2 both have SSL enabled with auto-generated certificates."
echo "Checking if they discovered each other..."
docker logs device1 | grep -i "Device discovered: Device2" || echo "Device1 didn't discover Device2"
docker logs device2 | grep -i "Device discovered: Device1" || echo "Device2 didn't discover Device1"

echo -e "\n---- TESTING SCENARIO 2: Certificates Received ----"
echo "Checking if certificates were exchanged..."
docker logs device1 | grep -i "Certificate received" || echo "Device1 didn't receive certificate"
docker logs device2 | grep -i "Certificate received" || echo "Device2 didn't receive certificate"

echo -e "\n---- TESTING SCENARIO 3: Certificate Trust Verification ----"
echo "Checking if certificates were trusted..."
docker logs device1 | grep -i "Trusted: Yes" || echo "Device1 hasn't trusted any certificates yet"
docker logs device2 | grep -i "Trusted: Yes" || echo "Device2 hasn't trusted any certificates yet"

echo -e "\n---- TESTING SCENARIO 4: Message Exchange with Encryption ----"
echo "Checking if encrypted messages were sent and received between Device1 and Device2..."
docker logs device1 | grep -i "Message sent:" || echo "Device1 didn't send message"
docker logs device2 | grep -i "Message received from" || echo "Device2 didn't receive message"

echo -e "\n---- TESTING SCENARIO 5: File Transfer with Encryption ----"
echo "Checking if encrypted files were transferred..."
docker logs device1 | grep -i "File sent:" || echo "Device1 didn't send file"
docker logs device2 | grep -i "File received from" || echo "Device2 didn't receive file"

echo -e "\n---- TESTING SCENARIO 6: Connection with Non-SSL Device ----"
echo "Checking if non-SSL device discovered SSL devices..."
docker logs device3 | grep -i "Device discovered:" || echo "Device3 didn't discover SSL devices"
docker logs device1 | grep -i "Device discovered: Device3" || echo "Device1 didn't discover Device3"

echo -e "\n---- CERTIFICATES EXCHANGE CHECK ----"
echo "Checking shared certificates directory..."
ls -l shared-certs/

echo -e "\n---- CERTIFICATE FINGERPRINTS ----"
if [ -f shared-certs/device1_cert.pem ]; then
  echo "Device1 Certificate Fingerprint:"
  openssl x509 -noout -fingerprint -sha256 -in shared-certs/device1_cert.pem
fi
if [ -f shared-certs/device2_cert.pem ]; then
  echo "Device2 Certificate Fingerprint:"
  openssl x509 -noout -fingerprint -sha256 -in shared-certs/device2_cert.pem
fi

echo -e "\n---- TRUSTED CERTIFICATES CHECK ----"
echo "Running manual trust setup..."
./setup-manual-trust.sh || echo "Manual trust setup failed, but test continues"

echo -e "\n---- SENDING TEST MESSAGE AFTER TRUST SETUP ----"
echo "Sending a test message from Device1 to Device2..."
docker exec device1 node -e "
const LocalSharing = require('./localSharing');
const localSharing = new LocalSharing({
  deviceName: 'TestScript',
  port: 8888,
  useSSL: true,
  keysDirectory: '/app/keys'
});

async function sendTestMessage() {
  try {
    await localSharing.initialize();
    const devices = await localSharing.discoverDevices();
    const device2 = Array.from(devices.values()).find(d => d.deviceName === 'Device2');
    if (device2) {
      console.log('Found Device2, sending test message...');
      const result = await localSharing.sendMessage(device2.deviceId, 'Test message after trust setup');
      console.log('Result:', result);
    } else {
      console.log('Device2 not found');
    }
    await localSharing.close();
  } catch (e) {
    console.error('Error:', e.message);
  }
}

sendTestMessage();
" || echo "Failed to send test message"

echo -e "\n---- TESTING COMPLETED ----"
echo "Check the logs for more details:"
echo "docker logs device1"
echo "docker logs device2"
echo "docker logs device3"

echo -e "\nTo stop the test environment:"
echo "docker-compose down"
