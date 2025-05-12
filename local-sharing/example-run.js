const LocalSharing = require('./localSharing');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Get environment variables
const deviceName = process.env.DEVICE_NAME || 'MyDevice';
const devicePort = parseInt(process.env.DEVICE_PORT || '8765');
const useSSL = process.env.USE_SSL !== 'false'; // Default to true
const generateKeys = process.env.GENERATE_KEYS !== 'false'; // Default to true
const trustAllCerts = process.env.TRUST_ALL_CERTIFICATES === 'true';
const password = process.env.NETWORK_PASSWORD || 'secret-network-password';

// Display network interfaces for debugging
console.log('Network interfaces:');
Object.entries(require('os').networkInterfaces()).forEach(([iface, addrs]) => {
  addrs.forEach(addr => {
    console.log(`${iface}: ${addr.address} (${addr.family})`);
  });
});

// Log SSL configuration
console.log(`SSL Config: useSSL=${useSSL}, generateKeys=${generateKeys}, trustAll=${trustAllCerts}`);

console.log(`Starting LocalSharing as ${deviceName} on port ${devicePort}...`);

async function runApp() {
  try {
    const localSharing = new LocalSharing({
      deviceName,
      port: devicePort,
      useSSL,
      generateKeys,
      trustAllCertificates: trustAllCerts,
      password,
      keysDirectory: '/app/keys'
    });

    // Event handlers
    localSharing.on('ready', (info) => {
      console.log(`LocalSharing ready: ${info.deviceName} (${info.deviceId})`);
    });

    localSharing.on('deviceDiscovered', (device) => {
      console.log(`Device discovered: ${device.deviceName} (${device.deviceId}) at ${device.address}:${device.port}`);
      console.log(`SSL: ${device.useSSL ? 'Enabled' : 'Disabled'}, Cert fingerprint: ${device.certFingerprint || 'N/A'}`);
      
      // Auto-trust discovered devices for testing
      if (trustAllCerts && device.certificate) {
        localSharing.trustDevice(device.deviceId, device.certificate);
        console.log(`Auto-trusted device: ${device.deviceName}`);
      }
    });

    localSharing.on('message', (data) => {
      console.log(`Message received from ${data.fromDeviceId}:`);
      console.log(`Message content: ${JSON.stringify(data.message)}`);
      console.log(`Verified: ${data.verified ? 'Yes' : 'No'}`);
    });

    localSharing.on('fileReceived', (data) => {
      console.log(`File received from ${data.fromDeviceName} (${data.fromDeviceId}):`);
      console.log(`File: ${data.fileName}, saved to: ${data.filePath}`);
      console.log(`Verified: ${data.signatureVerified ? 'Yes' : 'No'}`);
    });

    localSharing.on('error', (error) => {
      console.error('LocalSharing error:', error.message);
    });

    // Initialize the system
    await localSharing.initialize();
    
    console.log('Discovering devices...');
    const devices = await localSharing.discoverDevices();

    // Periodically rediscover devices and send test messages
    setInterval(async () => {
      console.log('Rediscovering devices...');
      await localSharing.discoverDevices();
      
      const deviceValues = Array.from(localSharing.knownDevices.values());
      console.log(`Found ${deviceValues.length} devices`);
      console.log('Trusted certificates:');
      localSharing.trustedCertificates.forEach((cert, id) => {
        console.log(`- ${id}: ${cert.fingerprint.substring(0, 16)}...`);
      });

      // Send test messages to all known devices
      deviceValues.forEach(async (device) => {
        if (device.deviceId !== localSharing.deviceId) {
          console.log(`Sending test message to ${device.deviceName}...`);
          try {
            const result = await localSharing.sendMessage(device.deviceId, {
              text: `Hello from ${deviceName}!`,
              timestamp: Date.now()
            });
            console.log(`Message sent: ${JSON.stringify(result)}`);
            
            // Try to send a file
            console.log(`Sending file /example-file.txt to ${device.deviceName}...`);
            try {
              const fileResult = await localSharing.sendFile(device.deviceId, '/app/example-file.txt');
              console.log(`File sent: ${JSON.stringify(fileResult)}`);
            } catch (fileErr) {
              console.log(`File send error: ${fileErr.message}`);
              
              // If public key issue, manually exchange public keys
              if (fileErr.message.includes('No public key available')) {
                console.log(`Attempting to manually exchange keys with ${device.deviceName}...`);
                
                // For non-SSL devices, use a simplified method
                if (!device.useSSL || !localSharing.useSSL) {
                  try {
                    await exchangePublicKeys(localSharing, device);
                  } catch (keyExErr) {
                    console.error(`Key exchange error: ${keyExErr.message}`);
                  }
                }
              }
            }
          } catch (err) {
            console.log(`Failed to send message to ${device.deviceName}: ${err.message}`);
          }
        }
      });
    }, 20000);
  } catch (error) {
    console.error(`Error initializing LocalSharing: ${error.message}`);
  }
}

/**
 * Exchange public keys between devices for non-SSL mode
 * @param {LocalSharing} localSharing The local sharing instance
 * @param {Object} device The target device
 */
async function exchangePublicKeys(localSharing, device) {
  try {
    // Use HTTP for simple key exchange
    const http = require('http');
    const keyExchangeData = JSON.stringify({
      deviceId: localSharing.deviceId,
      deviceName: localSharing.deviceName,
      publicKey: localSharing.publicKeyPem,
      useSSL: localSharing.useSSL
    });

    const options = {
      hostname: device.address,
      port: device.port,
      path: '/exchange-key',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(keyExchangeData)
      }
    };
    
    return new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Failed with status code: ${res.statusCode}`));
          return;
        }
        
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            
            // Store the received key
            if (response.publicKey && device.deviceId) {
              if (!localSharing.trustedCertificates.has(device.deviceId)) {
                localSharing.trustedCertificates.set(device.deviceId, {
                  publicKey: response.publicKey,
                  deviceName: device.deviceName,
                  useSSL: response.useSSL === true
                });
                console.log(`Stored public key for ${device.deviceName}`);
              }
              
              // Update device record
              device.publicKey = response.publicKey;
              console.log(`Updated public key for ${device.deviceName}`);
            }
            
            resolve(response);
          } catch (e) {
            reject(new Error('Invalid response format'));
          }
        });
      });
      
      req.on('error', reject);
      req.write(keyExchangeData);
      req.end();
    });
  } catch (err) {
    console.error(`Public key exchange failed: ${err.message}`);
    throw err;
  }
}

runApp();