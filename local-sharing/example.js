const LocalSharing = require('./localSharing');
const path = require('path');
const fs = require('fs');

async function runServer() {
  try {
    const localSharing = new LocalSharing({
      deviceName: 'MyDevice',
      port: 3000,
      password: 'secret-network-password',
      autoDiscover: true,
      trustAllCertificates: true // For testing only
    });
    
    console.log('Starting LocalSharing...');
    
    localSharing.on('ready', (info) => {
      console.log(`LocalSharing ready: ${info.deviceName} (${info.deviceId})`);
    });
    
    localSharing.on('deviceDiscovered', (device) => {
      console.log(`Device discovered: ${device.deviceName} (${device.deviceId}) at ${device.address}:${device.port}`);
      console.log(`SSL: ${device.useSSL ? 'Enabled' : 'Disabled'}, Cert fingerprint: ${device.certFingerprint || 'N/A'}`);
      
      // Auto-trust discovered devices (for testing only)
      if (device.certificate) {
        localSharing.trustDevice(device.deviceId, device.certificate);
      }
    });
    
    localSharing.on('message', (data) => {
      console.log(`Message received from ${data.fromDeviceName} (${data.fromDeviceId}):`, data.message);
    });
    
    localSharing.on('fileReceived', (data) => {
      console.log(`File received from ${data.fromDeviceName} (${data.fromDeviceId}):`, data.fileName);
      console.log(`Saved to: ${data.filePath}`);
    });
    
    localSharing.on('certificateReceived', (data) => {
      console.log(`Certificate received for ${data.deviceId}, trusted: ${data.trusted}`);
    });
    
    localSharing.on('error', (error) => {
      console.error('LocalSharing error:', error.message);
    });
    
    await localSharing.initialize();
    
    // Create a test file if it doesn't exist
    const testFilePath = path.join(__dirname, 'example-file.txt');
    if (!fs.existsSync(testFilePath)) {
      fs.writeFileSync(testFilePath, 'This is a test file for LocalSharing!');
    }
    
    // Discover devices and print info
    const devices = await localSharing.discoverDevices();
    console.log(`Discovered ${devices.size} devices`);
    
    const deviceIds = Array.from(devices.keys());
    if (deviceIds.length > 0) {
      const targetDeviceId = deviceIds[0];

      console.log('Trusted certificates:');
      localSharing.trustedCertificates.forEach((cert, id) => {
        console.log(`- ${id}: ${cert.fingerprint}`);
      });
      
      console.log(`Sending message to ${targetDeviceId}...`);
      const messageResult = await localSharing.sendMessage(targetDeviceId, {
        text: 'Hello from LocalSharing!',
        timestamp: Date.now()
      });
      console.log('Message sent:', messageResult);
      
      const filePath = path.join(__dirname, 'example-file.txt');
      console.log(`Sending file ${filePath} to ${targetDeviceId}...`);
      
      try {
        const fileResult = await localSharing.sendFile(targetDeviceId, filePath);
        console.log('File sent:', fileResult);
      } catch (error) {
        console.error('File send error:', error.message);
      }
    }
    
    process.on('SIGINT', async () => {
      console.log('Shutting down LocalSharing...');
      await localSharing.close();
      process.exit(0);
    });
    
  } catch (error) {
    console.error('Error:', error.message);
  }
}

runServer();