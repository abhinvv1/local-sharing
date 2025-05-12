const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dgram = require('dgram');
const os = require('os');
const { EventEmitter } = require('events');
const { promisify } = require('util');
const forge = require('node-forge');

/**
 * LocalSharing - A library for secure local network communication
 * 
 * Features:
 * - Device discovery on local network
 * - Secure authentication and communication
 * - File transfers
 * - Messaging between devices
 */
class LocalSharing extends EventEmitter {
  /**
   * Create a new LocalSharing instance
   * @param {Object} options Configuration options
   * @param {string} options.deviceName Name for this device on the network
   * @param {number} [options.port=8765] Port to use for HTTP server
   * @param {boolean} [options.useSSL=false] Whether to use HTTPS (requires cert and key)
   * @param {string} [options.certPath] Path to SSL certificate file if using HTTPS
   * @param {string} [options.keyPath] Path to SSL key file if using HTTPS
   * @param {string} [options.caPath] Path to CA certificate bundle for verifying peer certificates
   * @param {boolean} [options.generateKeys=false] Auto-generate keys if not provided
   * @param {string} [options.keysDirectory] Directory to store generated keys
   * @param {string} [options.password] Network password for authentication
   * @param {boolean} [options.autoDiscover=true] Automatically discover devices on initialization
   * @param {boolean} [options.trustAllCertificates=false] Trust all certificates (insecure, for testing only)
   */
  constructor(options) {
    super();
    
    if (!options || !options.deviceName) {
      throw new Error('Device name is required');
    }
    
    this.deviceName = options.deviceName;
    this.deviceId = this._generateDeviceId();
    this.port = options.port || 8765;
    this.useSSL = options.useSSL !== false;
    this.password = options.password || '';
    this.autoDiscover = options.autoDiscover !== false;
    this.trustAllCertificates = options.trustAllCertificates || false;
    
    // Key management options
    this.generateKeys = options.generateKeys !== false;
    this.keysDirectory = options.keysDirectory || path.join(os.homedir(), '.local-sharing', 'keys');
    
    // Internal state
    this.server = null;
    this.discoverySocket = null;
    this.knownDevices = new Map();
    this.trustedCertificates = new Map();
    this.connectionState = 'disconnected';
    this.discoveryPort = 8766; // UDP discovery port
    
    // Cryptography objects
    this.keyPair = null;
    this.certificate = null;
    this.publicKeyPem = null;
    this.privateKeyPem = null;
    this.certificatePem = null;
    
    // SSL options
    this.sslOptions = null;
    
    // Configure SSL if enabled or determine paths for key generation
    if (this.useSSL) {
      const certPath = options.certPath || path.join(this.keysDirectory, `${this.deviceId}_cert.pem`);
      const keyPath = options.keyPath || path.join(this.keysDirectory, `${this.deviceId}_key.pem`);
      const caPath = options.caPath;
      
      // Check if we need to generate keys
      if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
        if (!this.generateKeys) {
          throw new Error('Certificate or key files not found and key generation is disabled');
        }
        
        // We'll generate keys during initialization
        this.certPath = certPath;
        this.keyPath = keyPath;
      } else {
        // Use existing keys
        this.certPath = certPath;
        this.keyPath = keyPath;
        
        // Load the cert and key here to make them available for device discovery
        this.certificatePem = fs.readFileSync(certPath, 'utf8');
        this.privateKeyPem = fs.readFileSync(keyPath, 'utf8');
        this.publicKeyPem = this._extractPublicKeyFromCertificate(this.certificatePem);
        
        // Configure SSL options
        this.sslOptions = {
          cert: this.certificatePem,
          key: this.privateKeyPem,
          requestCert: true,
          rejectUnauthorized: !this.trustAllCertificates,
        };
        
        // Add CA certificates if provided
        if (caPath && fs.existsSync(caPath)) {
          this.sslOptions.ca = fs.readFileSync(caPath);
        }
      }
    }
    
    // Event binding
    this._handleDiscoveryMessage = this._handleDiscoveryMessage.bind(this);
    this._handleHttpRequest = this._handleHttpRequest.bind(this);
  }
  
  /**
   * Initialize the LocalSharing network
   * @returns {Promise<void>}
   */
  async initialize() {
    try {
      // Generate keys if needed
      if (this.useSSL && (!this.certificatePem || !this.privateKeyPem)) {
        await this._generateAndSaveKeypair();
      } else if (!this.useSSL) {
        // Generate a simple identity key even for non-SSL mode
        // This is needed for basic operations and prevents signing errors
        if (!fs.existsSync(this.keysDirectory)) {
          fs.mkdirSync(this.keysDirectory, { recursive: true });
        }
        const keyPath = path.join(this.keysDirectory, `${this.deviceId}_key.pem`);
        
        if (fs.existsSync(keyPath)) {
          // Load existing key if available
          this.privateKeyPem = fs.readFileSync(keyPath, 'utf8');
          this.publicKeyPem = this._extractPublicKeyFromPrivateKey(this.privateKeyPem);
        } else if (this.generateKeys) {
          // Generate a basic keypair for signing operations even without SSL
          const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
              type: 'spki',
              format: 'pem'
            },
            privateKeyEncoding: {
              type: 'pkcs8',
              format: 'pem'
            }
          });
          
          this.privateKeyPem = privateKey;
          this.publicKeyPem = publicKey;
          
          // Save the key for future use
          fs.writeFileSync(keyPath, privateKey);
        }
      }
      
      // Start the HTTP/HTTPS server
      await this._startServer();
      
      // Setup discovery service
      await this._setupDiscovery();
      
      this.connectionState = 'connected';
      this.emit('ready', {
        deviceId: this.deviceId,
        deviceName: this.deviceName,
        port: this.port
      });
      
      // Start auto-discovery if enabled
      if (this.autoDiscover) {
        this.discoverDevices();
      }
      
      return true;
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }
  
  /**
   * Discover devices on the local network
   * @returns {Promise<Map>} Map of discovered devices
   */
  async discoverDevices() {
    // Clear existing devices
    this.knownDevices.clear();
    
    // Broadcast discovery message
    const discoveryMessage = JSON.stringify({
      type: 'discovery',
      deviceId: this.deviceId,
      deviceName: this.deviceName,
      port: this.port,
      useSSL: this.useSSL,
      certFingerprint: this.useSSL ? 
        this._calculateCertificateFingerprint(this.certificatePem) : null,
      timestamp: Date.now()
    });
    
    // Get all network interfaces
    const interfaces = os.networkInterfaces();
    const broadcastAddresses = [];
    
    // Find broadcast addresses for all interfaces
    Object.keys(interfaces).forEach(iface => {
      interfaces[iface].forEach(details => {
        if (details.family === 'IPv4' && !details.internal) {
          // Calculate broadcast address based on address and netmask
          const addressParts = details.address.split('.').map(part => parseInt(part, 10));
          const maskParts = details.netmask.split('.').map(part => parseInt(part, 10));
          
          const broadcastParts = addressParts.map((part, i) => {
            return (part & maskParts[i]) | (~maskParts[i] & 255);
          });
          
          broadcastAddresses.push(broadcastParts.join('.'));
        }
      });
    });``
    
    // Send discovery message to all broadcast addresses
    broadcastAddresses.forEach(broadcastAddr => {
      this.discoverySocket.send(
        discoveryMessage,
        0,
        discoveryMessage.length,
        this.discoveryPort,
        broadcastAddr
      );
    });
    
    // Also send to localhost for testing
    this.discoverySocket.send(
      discoveryMessage,
      0,
      discoveryMessage.length,
      this.discoveryPort,
      '127.0.0.1'
    );
    
    // Wait for responses
    return new Promise(resolve => {
      // Set timeout to resolve after discovery period
      setTimeout(() => {
        this.emit('discovery', Array.from(this.knownDevices.values()));
        resolve(this.knownDevices);
      }, 1000);
    });
  }  
  /**
   * Generate and save a new keypair and self-signed certificate
   * @private
   */
  async _generateAndSaveKeypair() {
    // Create the keys directory if it doesn't exist
    if (!fs.existsSync(this.keysDirectory)) {
      fs.mkdirSync(this.keysDirectory, { recursive: true });
    }
    
    console.log(`Generating new keypair for ${this.deviceName} (${this.deviceId})...`);
    
    // Generate a new RSA key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    // Generate a self-signed certificate
    const cert = this._generateSelfSignedCertificate(privateKey);
    
    // Store the keys and certificate
    this.privateKeyPem = privateKey;
    this.publicKeyPem = publicKey;
    this.certificatePem = cert;
    
    // Save to files
    fs.writeFileSync(this.keyPath, privateKey);
    fs.writeFileSync(this.certPath, cert);
    
    console.log(`Keypair generated and saved to ${this.keysDirectory}`);
    
    // Configure SSL options
    this.sslOptions = {
      cert: cert,
      key: privateKey,
      requestCert: true,
      rejectUnauthorized: !this.trustAllCertificates,
    };
  }
  
  /**
   * Generate a self-signed certificate
   * @param {string} privateKey Private key in PEM format
   * @returns {string} Certificate in PEM format
   * @private
   */
  _generateSelfSignedCertificate(privateKey) {
    console.log(`Generating self-signed certificate for ${this.deviceName} (${this.deviceId})...`);

    try {
      const pki = forge.pki;
      
      // Parse the private key
      const privateKeyObj = pki.privateKeyFromPem(privateKey);
      
      // Create a certificate
      const cert = pki.createCertificate();
      cert.publicKey = pki.setRsaPublicKey(privateKeyObj.n, privateKeyObj.e);
      cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
      
      // Validity period
      const now = new Date();
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(now.getFullYear() + 2); // Valid for 2 years
      
      // Set certificate attributes
      const attrs = [
        { name: 'commonName', value: this.deviceId },
        { name: 'organizationName', value: 'LocalSharing' },
        { shortName: 'OU', value: this.deviceName }
      ];
      cert.setSubject(attrs);
      cert.setIssuer(attrs); // Self-signed
      
      // Add extensions
      cert.setExtensions([
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, dataEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
        { name: 'subjectAltName', altNames: [
          { type: 2, value: this.deviceName },
          { type: 2, value: 'localhost' }
        ]}
      ]);
      
      // Sign the certificate
      cert.sign(privateKeyObj, forge.md.sha256.create());
      
      // Convert to PEM format
      const certPem = pki.certificateToPem(cert);
      console.log(`Certificate generated successfully.`);
      return certPem;
    } catch (error) {
      console.error('Failed to generate certificate:', error.message);
      throw new Error(`Certificate generation failed: ${error.message}`);
    }
  }
  
  /**
   * Extract public key from private key
   * @param {string} privateKeyPem 
   * @returns {string} Public key in PEM format
   * @private
   */
  _extractPublicKeyFromPrivateKey(privateKeyPem) {
    const key = crypto.createPrivateKey(privateKeyPem);
    return crypto.createPublicKey(key).export({
      type: 'spki',
      format: 'pem'
    });
  }
  
  /**
   * Extract public key from certificate
   * @param {string} certificatePem 
   * @returns {string} Public key in PEM format
   * @private
   */
  _extractPublicKeyFromCertificate(certificatePem) {
    try {
      // Always use node-forge for certificate handling for compatibility
      const cert = forge.pki.certificateFromPem(certificatePem);
      return forge.pki.publicKeyToPem(cert.publicKey);
    } catch (error) {
      console.error('Error extracting public key:', error);
      throw error;
    }
  }
  
  /**
   * Add a device's certificate to trusted certificates
   * @param {string} deviceId Device ID to trust
   * @param {string} certificatePem Certificate in PEM format
   * @returns {boolean} Success status
   */
  trustDevice(deviceId, certificatePem) {
    try {
      // Extract the public key using node-forge
      let publicKey;
      try {
        const cert = forge.pki.certificateFromPem(certificatePem);
        publicKey = forge.pki.publicKeyToPem(cert.publicKey);
      } catch (error) {
        throw new Error(`Invalid certificate: ${error.message}`);
      }
      
      // Calculate fingerprint
      const fingerprint = this._calculateCertificateFingerprint(certificatePem);
      
      // Store the certificate
      this.trustedCertificates.set(deviceId, {
        certificatePem,
        publicKey,
        fingerprint
      });
      
      // Update device record if we have one
      const device = this.knownDevices.get(deviceId);
      if (device) {
        device.publicKey = publicKey;
        device.certificate = certificatePem;
        device.certificateFingerprint = fingerprint;
      }
      
      this.emit('deviceTrusted', { deviceId, fingerprint });
      return true;
    } catch (error) {
      this.emit('error', new Error(`Failed to trust device ${deviceId}: ${error.message}`));
      return false;
    }
  }
  
  /**
   * Sign a message with the sender's private key
   * @param {string} message Message to sign
   * @returns {Buffer} Digital signature
   * @private
   */
  _signMessage(message) {
    try {
      // Check if we have a private key
      if (!this.privateKeyPem) {
        if (this.useSSL) {
          throw new Error('Private key not available');
        } else {
          // Return empty signature for non-SSL mode
          return Buffer.from([]);
        }
      }
      
      const sign = crypto.createSign('SHA256');
      sign.update(typeof message === 'string' ? message : JSON.stringify(message));
      return sign.sign(this.privateKeyPem);
    } catch (error) {
      console.error("Error signing message:", error);
      throw new Error(`Failed to sign message: ${error.message}`);
    }
  }
  
  /**
   * Fetch a device's certificate for secure communication
   * @param {string} deviceId Device ID
   * @param {string} address Device IP address
   * @param {number} port Device port
   * @private
   */
  async _fetchDeviceCertificate(deviceId, address, port) {
    // Skip if we already have this device's certificate
    if (this.trustedCertificates.has(deviceId)) {
      return;
    }
    
    // Skip if device doesn't use SSL
    const device = this.knownDevices.get(deviceId);
    if (device && device.useSSL === false) {
      console.log(`Device ${deviceId} doesn't use SSL, skipping certificate fetch`);
      return;
    }
    
    const protocol = this.useSSL ? https : http;
    const options = {
      hostname: address,
      port: port,
      path: '/certificate',
      method: 'GET',
      rejectUnauthorized: false, // Initially allow untrusted connection to get certificate
      timeout: 5000, // Add timeout to prevent hanging
    };
    
    try {
      // Send request
      const response = await new Promise((resolve, reject) => {
        const req = protocol.request(options, (res) => {
          if (res.statusCode !== 200) {
            reject(new Error(`Failed to fetch certificate, status: ${res.statusCode}`));
            return;
          }
          
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          
          res.on('end', () => {
            try {
              const responseObj = JSON.parse(data);
              resolve(responseObj);
            } catch (e) {
              reject(new Error('Invalid certificate response format'));
            }
          });
        });
        
        req.on('error', reject);
        req.setTimeout(5000, () => {
          req.abort();
          reject(new Error('Connection timeout'));
        });
        req.end();
      });
      
      // Validate the certificate
      if (!response.certificate || !response.deviceId || response.deviceId !== deviceId) {
        throw new Error('Invalid certificate data');
      }
      
      // Store certificate and update device info
      if (device) {
        // Calculate fingerprint
        const fingerprint = this._calculateCertificateFingerprint(response.certificate);
        
        // Extract public key from certificate using node-forge
        let publicKey;
        try {
          const cert = forge.pki.certificateFromPem(response.certificate);
          publicKey = forge.pki.publicKeyToPem(cert.publicKey);
        } catch (error) {
          throw new Error(`Invalid certificate format: ${error.message}`);
        }
        
        // Update device with public key info
        device.publicKey = publicKey;
        device.certificate = response.certificate;
        device.certificateFingerprint = fingerprint;
        
        // Store in trusted certificates if fingerprint matches
        if (device.certFingerprint === fingerprint) {
          this.trustedCertificates.set(deviceId, {
            certificatePem: response.certificate,
            publicKey,
            fingerprint
          });
          
          this.emit('certificateReceived', {
            deviceId,
            fingerprint,
            trusted: true
          });
        } else {
          this.emit('certificateReceived', {
            deviceId,
            fingerprint,
            trusted: false,
            expectedFingerprint: device.certFingerprint
          });
        }
      }
    } catch (error) {
      console.log(`Certificate fetch error for ${deviceId}: ${error.message}`);
      this.emit('error', new Error(`Failed to fetch certificate for ${deviceId}: ${error.message}`));
    }
  }
  
  /**
   * Decrypt and verify a received message
   * @param {Buffer} encryptedData The encrypted message
   * @param {Buffer} signature The digital signature
   * @param {string} certificate The sender's certificate (PEM)
   * @param {string} sourceDeviceId The sender's device ID
   * @returns {string|object} The decrypted message
   * @private
   */
  async _decryptAndVerifyMessage(encryptedData, signature, certificate, sourceDeviceId) {
    // First, get the sender's public key
    let publicKey;
    let trusted = false;
    
    if (certificate) {
      try {
        // Use node-forge to extract public key
        const cert = forge.pki.certificateFromPem(certificate);
        publicKey = forge.pki.publicKeyToPem(cert.publicKey);
        
        // Check if we trust this certificate
        if (this.trustedCertificates.has(sourceDeviceId)) {
          const storedCert = this.trustedCertificates.get(sourceDeviceId);
          trusted = storedCert.fingerprint === this._calculateCertificateFingerprint(certificate);
        }
        
        // Store the certificate if we don't have it yet
        if (!this.trustedCertificates.has(sourceDeviceId)) {
          // Store certificate data
          this.trustedCertificates.set(sourceDeviceId, {
            certificatePem: certificate,
            publicKey,
            fingerprint: this._calculateCertificateFingerprint(certificate)
          });
          
          // Update device record if we have one
          const device = this.knownDevices.get(sourceDeviceId);
          if (device) {
            device.publicKey = publicKey;
            device.certificate = certificate;
          }
          
          this.emit('certificateReceived', {
            deviceId: sourceDeviceId,
            fingerprint: this._calculateCertificateFingerprint(certificate),
            trusted: false,
            requiresManualVerification: true
          });
        }
      } catch (error) {
        throw new Error(`Invalid certificate: ${error.message}`);
      }
    } else if (this.trustedCertificates.has(sourceDeviceId)) {
      // Use stored public key
      publicKey = this.trustedCertificates.get(sourceDeviceId).publicKey;
      trusted = true;
    } else {
      throw new Error('No certificate provided and no trusted certificate found');
    }
    
    try {
      // Parse the encrypted message format
      // [encrypted key length (4 bytes)][encrypted key][IV (16 bytes)][encrypted message]
      const keyLength = encryptedData.readUInt32BE(0);
      const encryptedKey = encryptedData.subarray(4, 4 + keyLength);
      const iv = encryptedData.subarray(4 + keyLength, 4 + keyLength + 16);
      const encryptedMessage = encryptedData.subarray(4 + keyLength + 16);
      
      // Decrypt the symmetric key with our private key
      let symmetricKey;
      try {
        const decryptedKeyBuffer = crypto.privateDecrypt(
          {
            key: this.privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
          },
          encryptedKey
        );
        symmetricKey = decryptedKeyBuffer;
      } catch (error) {
        throw new Error(`Failed to decrypt symmetric key: ${error.message}`);
      }
      
      // Decrypt the message with the symmetric key
      const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, iv);
      const decryptedBuffer = Buffer.concat([
        decipher.update(encryptedMessage),
        decipher.final()
      ]);
      const decryptedText = decryptedBuffer.toString();
      
      // Verify signature if available
      let isValid = false;
      if (signature && publicKey) {
        try {
          const verify = crypto.createVerify('SHA256');
          verify.update(Buffer.from(decryptedText));
          isValid = verify.verify(publicKey, signature);
          
          if (!isValid && !this.trustAllCertificates) {
            this.emit('securityWarning', {
              type: 'signature_invalid',
              deviceId: sourceDeviceId,
              message: 'Message signature verification failed'
            });
          }
        } catch (error) {
          console.error("Signature verification error:", error);
          this.emit('securityWarning', {
            type: 'signature_verification_error',
            deviceId: sourceDeviceId,
            message: `Error verifying signature: ${error.message}`
          });
        }
      }
      
      // Try to parse as JSON
      try {
        return JSON.parse(decryptedText);
      } catch (e) {
        // Not JSON, return as string
        return decryptedText;
      }
    } catch (error) {
      throw new Error(`Message decryption failed: ${error.message}`);
    }
  }
  
  /**
   * Handle file receiving
   * @private
   */
  _handleReceiveFileRoute(req, res) {
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }
    
    const sourceDeviceId = req.headers['x-auth-device-id'];
    const fileName = decodeURIComponent(req.headers['x-file-name'] || 'unnamed_file');
    const expectedHash = req.headers['x-file-hash'];
    const usingPasswordMode = req.headers['x-password-mode'] === 'true';
    
    // Choose decryption method based on mode
    if (usingPasswordMode) {
      this._handlePasswordFileReceive(req, res, sourceDeviceId, fileName, expectedHash);
    } else {
      this._handleCertificateFileReceive(req, res, sourceDeviceId, fileName, expectedHash);
    }
  }
  
  /**
   * Handle file receiving using password-based encryption
   * @private
   */
  _handlePasswordFileReceive(req, res, sourceDeviceId, fileName, expectedHash) {
    const saltBase64 = req.headers['x-salt'];
    const ivBase64 = req.headers['x-iv'];
    
    if (!saltBase64 || !ivBase64) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Missing salt or IV' }));
      return;
    }
    
    const salt = Buffer.from(saltBase64, 'base64');
    const iv = Buffer.from(ivBase64, 'base64');
    
    // Derive the key from the password
    const key = crypto.pbkdf2Sync(this.password || 'default-password', salt, 10000, 32, 'sha256');
    
    // Create unique file name to prevent overwrites
    const saveDir = path.join(process.env.RECEIVED_FILES_DIR || '/app/received-files');
    
    // Ensure directory exists
    if (!fs.existsSync(saveDir)) {
      fs.mkdirSync(saveDir, { recursive: true });
    }
    
    const savePath = path.join(saveDir, `${Date.now()}_${fileName}`);
    const tempPath = `${savePath}.temp`;
    const fileStream = fs.createWriteStream(tempPath);
    const hash = crypto.createHash('sha256');
    
    // Create a decryption stream
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    req.pipe(decipher);
    
    decipher.on('data', (chunk) => {
      hash.update(chunk);
      fileStream.write(chunk);
    });
    
    decipher.on('end', async () => {
      fileStream.end();
      
      const calculatedHash = hash.digest('hex');
      
      // Verify file integrity
      if (expectedHash && calculatedHash !== expectedHash) {
        fs.unlinkSync(tempPath); // Delete corrupted file
        
        res.statusCode = 400;
        res.end(JSON.stringify({ 
          error: 'File integrity check failed',
          expectedHash,
          actualHash: calculatedHash
        }));
        return;
      }
      
      // Move from temp to final location
      fs.renameSync(tempPath, savePath);
      
      // Get device name if we have it
      const device = this.knownDevices.get(sourceDeviceId);
      const fromDeviceName = device ? device.deviceName : 'Unknown Device';
      
      // Emit file received event
      this.emit('fileReceived', {
        fromDeviceId: sourceDeviceId,
        fromDeviceName,
        filePath: savePath,
        fileName,
        fileHash: calculatedHash,
        signatureVerified: false, // No signature in password mode
        timestamp: Date.now()
      });
      
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ 
        status: 'success',
        filePath: savePath,
        fileName,
        fileHash: calculatedHash,
        timestamp: Date.now()
      }));
    });
    
    decipher.on('error', (error) => {
      fileStream.end();
      
      // Clean up partial file
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
      
      res.statusCode = 500;
      res.end(JSON.stringify({ error: `File decryption failed: ${error.message}` }));
      
      this.emit('error', new Error(`File decryption failed: ${error.message}`));
    });
    
    req.on('error', (error) => {
      decipher.end();
      fileStream.end();
      
      // Clean up partial file
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
      
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'File transfer failed' }));
      
      this.emit('error', new Error(`File transfer failed: ${error.message}`));
    });
  }
  
  /**
   * Handle file receiving with certificate-based encryption
   * @private
   */
  _handleCertificateFileReceive(req, res, sourceDeviceId, fileName, expectedHash) {
    const encryptedKeyB64 = req.headers['x-encrypted-key'];
    const signatureB64 = req.headers['x-signature'];
    const certificate = req.headers['x-certificate'] ? 
      Buffer.from(req.headers['x-certificate'], 'base64').toString() : null;

    // If we have the certificate, validate and store it
    if (certificate && !this.trustedCertificates.has(sourceDeviceId)) {
      try {
        // Extract public key from certificate using node-forge
        const cert = forge.pki.certificateFromPem(certificate);
        const publicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);
        
        // Store certificate data
        this.trustedCertificates.set(sourceDeviceId, {
          certificatePem: certificate,
          publicKey: publicKeyPem,
          fingerprint: this._calculateCertificateFingerprint(certificate)
        });
        
        // Update device record if we have one
        const device = this.knownDevices.get(sourceDeviceId);
        if (device) {
          device.publicKey = publicKeyPem;
          device.certificate = certificate;
        }
      } catch (error) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: `Invalid certificate: ${error.message}` }));
        return;
      }
    }
    
    // Decrypt the session key
    let sessionKey, iv;
    if (encryptedKeyB64) {
      try {
        const encryptedKey = Buffer.from(encryptedKeyB64, 'base64');
        const decryptedBuffer = crypto.privateDecrypt(
          {
            key: this.privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
          },
          encryptedKey
        );
        
        // The first 32 bytes are the key, the next 16 are the IV
        sessionKey = decryptedBuffer.subarray(0, 32);
        iv = decryptedBuffer.subarray(32, 48);
      } catch (error) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: `Failed to decrypt session key: ${error.message}` }));
        return;
      }
    } else {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Missing encrypted key' }));
      return;
    }
    
    // Create unique file name to prevent overwrites
    const saveDir = path.join(process.env.RECEIVED_FILES_DIR || '/app/received-files');
    
    // Ensure directory exists
    if (!fs.existsSync(saveDir)) {
      fs.mkdirSync(saveDir, { recursive: true });
    }
    
    const savePath = path.join(saveDir, `${Date.now()}_${fileName}`);
    const tempPath = `${savePath}.temp`;
    const fileStream = fs.createWriteStream(tempPath);
    const hash = crypto.createHash('sha256');
    
    // Create a decryption stream
    const decipher = crypto.createDecipheriv('aes-256-cbc', sessionKey, iv);
    
    req.pipe(decipher);
    
    decipher.on('data', (chunk) => {
      hash.update(chunk);
      fileStream.write(chunk);
    });
    
    decipher.on('end', async () => {
      fileStream.end();
      
      const calculatedHash = hash.digest('hex');
      
      // Verify file integrity
      if (expectedHash && calculatedHash !== expectedHash) {
        fs.unlinkSync(tempPath); // Delete corrupted file
        
        res.statusCode = 400;
        res.end(JSON.stringify({ 
          error: 'File integrity check failed',
          expectedHash,
          actualHash: calculatedHash
        }));
        return;
      }
      
      // Verify signature if available
      let verified = false;
      if (signatureB64) {
        try {
          const signature = Buffer.from(signatureB64, 'base64');
          let publicKey;
          
          if (this.trustedCertificates.has(sourceDeviceId)) {
            publicKey = crypto.createPublicKey(this.trustedCertificates.get(sourceDeviceId).publicKey);
          } else if (certificate) {
            const cert = forge.pki.certificateFromPem(certificate);
            publicKey = forge.pki.publicKeyToPem(cert.publicKey);
          }
          
          if (publicKey) {
            // Read the file for verification
            const fileBuffer = fs.readFileSync(tempPath);
            const fileHashForVerification = crypto.createHash('sha256').update(fileBuffer).digest();
            
            // Verify the signature
            const verify = crypto.createVerify('SHA256');
            verify.update(fileHashForVerification);
            verified = verify.verify(publicKey, signature);
          }
        } catch (error) {
          this.emit('securityWarning', {
            type: 'signature_verification_failed',
            deviceId: sourceDeviceId,
            message: `File signature verification failed: ${error.message}`
          });
        }
      }
      
      // Move from temp to final location
      fs.renameSync(tempPath, savePath);
      
      // Get device name if we have it
      const device = this.knownDevices.get(sourceDeviceId);
      const fromDeviceName = device ? device.deviceName : 'Unknown Device';
      
      // Emit file received event
      this.emit('fileReceived', {
        fromDeviceId: sourceDeviceId,
        fromDeviceName,
        filePath: savePath,
        fileName,
        fileHash: calculatedHash,
        signatureVerified: verified,
        timestamp: Date.now()
      });
      
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ 
        status: 'success',
        filePath: savePath,
        fileName,
        fileHash: calculatedHash,
        signatureVerified: verified,
        timestamp: Date.now()
      }));
    });
    
    decipher.on('error', (error) => {
      fileStream.end();
      
      // Clean up partial file
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
      
      res.statusCode = 500;
      res.end(JSON.stringify({ error: `File decryption failed: ${error.message}` }));
      
      this.emit('error', new Error(`File decryption failed: ${error.message}`));
    });
    
    req.on('error', (error) => {
      decipher.end();
      fileStream.end();
      
      // Clean up partial file
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
      
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'File transfer failed' }));
      
      this.emit('error', new Error(`File transfer failed: ${error.message}`));
    });
  }

  /**
   * Send a file to another device on the network
   * @param {string} deviceId The ID of the target device
   * @param {string} filePath Path to the file to send
   * @returns {Promise<Object>} Result of the transfer
   */
  async sendFile(deviceId, filePath) {
    const device = this.knownDevices.get(deviceId);
    if (!device) {
      throw new Error(`Device ${deviceId} not found`);
    }
    
    const fileName = path.basename(filePath);
    const fileSize = fs.statSync(filePath).size;
    const fileStream = fs.createReadStream(filePath);
    
    // Calculate file hash for integrity verification
    const fileHash = await this._calculateFileHash(filePath);
    
    // Create auth token
    const authToken = this._generateAuthToken(device);
    
    // Generate a symmetric key for file encryption (faster than asymmetric for large files)
    const sessionKey = crypto.randomBytes(32); // 256-bit AES key
    const iv = crypto.randomBytes(16); // AES initialization vector
    
    // Encrypt the session key with the recipient's public key
    let encryptedSessionKey;
    if (device.publicKey) {
      // Use the device's public key to encrypt the session key
      encryptedSessionKey = crypto.publicEncrypt(
        {
          key: device.publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        Buffer.concat([sessionKey, iv])
      );
    } else {
      throw new Error(`No public key available for device ${deviceId}`);
    }
    
    // Create digital signature for the file
    const fileSignature = await this._signFile(filePath);
    
    // Prepare request options
    const protocol = device.useSSL ? https : http;
    const options = {
      hostname: device.address,
      port: device.port,
      path: '/receive',
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': fileSize,
        'X-File-Name': encodeURIComponent(fileName),
        'X-Auth-Device-Id': this.deviceId,
        'X-Auth-Token': authToken,
        'X-File-Hash': fileHash,
        'X-Encrypted-Key': encryptedSessionKey.toString('base64'),
        'X-Signature': fileSignature.toString('base64'),
        'X-Certificate': this.certificatePem ? 
          Buffer.from(this.certificatePem).toString('base64') : ''
      },
      // For HTTPS connections
      rejectUnauthorized: !this.trustAllCertificates,
    };
    
    // If we have a CA certificate or trust the device's certificate
    if (this.trustedCertificates.has(deviceId)) {
      options.ca = this.trustedCertificates.get(deviceId).certificatePem;
    }
    
    // Create a file encryption pipeline
    const cipher = crypto.createCipheriv('aes-256-cbc', sessionKey, iv);
    
    // Make request
    return new Promise((resolve, reject) => {
      const req = protocol.request(options, (res) => {
        if (res.statusCode !== 200) {
          let errorData = '';
          res.on('data', (chunk) => {
            errorData += chunk;
          });
          res.on('end', () => {
            reject(new Error(`Failed with status code: ${res.statusCode}, ${errorData}`));
          });
          return;
        }
        
        let responseData = '';
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        
        res.on('end', () => {
          try {
            const response = JSON.parse(responseData);
            resolve(response);
          } catch (error) {
            reject(new Error('Invalid response format'));
          }
        });
      });
      
      req.on('error', reject);
      
      // Send the encrypted file data
      fileStream.pipe(cipher).pipe(req);
    });
  }
Z
  /**
   * Handle incoming HTTP/HTTPS requests
   * @private
   */
  _handleHttpRequest(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    
    // Add CORS headers for browser compatibility
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 
      'Content-Type, X-Auth-Device-Id, X-Auth-Token, X-File-Name, X-File-Hash, X-Encrypted-Key, X-Signature, X-Certificate');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      res.end();
      return;
    }
    
    // Validate authentication for all routes except discovery, certificate and key exchange
    if (path !== '/discovery' && path !== '/certificate' && path !== '/exchange-key') {
      try {
        this._validateRequest(req);
      } catch (error) {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Authentication failed', message: error.message }));
        return;
      }
    }
    
    // Route handling
    switch (path) {
      case '/discovery':
        this._handleDiscoveryRoute(req, res);
        break;
      case '/certificate':
        this._handleCertificateRoute(req, res);
        break;
      case '/message':
        this._handleMessageRoute(req, res);
        break;
      case '/receive':
        this._handleReceiveFileRoute(req, res);
        break;
      case '/exchange-key':
        this._handleKeyExchangeRoute(req, res);
        break;
      default:
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Not found' }));
    }
  }

  /**
   * Handle public key exchange for non-SSL devices
   * @private
   */
  _handleKeyExchangeRoute(req, res) {
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    let data = '';
    req.on('data', chunk => {
      data += chunk;
    });

    req.on('end', () => {
      try {
        const requestData = JSON.parse(data);
        const { deviceId, deviceName, publicKey, useSSL } = requestData;

        if (!deviceId || !publicKey) {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: 'Missing required fields' }));
          return;
        }

        // Store the sender's public key
        if (!this.trustedCertificates.has(deviceId)) {
          this.trustedCertificates.set(deviceId, {
            publicKey,
            deviceName,
            useSSL: useSSL === true
          });

          // Update device record if we have one
          const device = this.knownDevices.get(deviceId);
          if (device) {
            device.publicKey = publicKey;
            device.useSSL = useSSL;
          }

          console.log(`Stored public key for ${deviceName} (${deviceId})`);
        }

        // Send our public key in response
        const responseData = {
          deviceId: this.deviceId,
          deviceName: this.deviceName,
          publicKey: this.publicKeyPem,
          useSSL: this.useSSL,
          timestamp: Date.now()
        };

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(responseData));

      } catch (error) {
        console.error('Key exchange error:', error);
        res.statusCode = 400;
        res.end(JSON.stringify({ error: `Key exchange failed: ${error.message}` }));
      }
    });
  }

  /**
   * Start HTTP/HTTPS server
   * @private
   */
  async _startServer() {
    return new Promise((resolve, reject) => {
      try {
        // Create server based on SSL configuration
        if (this.useSSL && this.sslOptions) {
          this.server = https.createServer(this.sslOptions, this._handleHttpRequest);
        } else {
          this.server = http.createServer(this._handleHttpRequest);
        }
        
        // Start listening
        this.server.listen(this.port, () => {
          resolve();
        });
        
        this.server.on('error', (error) => {
          reject(error);
        });
      } catch (error) {
        reject(error);
      }
    });
  }
  
  /**
   * Setup UDP discovery service
   * @private
   */
  async _setupDiscovery() {
    return new Promise((resolve, reject) => {
      try {
        this.discoverySocket = dgram.createSocket('udp4');
        
        this.discoverySocket.on('error', (error) => {
          this.emit('error', error);
          reject(error);
        });
        
        this.discoverySocket.on('message', this._handleDiscoveryMessage);
        
        this.discoverySocket.bind(this.discoveryPort, () => {
          // Enable broadcast
          this.discoverySocket.setBroadcast(true);
          resolve();
        });
      } catch (error) {
        reject(error);
      }
    });
  }
  
  /**
   * Handle incoming HTTP/HTTPS requests
   * @private
   */
  _handleHttpRequest(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    
    // Add CORS headers for browser compatibility
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 
      'Content-Type, X-Auth-Device-Id, X-Auth-Token, X-File-Name, X-File-Hash, X-Encrypted-Key, X-Signature, X-Certificate');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      res.end();
      return;
    }
    
    // Validate authentication for all routes except discovery and certificate
    if (path !== '/discovery' && path !== '/certificate') {
      try {
        this._validateRequest(req);
      } catch (error) {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Authentication failed', message: error.message }));
        return;
      }
    }
    
    // Route handling
    switch (path) {
      case '/discovery':
        this._handleDiscoveryRoute(req, res);
        break;
      case '/certificate':
        this._handleCertificateRoute(req, res);
        break;
      case '/message':
        this._handleMessageRoute(req, res);
        break;
      case '/receive':
        this._handleReceiveFileRoute(req, res);
        break;
      default:
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Not found' }));
    }
  }
  
  /**
   * Handle certificate request route
   * @private
   */
  _handleCertificateRoute(req, res) {
    if (req.method !== 'GET') {
      res.statusCode = 405;
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }
    
    if (!this.certificatePem) {
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'Certificate not available' }));
      return;
    }
    
    const certificateResponse = {
      deviceId: this.deviceId,
      deviceName: this.deviceName,
      certificate: this.certificatePem,
      fingerprint: this._calculateCertificateFingerprint(this.certificatePem),
      timestamp: Date.now()
    };
    
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 200;
    res.end(JSON.stringify(certificateResponse));
  }
  
  /**
   * Handle UDP discovery messages
   * @private
   */
  _handleDiscoveryMessage(msg, rinfo) {
    try {
      const message = JSON.parse(msg.toString());
      
      // Ignore our own messages
      if (message.deviceId === this.deviceId) {
        return;
      }
      
      if (message.type === 'discovery') {
        // Add to known devices
        this.knownDevices.set(message.deviceId, {
          deviceId: message.deviceId,
          deviceName: message.deviceName,
          address: rinfo.address,
          port: message.port,
          useSSL: message.useSSL,
          certFingerprint: message.certFingerprint,
          lastSeen: Date.now()
        });
        
        // After discovery, fetch the device's certificate if needed
        if (message.useSSL && message.certFingerprint) {
          this._fetchDeviceCertificate(message.deviceId, rinfo.address, message.port);
        }
        
        this.emit('deviceDiscovered', {
          deviceId: message.deviceId,
          deviceName: message.deviceName,
          address: rinfo.address,
          port: message.port,
          useSSL: message.useSSL,
          certFingerprint: message.certFingerprint
        });
        
        // Send a response
        const response = JSON.stringify({
          type: 'discovery-response',
          deviceId: this.deviceId,
          deviceName: this.deviceName,
          port: this.port,
          useSSL: this.useSSL,
          certFingerprint: this.useSSL ? 
            this._calculateCertificateFingerprint(this.certificatePem) : null,
          timestamp: Date.now()
        });
        
        this.discoverySocket.send(
          response,
          0,
          response.length,
          this.discoveryPort,
          rinfo.address
        );
      } else if (message.type === 'discovery-response') {
        // Add to known devices
        this.knownDevices.set(message.deviceId, {
          deviceId: message.deviceId,
          deviceName: message.deviceName,
          address: rinfo.address,
          port: message.port,
          useSSL: message.useSSL,
          certFingerprint: message.certFingerprint,
          lastSeen: Date.now()
        });
        
        // After discovery, fetch the device's certificate if needed
        if (message.useSSL && message.certFingerprint) {
          this._fetchDeviceCertificate(message.deviceId, rinfo.address, message.port);
        }
        
        this.emit('deviceDiscovered', {
          deviceId: message.deviceId,
          deviceName: message.deviceName,
          address: rinfo.address,
          port: message.port,
          useSSL: message.useSSL,
          certFingerprint: message.certFingerprint
        });
      }
    } catch (error) {
      this.emit('error', new Error(`Invalid discovery message: ${error.message}`));
    }
  }
  
  /**
   * Validate authentication for incoming requests
   * @private
   */
  _validateRequest(req) {
    const deviceId = req.headers['x-auth-device-id'];
    const token = req.headers['x-auth-token'];
    
    if (!deviceId || !token) {
      throw new Error('Missing authentication headers');
    }
    
    // In a real implementation, we would verify the token here
    // This is a simple placeholder for demonstration
    if (this.password) {
      const expectedToken = this._generateAuthTokenForDevice(deviceId);
      if (token !== expectedToken) {
        throw new Error('Invalid token');
      }
    }
    
    return true;
  }
  
  /**
   * Generate unique device ID
   * @private
   */
  _generateDeviceId() {
    const macAddresses = [];
    
    // Collect MAC addresses from all interfaces
    const interfaces = os.networkInterfaces();
    Object.keys(interfaces).forEach(ifaceName => {
      interfaces[ifaceName].forEach(iface => {
        if (!iface.internal) {
          macAddresses.push(iface.mac);
        }
      });
    });
    
    // Use MAC addresses and device name to create a unique ID
    const idBase = macAddresses.join('') + this.deviceName;
    return crypto.createHash('sha256').update(idBase).digest('hex').substring(0, 16);
  }
  
  /**
   * Generate authentication token for a device
   * @private
   */
  _generateAuthToken(device) {
    // In a production implementation, this would be more sophisticated
    const base = `${this.deviceId}:${device.deviceId}:${this.password}:${Math.floor(Date.now() / 10000)}`;
    return crypto.createHash('sha256').update(base).digest('hex');
  }
  
  /**
   * Generate authentication token based on device ID
   * @private
   */
  _generateAuthTokenForDevice(deviceId) {
    // Simplified token generation for validation
    const base = `${deviceId}:${this.deviceId}:${this.password}:${Math.floor(Date.now() / 10000)}`;
    return crypto.createHash('sha256').update(base).digest('hex');
  }
  
  /**
   * Calculate file hash for integrity verification
   * @private
   */
  async _calculateFileHash(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', (data) => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }
  
  /**
   * Calculate a certificate fingerprint for verification
   * @param {string} certificatePem Certificate in PEM format
   * @returns {string} SHA-256 fingerprint of the certificate
   * @private
   */
  _calculateCertificateFingerprint(certificatePem) {
    return crypto.createHash('sha256')
      .update(certificatePem)
      .digest('hex');
  }

  /**
   * Send a message to another device
   * @param {string} deviceId The ID of the target device
   * @param {Object|string} message The message to send
   * @returns {Promise<Object>} Result of the message send
   */
  async sendMessage(deviceId, message) {
    const device = this.knownDevices.get(deviceId);
    if (!device) {
      throw new Error(`Device ${deviceId} not found`);
    }
    
    // Convert message to string if it's an object
    const messageData = typeof message === 'object' 
      ? JSON.stringify(message)
      : String(message);
    
    // Create auth token
    const authToken = this._generateAuthToken(device);
    
    // Generate a digital signature for the message if SSL is enabled
    let signature;
    try {
      signature = this._signMessage(messageData);
    } catch (error) {
      if (this.useSSL) {
        throw error; // Re-throw if SSL is enabled
      } else {
        // Continue without signature for non-SSL mode
        console.log(`Warning: Message not signed - ${error.message}`);
        signature = Buffer.from([]);
      }
    }
    
    let encryptedData;
    // Different approach based on if target uses SSL
    if (device.useSSL && device.publicKey) {
      // Encrypt with target's public key
      encryptedData = this._encryptWithHybridEncryption(messageData, device.publicKey);
    } else if (device.useSSL && !device.publicKey) {
      throw new Error(`No public key available for device ${deviceId}`);
    } else {
      // Simple encryption for non-SSL devices
      encryptedData = this._encryptWithSharedPassword(messageData);
    }
    
    // Prepare request options
    const protocol = device.useSSL ? https : http;
    const options = {
      hostname: device.address,
      port: device.port,
      path: '/message',
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': Buffer.byteLength(encryptedData),
        'X-Auth-Device-Id': this.deviceId,
        'X-Auth-Device-Name': this.deviceName,
        'X-Auth-Token': authToken,
        'X-Signature': signature.toString('base64'),
        'X-Use-SSL': String(this.useSSL)
      },
      // For HTTPS connections
      rejectUnauthorized: !this.trustAllCertificates,
    };
    
    // Add certificate info if available
    if (this.certificatePem) {
      options.headers['X-Certificate'] = Buffer.from(this.certificatePem).toString('base64');
    }
    
    // If we have a CA certificate or trust the device's certificate
    if (this.trustedCertificates.has(deviceId)) {
      options.ca = this.trustedCertificates.get(deviceId).certificatePem;
    }
    
    // Make request
    return new Promise((resolve, reject) => {
      const req = protocol.request(options, (res) => {
        if (res.statusCode !== 200) {
          let errorData = '';
          res.on('data', (chunk) => {
            errorData += chunk;
          });
          res.on('end', () => {
            reject(new Error(`Failed with status code: ${res.statusCode}, ${errorData}`));
          });
          return;
        }
        
        let responseData = '';
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        
        res.on('end', () => {
          try {
            const response = JSON.parse(responseData);
            resolve(response);
          } catch (error) {
            reject(new Error('Invalid response format'));
          }
        });
      });
      
      req.on('error', reject);
      req.write(encryptedData);
      req.end();
    });
  }

  /**
   * Encrypt a message with hybrid encryption (public key + symmetric)
   * @param {string} message The message to encrypt
   * @param {string} publicKeyPem The recipient's public key in PEM format
   * @returns {Buffer} The encrypted data
   * @private
   */
  _encryptWithHybridEncryption(message, publicKeyPem) {
    // Generate a random symmetric key
    const symmetricKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Encrypt the symmetric key with the recipient's public key
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
      },
      symmetricKey
    );
    
    // Encrypt the message with the symmetric key
    const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);
    const encryptedMessage = Buffer.concat([
      cipher.update(Buffer.from(message)),
      cipher.final()
    ]);
    
    // Format: [encrypted key length (4 bytes)][encrypted key][IV (16 bytes)][encrypted message]
    const keyLengthBuffer = Buffer.alloc(4);
    keyLengthBuffer.writeUInt32BE(encryptedKey.length);
    
    return Buffer.concat([keyLengthBuffer, encryptedKey, iv, encryptedMessage]);
  }

  /**
   * Encrypt message with shared password (for non-SSL mode)
   * @param {string} message The message to encrypt
   * @returns {Buffer} The encrypted data
   * @private
   */
  _encryptWithSharedPassword(message) {
    // Derive a key from the shared password
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(this.password || 'default-password', salt, 10000, 32, 'sha256');
    const iv = crypto.randomBytes(16);
    
    // Encrypt the message
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encryptedMessage = Buffer.concat([
      cipher.update(Buffer.from(message)),
      cipher.final()
    ]);
    
    // Format: [salt (16 bytes)][IV (16 bytes)][encrypted message]
    // No need for key length since we're using password derivation
    return Buffer.concat([salt, iv, encryptedMessage]);
  }
  
  /**
   * Handle incoming messages
   * @private
   */
  _handleMessageRoute(req, res) {
    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }
    
    const sourceDeviceId = req.headers['x-auth-device-id'];
    const sourceDeviceName = req.headers['x-auth-device-name'] || 'Unknown Device';
    const signatureBase64 = req.headers['x-signature'];
    const signature = signatureBase64 ? Buffer.from(signatureBase64, 'base64') : null;
    const certificateBase64 = req.headers['x-certificate'];
    const certificate = certificateBase64 ? Buffer.from(certificateBase64, 'base64').toString() : null;
    const senderUsesSSL = req.headers['x-use-ssl'] === 'true';
    
    let data = [];
    
    req.on('data', (chunk) => {
      data.push(chunk);
    });
    
    req.on('end', async () => {
      try {
        // Combine chunks
        const encryptedData = Buffer.concat(data);
        
        // Process message differently based on SSL usage
        let decryptedMessage;
        if (senderUsesSSL && this.useSSL) {
          // Both using SSL - use hybrid decryption
          decryptedMessage = await this._decryptAndVerifyMessage(encryptedData, signature, certificate, sourceDeviceId);
        } else {
          // At least one party isn't using SSL - use password-based decryption
          decryptedMessage = this._decryptWithSharedPassword(encryptedData);
        }
        
        // Emit message event
        this.emit('message', {
          fromDeviceId: sourceDeviceId,
          fromDeviceName: sourceDeviceName,
          message: decryptedMessage,
          timestamp: Date.now(),
          verified: !!signature
        });
        
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ 
          status: 'success',
          timestamp: Date.now()
        }));
      } catch (error) {
        console.error('Message processing error:', error.message);
        res.statusCode = 400;
        res.end(JSON.stringify({ error: 'Message processing failed', message: error.message }));
      }
    });
  }
  
  /**
   * Decrypt message with shared password (for non-SSL mode)
   * @param {Buffer} encryptedData The encrypted message
   * @returns {string|object} The decrypted message
   * @private
   */
  _decryptWithSharedPassword(encryptedData) {
    try {
      // Extract salt and IV
      const salt = encryptedData.subarray(0, 16);
      const iv = encryptedData.subarray(16, 32);
      const encryptedMessage = encryptedData.subarray(32);
      
      // Derive key from password
      const key = crypto.pbkdf2Sync(this.password || 'default-password', salt, 10000, 32, 'sha256');
      
      // Decrypt
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      const decryptedBuffer = Buffer.concat([
        decipher.update(encryptedMessage),
        decipher.final()
      ]);
      const decryptedText = decryptedBuffer.toString();
      
      // Try to parse as JSON
      try {
        return JSON.parse(decryptedText);
      } catch (e) {
        return decryptedText;
      }
    } catch (error) {
      throw new Error(`Failed to decrypt message: ${error.message}`);
    }
  }
}

module.exports = LocalSharing;