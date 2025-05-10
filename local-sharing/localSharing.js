const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dgram = require('dgram');
const os = require('os');
const { EventEmitter } = require('events');
const { promisify } = require('util');

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
   * @param {string} [options.password] Network password for authentication
   * @param {boolean} [options.autoDiscover=true] Automatically discover devices on initialization
   */
  constructor(options) {
    super();
    
    if (!options || !options.deviceName) {
      throw new Error('Device name is required');
    }
    
    this.deviceName = options.deviceName;
    this.deviceId = this._generateDeviceId();
    this.port = options.port || 8765;
    this.useSSL = options.useSSL || false;
    this.password = options.password || '';
    this.autoDiscover = options.autoDiscover !== false;
    
    // Internal state
    this.server = null;
    this.discoverySocket = null;
    this.knownDevices = new Map();
    this.connectionState = 'disconnected';
    this.discoveryPort = 8766; // UDP discovery port
    
    // SSL options if enabled
    this.sslOptions = null;
    if (this.useSSL) {
      if (!options.certPath || !options.keyPath) {
        throw new Error('certPath and keyPath are required when useSSL is true');
      }
      
      this.sslOptions = {
        cert: fs.readFileSync(options.certPath),
        key: fs.readFileSync(options.keyPath)
      };
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
    });
    
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
        'X-File-Hash': fileHash
      }
    };
    
    // Make request
    return new Promise((resolve, reject) => {
      const req = protocol.request(options, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Failed with status code: ${res.statusCode}`));
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
      
      // Send the file data
      fileStream.pipe(req);
    });
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
    
    // Create auth token
    const authToken = this._generateAuthToken(device);
    
    // Convert message to string if it's an object
    const messageData = typeof message === 'object' 
      ? JSON.stringify(message)
      : String(message);
    
    // Prepare request options
    const protocol = device.useSSL ? https : http;
    const options = {
      hostname: device.address,
      port: device.port,
      path: '/message',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(messageData),
        'X-Auth-Device-Id': this.deviceId,
        'X-Auth-Token': authToken
      }
    };
    
    // Make request
    return new Promise((resolve, reject) => {
      const req = protocol.request(options, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`Failed with status code: ${res.statusCode}`));
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
      req.write(messageData);
      req.end();
    });
  }
  
  /**
   * Close all connections and shutdown
   * @returns {Promise<void>}
   */
  async close() {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          if (this.discoverySocket) {
            this.discoverySocket.close(() => {
              this.connectionState = 'disconnected';
              this.emit('closed');
              resolve();
            });
          } else {
            this.connectionState = 'disconnected';
            this.emit('closed');
            resolve();
          }
        });
      } else {
        if (this.discoverySocket) {
          this.discoverySocket.close(() => {
            this.connectionState = 'disconnected';
            this.emit('closed');
            resolve();
          });
        } else {
          this.connectionState = 'disconnected';
          this.emit('closed');
          resolve();
        }
      }
    });
  }
  
  // ===== Private methods =====
  
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
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Auth-Device-Id, X-Auth-Token, X-File-Name, X-File-Hash');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      res.end();
      return;
    }
    
    // Validate authentication for all routes except discovery
    if (path !== '/discovery') {
      try {
        this._validateRequest(req);
      } catch (error) {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Authentication failed' }));
        return;
      }
    }
    
    // Route handling
    switch (path) {
      case '/discovery':
        this._handleDiscoveryRoute(req, res);
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
          lastSeen: Date.now()
        });
        
        this.emit('deviceDiscovered', {
          deviceId: message.deviceId,
          deviceName: message.deviceName,
          address: rinfo.address,
          port: message.port
        });
        
        // Send a response
        const response = JSON.stringify({
          type: 'discovery-response',
          deviceId: this.deviceId,
          deviceName: this.deviceName,
          port: this.port,
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
          lastSeen: Date.now()
        });
        
        this.emit('deviceDiscovered', {
          deviceId: message.deviceId,
          deviceName: message.deviceName,
          address: rinfo.address,
          port: message.port
        });
      }
    } catch (error) {
      this.emit('error', new Error(`Invalid discovery message: ${error.message}`));
    }
  }
  
  /**
   * Handle HTTP discovery route
   * @private
   */
  _handleDiscoveryRoute(req, res) {
    if (req.method !== 'GET') {
      res.statusCode = 405;
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }
    
    const discoveryResponse = {
      deviceId: this.deviceId,
      deviceName: this.deviceName,
      timestamp: Date.now()
    };
    
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 200;
    res.end(JSON.stringify(discoveryResponse));
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
    let data = '';
    
    req.on('data', (chunk) => {
      data += chunk;
    });
    
    req.on('end', () => {
      try {
        const message = JSON.parse(data);
        
        // Emit message event
        this.emit('message', {
          fromDeviceId: sourceDeviceId,
          message,
          timestamp: Date.now()
        });
        
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ 
          status: 'success',
          timestamp: Date.now()
        }));
      } catch (error) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: 'Invalid message format' }));
      }
    });
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
    
    // Create unique file name to prevent overwrites
    const saveDir = path.join(os.tmpdir(), 'LocalSharing');
    
    // Ensure directory exists
    if (!fs.existsSync(saveDir)) {
      fs.mkdirSync(saveDir, { recursive: true });
    }
    
    const savePath = path.join(saveDir, `${Date.now()}_${fileName}`);
    const fileStream = fs.createWriteStream(savePath);
    const hash = crypto.createHash('sha256');
    
    req.on('data', (chunk) => {
      hash.update(chunk);
      fileStream.write(chunk);
    });
    
    req.on('end', () => {
      fileStream.end();
      
      const calculatedHash = hash.digest('hex');
      
      // Verify file integrity
      if (expectedHash && calculatedHash !== expectedHash) {
        fs.unlinkSync(savePath); // Delete corrupted file
        
        res.statusCode = 400;
        res.end(JSON.stringify({ 
          error: 'File integrity check failed',
          expectedHash,
          actualHash: calculatedHash
        }));
        return;
      }
      
      // Emit file received event
      this.emit('fileReceived', {
        fromDeviceId: sourceDeviceId,
        filePath: savePath,
        fileName,
        fileHash: calculatedHash,
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
    
    req.on('error', (error) => {
      fileStream.end();
      
      // Clean up partial file
      if (fs.existsSync(savePath)) {
        fs.unlinkSync(savePath);
      }
      
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'File transfer failed' }));
      
      this.emit('error', new Error(`File transfer failed: ${error.message}`));
    });
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
}

module.exports = LocalSharing;