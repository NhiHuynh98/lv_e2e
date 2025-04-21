// SecurityManager.js - Handles all security features

const API_URL = process.env.REACT_APP_API_URL;
const API_WS = process.env.REACT_APP_WS_URL;

class SecurityManager {
  constructor() {
    this.sessions = {};
    this.keyExchanges = {};
    this.token = localStorage.getItem('token');
    this.username = localStorage.getItem('username');
    this.baseUrl = API_URL;
    this.wsConnection = null;
    this.messageHandlers = [];
    this.pfsCacheKey = 'pfs_sessions';

    // Load any cached PFS sessions from local storage
    try {
      const cachedSessions = localStorage.getItem(this.pfsCacheKey);
      if (cachedSessions) {
        this.sessions = JSON.parse(cachedSessions);
      }
    } catch (e) {
      console.error('Failed to load cached sessions:', e);
      localStorage.removeItem(this.pfsCacheKey);
    }
  }

  // Authentication methods
  async login(username, password) {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);

    try {
      const response = await fetch(`${this.baseUrl}/token`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Login failed');
      }

      const data = await response.json();
      this.token = data.access_token;
      this.username = username;
      
      // Store credentials
      localStorage.setItem('token', this.token);
      localStorage.setItem('username', username);
      
      return true;
    } catch (error) {
      console.error('Login error:', error);
      return false;
    }
  }

  async register(username, password) {
    try {
      const response = await fetch(`${this.baseUrl}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        throw new Error('Registration failed');
      }

      const data = await response.json();
      this.token = data.access_token;
      this.username = username;
      
      // Store credentials
      localStorage.setItem('token', this.token);
      localStorage.setItem('username', username);
      
      return true;
    } catch (error) {
      console.error('Registration error:', error);
      return false;
    }
  }

  logout() {
    this.token = null;
    this.username = null;
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    
    // Close WebSocket connection if open
    if (this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
      this.wsConnection.close();
    }
  }

  isLoggedIn() {
    return !!this.token;
  }

  // Perfect Forward Secrecy (PFS) methods
  async createPFSSession(sessionId, algorithm = 'ecc', keySize = null) {
    try {
      const response = await fetch(`${this.baseUrl}/pfs/create`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          session_id: sessionId,
          algorithm,
          key_size: keySize
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create PFS session');
      }

      const data = await response.json();
      
      // Store session information
      this.sessions[sessionId] = {
        id: data.session_id,
        algorithm: data.algorithm,
        publicKey: data.public_key,
        expiresAt: data.expires_at,
        createdAt: Date.now()
      };
      
      // Cache sessions in local storage
      this._cacheSessions();
      
      return data;
    } catch (error) {
      console.error('PFS session creation error:', error);
      throw error;
    }
  }

  async getPFSSessionInfo(sessionId) {
    try {
      const response = await fetch(`${this.baseUrl}/pfs/info/${sessionId}`, {
        headers: {
          'Authorization': `Bearer ${this.token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to get PFS session info');
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Get PFS session info error:', error);
      throw error;
    }
  }

  // Check if we need to rotate PFS keys
  shouldRotatePFSKeys(sessionId) {
    if (!this.sessions[sessionId]) {
      return true; // No session exists, so we need new keys
    }

    const session = this.sessions[sessionId];
    const now = Date.now();
    
    // If session is expired or about to expire (within 30 seconds)
    if (session.expiresAt * 1000 < now + 30000) {
      return true;
    }
    
    // If session is older than 5 minutes
    if (now - session.createdAt > 5 * 60 * 1000) {
      return true;
    }
    
    return false;
  }

  // Rotate PFS keys through WebSocket
  async rotatePFSKeys(websocket, algorithm = 'ecc') {
    try {
      websocket.send(JSON.stringify({
        type: 'pfs_rotation',
        algorithm
      }));
      
      // The response will be handled by the WebSocket message handler
      console.log('PFS key rotation requested');
    } catch (error) {
      console.error('PFS key rotation error:', error);
      throw error;
    }
  }

  // HMAC methods
  async createHMACSession(sessionId, keySize = 32) {
    try {
      const response = await fetch(`${this.baseUrl}/hmac/create`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          session_id: sessionId,
          key_size: keySize
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create HMAC session');
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('HMAC session creation error:', error);
      throw error;
    }
  }

  // Key Exchange methods
  async initiateKeyExchange(targetUsername, algorithm = 'ecc', keySize = null) {
    try {
      const response = await fetch(`${this.baseUrl}/key-exchange/initiate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          target: targetUsername,
          algorithm,
          key_size: keySize
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to initiate key exchange');
      }

      const data = await response.json();
      
      // Store key exchange information
      this.keyExchanges[data.exchange_id] = {
        id: data.exchange_id,
        algorithm: data.algorithm,
        publicKey: data.public_key,
        params: data.params,
        target: targetUsername,
        status: 'initiated',
        createdAt: Date.now()
      };
      
      return data;
    } catch (error) {
      console.error('Key exchange initiation error:', error);
      throw error;
    }
  }

  async completeKeyExchange(exchangeId, publicKey) {
    try {
      const response = await fetch(`${this.baseUrl}/key-exchange/complete`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          exchange_id: exchangeId,
          public_key: publicKey
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to complete key exchange');
      }

      const data = await response.json();
      
      // Update key exchange status
      if (this.keyExchanges[exchangeId]) {
        this.keyExchanges[exchangeId].status = 'completed';
      }
      
      return data;
    } catch (error) {
      console.error('Key exchange completion error:', error);
      throw error;
    }
  }

  // WebSocket methods
  setupWebSocket(onMessage) {
    // Close existing connection if any
    if (this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
      this.wsConnection.close();
    }

    // Create a new connection
    const wsUrl = `${API_WS}/${this.username}?token=${this.token}`;
    this.wsConnection = new WebSocket(wsUrl);
    
    this.wsConnection.onopen = () => {
      console.log('WebSocket connection established');
    };
    
    this.wsConnection.onmessage = (event) => {
      const message = JSON.parse(event.data);
      
      // Handle session info message
      if (message.type === 'session_info') {
        this._handleSessionInfo(message);
        return;
      }
      
      // Handle PFS update message
      if (message.type === 'pfs_update') {
        this._handlePFSUpdate(message);
        return;
      }
      
      // For normal messages, pass to callback
      if (onMessage) {
        onMessage(message);
      }
    };
    
    this.wsConnection.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    this.wsConnection.onclose = () => {
      console.log('WebSocket connection closed');
    };
    
    // Set up PFS key rotation timer
    this._setupKeyRotationTimer();
    
    return this.wsConnection;
  }

  sendMessage(recipient, content, algorithm = 'ecc') {
    if (!this.wsConnection || this.wsConnection.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket connection not open');
    }
    
    const message = {
      recipient,
      content,
      algorithm
    };
    
    this.wsConnection.send(JSON.stringify(message));
  }

  // Private methods
  _handleSessionInfo(message) {
    console.log('Session info received:', message);
    
    // Store PFS session information
    if (message.session_id && message.pfs) {
      this.sessions[message.session_id] = {
        id: message.session_id,
        algorithm: message.pfs.algorithm,
        publicKey: message.pfs.public_key,
        expiresAt: message.pfs.expires_at,
        createdAt: Date.now()
      };
      
      // Cache sessions
      this._cacheSessions();
    }
  }

  _handlePFSUpdate(message) {
    console.log('PFS update received:', message);
    
    // Extract session ID from existing sessions
    // This assumes session_id is prefixed with username
    const sessionPrefix = `${this.username}_`;
    let sessionId = null;
    
    for (const id in this.sessions) {
      if (id.startsWith(sessionPrefix)) {
        sessionId = id;
        break;
      }
    }
    
    if (sessionId) {
      this.sessions[sessionId] = {
        id: sessionId,
        algorithm: message.algorithm,
        publicKey: message.public_key,
        expiresAt: message.expires_at,
        createdAt: Date.now()
      };
      
      // Cache sessions
      this._cacheSessions();
    }
  }

  _setupKeyRotationTimer() {
    // Check every minute if keys need rotation
    setInterval(() => {
      // Find active session for current user
      const sessionPrefix = `${this.username}_`;
      let sessionId = null;
      
      for (const id in this.sessions) {
        if (id.startsWith(sessionPrefix)) {
          sessionId = id;
          break;
        }
      }
      
      if (sessionId && this.shouldRotatePFSKeys(sessionId) && 
          this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
        this.rotatePFSKeys(this.wsConnection);
      }
    }, 60 * 1000); // Check every minute
  }

  _cacheSessions() {
    try {
      localStorage.setItem(this.pfsCacheKey, JSON.stringify(this.sessions));
    } catch (e) {
      console.error('Failed to cache sessions:', e);
    }
  }
}

export default SecurityManager;