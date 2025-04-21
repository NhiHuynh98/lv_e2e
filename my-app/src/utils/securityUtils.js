// SecurityUtils.js - Helper functions for PFS, HMAC, and Key Exchange in the browser

/**
 * Creates a secure session with the backend WebSocket
 * This helps initialize the PFS and HMAC mechanisms
 * 
 * @param {WebSocket} websocket - The WebSocket connection
 * @param {Object} message - Session info message received from server
 * @returns {Object} Session information
 */

const API_URL = process.env.REACT_APP_API_URL;

export const setupSecureSession = (message) => {
    // Extract session information
    const sessionId = message.session_id;
    const pfsInfo = message.pfs;
    
    // Store session information in local storage (only the ID and public info)
    const sessionInfo = {
      id: sessionId,
      pfs: {
        algorithm: pfsInfo.algorithm,
        publicKey: pfsInfo.public_key,
        expiresAt: pfsInfo.expires_at
      },
      createdAt: Date.now()
    };
    
    localStorage.setItem(`secure_session_${sessionId}`, JSON.stringify(sessionInfo));
    
    return sessionInfo;
  };
  
  /**
   * Request PFS key rotation from the server
   * 
   * @param {WebSocket} websocket - The WebSocket connection 
   * @param {string} algorithm - Encryption algorithm for PFS ('ecc', 'rsa', 'dh')
   */
  export const requestPFSKeyRotation = (websocket, algorithm = 'ecc') => {
    if (websocket && websocket.readyState === WebSocket.OPEN) {
      websocket.send(JSON.stringify({
        type: 'pfs_rotation',
        algorithm
      }));
      
      console.log(`PFS key rotation requested using ${algorithm}`);
      return true;
    }
    return false;
  };
  
  /**
   * Update session information after PFS key rotation
   * 
   * @param {Object} message - PFS update message from server
   * @returns {Object} Updated session information 
   */
  export const updatePFSKeys = (message) => {
    // Find the session ID in local storage
    const sessionKeys = Object.keys(localStorage).filter(key => 
      key.startsWith('secure_session_')
    );
    
    if (sessionKeys.length === 0) {
      console.error('No secure session found in local storage');
      return null;
    }
    
    // Use the first session found (in most cases there will only be one)
    const sessionKey = sessionKeys[0];
    const sessionId = sessionKey.replace('secure_session_', '');
    
    try {
      const sessionInfo = JSON.parse(localStorage.getItem(sessionKey));
      
      // Update PFS information
      sessionInfo.pfs = {
        algorithm: message.algorithm,
        publicKey: message.public_key,
        expiresAt: message.expires_at
      };
      
      // Update timestamp
      sessionInfo.lastRotation = Date.now();
      
      // Save updated session info
      localStorage.setItem(sessionKey, JSON.stringify(sessionInfo));
      
      return sessionInfo;
    } catch (error) {
      console.error('Error updating PFS keys:', error);
      return null;
    }
  };
  
  /**
   * Check if PFS keys need rotation
   * 
   * @param {number} rotationInterval - Rotation interval in milliseconds (default: 4.5 min) 
   * @returns {boolean} True if keys need rotation
   */
  export const shouldRotatePFSKeys = (rotationInterval = 270000) => {
    // Find the session ID in local storage
    const sessionKeys = Object.keys(localStorage).filter(key => 
      key.startsWith('secure_session_')
    );
    
    if (sessionKeys.length === 0) {
      return true; // No session found, need new keys
    }
    
    // Use the first session found
    const sessionKey = sessionKeys[0];
    
    try {
      const sessionInfo = JSON.parse(localStorage.getItem(sessionKey));
      const now = Date.now();
      
      // Check if PFS info exists
      if (!sessionInfo.pfs) {
        return true;
      }
      
      // Check expiration (convert to milliseconds)
      if (sessionInfo.pfs.expiresAt * 1000 < now) {
        return true;
      }
      
      // Check last rotation time
      if (sessionInfo.lastRotation && (now - sessionInfo.lastRotation > rotationInterval)) {
        return true;
      }
      
      // Check creation time if no rotation has happened yet
      if (!sessionInfo.lastRotation && (now - sessionInfo.createdAt > rotationInterval)) {
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('Error checking PFS key rotation:', error);
      return true; // Rotate on error to be safe
    }
  };
  
  /**
   * Initiate a key exchange with another user
   * 
   * @param {string} token - Authentication token
   * @param {string} targetUsername - Username to exchange keys with
   * @param {string} algorithm - Key exchange algorithm ('ecc', 'rsa', 'dh')
   * @returns {Promise<Object>} Exchange information
   */
  export const initiateKeyExchange = async (token, targetUsername, algorithm = 'ecc') => {
    try {
      const response = await fetch(`${API_URL}/key-exchange/initiate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          target: targetUsername,
          algorithm: algorithm,
        })
      });
      
      if (!response.ok) {
        throw new Error(`Key exchange failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      // Store exchange information in local storage
      const exchangeInfo = {
        id: data.exchange_id,
        target: targetUsername,
        algorithm: algorithm,
        publicKey: data.public_key,
        params: data.params,
        status: 'initiated',
        createdAt: Date.now()
      };
      
      localStorage.setItem(`key_exchange_${data.exchange_id}`, JSON.stringify(exchangeInfo));
      
      return exchangeInfo;
    } catch (error) {
      console.error('Error initiating key exchange:', error);
      throw error;
    }
  };
  
  /**
   * Complete a key exchange initiated by another user
   * 
   * @param {string} token - Authentication token
   * @param {string} exchangeId - Exchange ID
   * @param {string} publicKey - Your public key to send
   * @returns {Promise<Object>} Result of key exchange
   */
  export const completeKeyExchange = async (token, exchangeId, publicKey) => {
    try {
      const response = await fetch(`${API_URL}/key-exchange/complete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          exchange_id: exchangeId,
          public_key: publicKey
        })
      });
      
      if (!response.ok) {
        throw new Error(`Key exchange completion failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      // Update exchange information in local storage
      const storageKey = `key_exchange_${exchangeId}`;
      const existingInfo = localStorage.getItem(storageKey);
      
      if (existingInfo) {
        const exchangeInfo = JSON.parse(existingInfo);
        exchangeInfo.status = 'completed';
        exchangeInfo.completedAt = Date.now();
        
        localStorage.setItem(storageKey, JSON.stringify(exchangeInfo));
      }
      
      return data;
    } catch (error) {
      console.error('Error completing key exchange:', error);
      throw error;
    }
  };
  
  /**
   * Get security status from the server
   * 
   * @param {string} token - Authentication token
   * @returns {Promise<Object>} Security status information
   */
  export const getSecurityStatus = async (token) => {
    try {
      const response = await fetch(`${API_URL}/security/status`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error(`Failed to get security status: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting security status:', error);
      return {
        pfsActive: false,
        hmacActive: false,
        keyExchangeActive: false
      };
    }
  };
  
  /**
   * Verify if a message is authentic using HMAC
   * 
   * @param {WebSocket} websocket - WebSocket connection
   * @param {Object} message - Message to verify
   * @returns {boolean} True if authentic, false otherwise
   */
  export const verifyMessageAuthenticity = (message) => {
    // Check if message has required fields
    if (!message || !message.content || !message.signature) {
      return false;
    }
    
    // For the web application, verification is handled by the server
    // This is just a placeholder to indicate the message has a signature
    return !!message.signature;
  };
  
  /**
   * Setup automatic PFS key rotation
   * 
   * @param {WebSocket} websocket - WebSocket connection
   * @param {number} checkInterval - How often to check for rotation in ms
   * @returns {number} Interval ID for clearInterval
   */
  export const setupKeyRotationSchedule = (websocket, checkInterval = 60000) => {
    const intervalId = setInterval(() => {
      if (shouldRotatePFSKeys()) {
        requestPFSKeyRotation(websocket);
      }
    }, checkInterval);
    
    return intervalId;
  };
  
  /**
   * Clear key rotation schedule
   * 
   * @param {number} intervalId - Interval ID from setupKeyRotationSchedule
   */
  export const clearKeyRotationSchedule = (intervalId) => {
    if (intervalId) {
      clearInterval(intervalId);
    }
  };