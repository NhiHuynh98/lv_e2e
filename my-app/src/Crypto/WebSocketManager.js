// src/components/Crypto/WebSocketManager.js
import CryptoService from './CryptoService';
import KeyManager from './KeyManager';

class WebSocketManager {
  constructor() {
    this.socket = null;
    this.connected = false;
    this.messageHandlers = [];
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000; // Start with 1 second
    this.username = null;
    this.token = null;
  }
  
  connect(username, token) {
    this.username = username;
    this.token = token;
    
    return new Promise((resolve, reject) => {
      try {
        // Close existing connection if any
        if (this.socket) {
          this.socket.close();
        }
        
        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const wsUrl = `${protocol}://${window.location.host}/chat/ws/${username}?token=${token}`;
        
        this.socket = new WebSocket(wsUrl);
        
        this.socket.onopen = () => {
          console.log('WebSocket connected');
          this.connected = true;
          this.reconnectAttempts = 0;
          
          // Initialize PFS session
          this.initPFS();
          
          resolve();
        };
        
        this.socket.onmessage = (event) => {
          this.handleMessage(event.data);
        };
        
        this.socket.onclose = (event) => {
          console.log('WebSocket closed:', event.code, event.reason);
          this.connected = false;
          
          // Attempt to reconnect
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            
            console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
            
            setTimeout(() => {
              this.connect(this.username, this.token).catch(console.error);
            }, delay);
          }
        };
        
        this.socket.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(error);
        };
        
      } catch (error) {
        console.error('Error connecting to WebSocket:', error);
        reject(error);
      }
    });
  }
  
  disconnect() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
      this.connected = false;
    }
  }
  
  addMessageHandler(handler) {
    this.messageHandlers.push(handler);
    return () => {
      this.messageHandlers = this.messageHandlers.filter(h => h !== handler);
    };
  }
  
 // src/components/Crypto/WebSocketManager.js (continued)
 handleMessage(data) {
    try {
      const message = JSON.parse(data);
      
      // Handle special message types
      if (message.type === 'pfs_init_response') {
        // Store PFS session info
        KeyManager.storePFSSession(message.session_id, message.algorithm, message.public_key, message.expires_at);
      } else if (message.type === 'pfs_update') {
        // Update PFS session
        KeyManager.storePFSSession(message.session_id, message.algorithm, message.public_key, message.expires_at);
      } else if (message.type === 'key_exchange_success') {
        // Handle key exchange success
        console.log(`Shared key established with ${message.peer_id} using ${message.algorithm}`);
      } else if (message.type === 'error') {
        // Handle error
        console.error('WebSocket error message:', message.error);
      }
      
      // Notify all message handlers
      this.messageHandlers.forEach(handler => {
        try {
          handler(message);
        } catch (error) {
          console.error('Error in message handler:', error);
        }
      });
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  }
  
  sendMessage(recipient, content, algorithm = 'AES-GCM') {
    if (!this.connected || !this.socket) {
      throw new Error('WebSocket not connected');
    }
    
    // Get shared key for recipient
    const sharedKey = KeyManager.getSharedKey(recipient);
    
    if (!sharedKey) {
      // Establish shared key first
      this.establishSharedKey(recipient, algorithm).then(() => {
        // Retry sending message after key exchange
        this.sendMessage(recipient, content, algorithm);
      }).catch(error => {
        console.error('Error establishing shared key:', error);
        throw error;
      });
      
      return;
    }
    
    // Encrypt and sign message
    CryptoService.encryptMessage(content, sharedKey.key, 'AES').then(encryptedContent => {
      // Create HMAC signature
      return CryptoService.createHMAC(encryptedContent, sharedKey.keyData).then(signature => {
        // Send message
        const message = {
          type: 'message',
          recipient,
          content: encryptedContent,
          signature,
          algorithm,
          timestamp: new Date().toISOString()
        };
        
        this.socket.send(JSON.stringify(message));
      });
    }).catch(error => {
      console.error('Error sending message:', error);
      throw error;
    });
  }
  
  initPFS() {
    if (!this.connected || !this.socket) {
      throw new Error('WebSocket not connected');
    }
    
    // Request PFS initialization
    const message = {
      type: 'pfs_init',
      algorithm: 'ecc' // Can be 'rsa', 'ecc', 'dh'
    };
    
    this.socket.send(JSON.stringify(message));
  }
  
  rotatePFSKeys() {
    if (!this.connected || !this.socket) {
      throw new Error('WebSocket not connected');
    }
    
    // Request PFS key rotation
    const message = {
      type: 'pfs_rotation',
      algorithm: 'ecc' // Can be 'rsa', 'ecc', 'dh'
    };
    
    this.socket.send(JSON.stringify(message));
  }
  
  establishSharedKey(peerId, algorithm = 'ecdh') {
    if (!this.connected || !this.socket) {
      throw new Error('WebSocket not connected');
    }
    
    return new Promise((resolve, reject) => {
      // Create one-time handler for key exchange response
      const handleResponse = (message) => {
        if (message.type === 'key_exchange_success' && message.peer_id === peerId) {
          // Remove this handler
          this.messageHandlers = this.messageHandlers.filter(h => h !== handleResponse);
          resolve();
        } else if (message.type === 'error' && message.relates_to === 'key_exchange') {
          // Remove this handler
          this.messageHandlers = this.messageHandlers.filter(h => h !== handleResponse);
          reject(new Error(message.error));
        }
      };
      
      // Add temporary handler
      this.addMessageHandler(handleResponse);
      
      // Send key exchange request
      const message = {
        type: 'key_exchange',
        peer_id: peerId,
        algorithm
      };
      
      this.socket.send(JSON.stringify(message));
      
      // Set timeout for key exchange
      setTimeout(() => {
        // Remove handler if still present
        this.messageHandlers = this.messageHandlers.filter(h => h !== handleResponse);
        reject(new Error('Key exchange timeout'));
      }, 10000); // 10 seconds timeout
    });
  }
}

// Create a singleton instance
export default new WebSocketManager();