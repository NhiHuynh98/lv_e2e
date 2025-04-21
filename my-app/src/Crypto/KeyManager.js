// src/components/Crypto/KeyManager.js
import CryptoService from './CryptoService';

class KeyManager {
  constructor() {
    // Store key pairs by algorithm
    this.keyPairs = {};
    
    // Store PFS sessions
    this.pfsSessions = {};
    
    // Store peer public keys
    this.peerKeys = {};
    
    // Store shared keys by peer ID
    this.sharedKeys = {};
    
    // Initialize
    this.init();
  }
  
  async init() {
    // Load keys from localStorage if available
    try {
      const savedKeyPairs = localStorage.getItem('keyPairs');
      const savedPeerKeys = localStorage.getItem('peerKeys');
      const savedSharedKeys = localStorage.getItem('sharedKeys');
      
      if (savedKeyPairs) {
        this.keyPairs = JSON.parse(savedKeyPairs);
      } else {
        // Generate default key pairs
        await this.generateDefaultKeys();
      }
      
      if (savedPeerKeys) {
        this.peerKeys = JSON.parse(savedPeerKeys);
      }
      
      if (savedSharedKeys) {
        // SharedKeys includes actual CryptoKey objects which can't be serialized
        // We'll need to reimport them
        const parsedSharedKeys = JSON.parse(savedSharedKeys);
        
        for (const peerId in parsedSharedKeys) {
          for (const algorithm in parsedSharedKeys[peerId]) {
            const keyData = parsedSharedKeys[peerId][algorithm].keyData;
            
            try {
              // Import the key
              const keyBuffer = this.base64ToArrayBuffer(keyData);
              const key = await window.crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
              );
              
              // Store in sharedKeys
              if (!this.sharedKeys[peerId]) {
                this.sharedKeys[peerId] = {};
              }
              
              this.sharedKeys[peerId][algorithm] = {
                key,
                keyData,
                created_at: parsedSharedKeys[peerId][algorithm].created_at,
                expires_at: parsedSharedKeys[peerId][algorithm].expires_at
              };
            } catch (error) {
              console.error(`Error importing shared key for ${peerId}:`, error);
            }
          }
        }
      }
    } catch (error) {
      console.error('Error initializing KeyManager:', error);
    }
  }
  
  async generateDefaultKeys() {
    try {
      // Generate RSA key pair
      const rsaKeyPair = await CryptoService.generateKeyPair('RSA', 2048);
      this.keyPairs['RSA'] = rsaKeyPair;
      
      // Generate ECC key pair
      const eccKeyPair = await CryptoService.generateKeyPair('ECC', 256);
      this.keyPairs['ECC'] = eccKeyPair;
      
      // Save to localStorage
      this.saveKeyPairs();
    } catch (error) {
      console.error('Error generating default keys:', error);
    }
  }
  
  saveKeyPairs() {
    try {
      localStorage.setItem('keyPairs', JSON.stringify(this.keyPairs));
    } catch (error) {
      console.error('Error saving key pairs:', error);
    }
  }
  
  savePeerKeys() {
    try {
      localStorage.setItem('peerKeys', JSON.stringify(this.peerKeys));
    } catch (error) {
      console.error('Error saving peer keys:', error);
    }
  }
  
  saveSharedKeys() {
    try {
      // Create a serializable version of sharedKeys
      const serializableSharedKeys = {};
      
      for (const peerId in this.sharedKeys) {
        serializableSharedKeys[peerId] = {};
        
        for (const algorithm in this.sharedKeys[peerId]) {
          serializableSharedKeys[peerId][algorithm] = {
            keyData: this.sharedKeys[peerId][algorithm].keyData,
            created_at: this.sharedKeys[peerId][algorithm].created_at,
            expires_at: this.sharedKeys[peerId][algorithm].expires_at
          };
        }
      }
      
      localStorage.setItem('sharedKeys', JSON.stringify(serializableSharedKeys));
    } catch (error) {
      console.error('Error saving shared keys:', error);
    }
  }
  
  getKeyPair(algorithm) {
    return this.keyPairs[algorithm];
  }
  
  storePFSSession(sessionId, algorithm, publicKey, expiresAt) {
    this.pfsSessions[sessionId] = {
      algorithm,
      publicKey,
      expires_at: expiresAt,
      created_at: new Date().toISOString()
    };
  }
  
  storePeerKey(peerId, algorithm, publicKey, expiresAt) {
    if (!this.peerKeys[peerId]) {
      this.peerKeys[peerId] = {};
    }
    
    this.peerKeys[peerId][algorithm] = {
      public_key: publicKey,
      expires_at: expiresAt,
      created_at: new Date().toISOString()
    };
    
    this.savePeerKeys();
  }
  
  getPeerKey(peerId, algorithm) {
    if (!this.peerKeys[peerId] || !this.peerKeys[peerId][algorithm]) {
      return null;
    }
    
    const peerKey = this.peerKeys[peerId][algorithm];
    
    // Check if key has expired
    if (new Date(peerKey.expires_at) < new Date()) {
      delete this.peerKeys[peerId][algorithm];
      this.savePeerKeys();
      return null;
    }
    
    return peerKey.public_key;
  }
  
  async storeSharedKey(peerId, algorithm, key, keyData, expiresAt) {
    if (!this.sharedKeys[peerId]) {
      this.sharedKeys[peerId] = {};
    }
    
    this.sharedKeys[peerId][algorithm] = {
      key,
      keyData,
      created_at: new Date().toISOString(),
      expires_at: expiresAt
    };
    
    this.saveSharedKeys();
  }
  
  getSharedKey(peerId, algorithm = null) {
    if (!this.sharedKeys[peerId]) {
      return null;
    }
    
    if (algorithm) {
      // Return specific algorithm key
      if (!this.sharedKeys[peerId][algorithm]) {
        return null;
      }
      
      const sharedKey = this.sharedKeys[peerId][algorithm];
      
      // Check if key has expired
      if (new Date(sharedKey.expires_at) < new Date()) {
        delete this.sharedKeys[peerId][algorithm];
        this.saveSharedKeys();
        return null;
      }
      
      return sharedKey;
    } else {
      // Return first non-expired key found
      for (const algo in this.sharedKeys[peerId]) {
        const sharedKey = this.sharedKeys[peerId][algo];
        
        // Check if key has expired
        if (new Date(sharedKey.expires_at) < new Date()) {
          delete this.sharedKeys[peerId][algo];
          continue;
        }
        
        return sharedKey;
      }
      
      return null;
    }
  }
  
  // Helper method to convert base64 to ArrayBuffer
  base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// Create a singleton instance
export default new KeyManager();