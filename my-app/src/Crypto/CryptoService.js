// src/components/Crypto/CryptoService.js
import { arrayBufferToBase64, base64ToArrayBuffer } from '../utils/helpers';

class CryptoService {
  constructor() {
    this.performanceMetrics = {};
  }
  
  async generateKeyPair(algorithm = 'RSA', keySize = 2048) {
    const startTime = performance.now();
    
    let keyPair;
    if (algorithm === 'RSA') {
      keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: keySize,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );
    } else if (algorithm === 'ECC') {
      let namedCurve;
      switch (keySize) {
        case 256: namedCurve = 'P-256'; break;
        case 384: namedCurve = 'P-384'; break;
        case 521: namedCurve = 'P-521'; break;
        default: namedCurve = 'P-256';
      }
      
      keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve,
        },
        true,
        ['deriveKey', 'deriveBits']
      );
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    // Export public key
    const publicKeyData = await window.crypto.subtle.exportKey(
      'spki',
      keyPair.publicKey
    );
    
    // Export private key (in a real app, you'd secure this better)
    const privateKeyData = await window.crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey
    );
    
    const endTime = performance.now();
    this.recordPerformance(algorithm, keySize, 'generateKeyPair', endTime - startTime);
    
    return {
      publicKey: arrayBufferToBase64(publicKeyData),
      privateKey: arrayBufferToBase64(privateKeyData),
      algorithm,
      keySize
    };
  }
  
  async importPublicKey(publicKeyData, algorithm = 'RSA') {
    const startTime = performance.now();
    
    const binaryKey = base64ToArrayBuffer(publicKeyData);
    
    let publicKey;
    if (algorithm === 'RSA') {
      publicKey = await window.crypto.subtle.importKey(
        'spki',
        binaryKey,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256',
        },
        true,
        ['encrypt']
      );
    } else if (algorithm === 'ECC' || algorithm === 'ECDH') {
      publicKey = await window.crypto.subtle.importKey(
        'spki',
        binaryKey,
        {
          name: 'ECDH',
          namedCurve: 'P-256', // Assuming P-256 curve
        },
        true,
        []
      );
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    const endTime = performance.now();
    this.recordPerformance(algorithm, 0, 'importPublicKey', endTime - startTime);
    
    return publicKey;
  }
  
  async importPrivateKey(privateKeyData, algorithm = 'RSA') {
    const startTime = performance.now();
    
    const binaryKey = base64ToArrayBuffer(privateKeyData);
    
    let privateKey;
    if (algorithm === 'RSA') {
      privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        binaryKey,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256',
        },
        true,
        ['decrypt']
      );
    } else if (algorithm === 'ECC' || algorithm === 'ECDH') {
      privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        binaryKey,
        {
          name: 'ECDH',
          namedCurve: 'P-256', // Assuming P-256 curve
        },
        true,
        ['deriveKey', 'deriveBits']
      );
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    const endTime = performance.now();
    this.recordPerformance(algorithm, 0, 'importPrivateKey', endTime - startTime);
    
    return privateKey;
  }
  
  async encryptMessage(message, publicKey, algorithm = 'RSA') {
    const startTime = performance.now();
    
    let encryptedData;
    
    if (algorithm === 'RSA') {
      // For RSA, encrypt directly
      const encoder = new TextEncoder();
      const messageBuffer = encoder.encode(message);
      
      encryptedData = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKey,
        messageBuffer
      );
    } else if (algorithm === 'AES') {
      // For AES, encrypt with the provided key (which should be a symmetric key)
      const encoder = new TextEncoder();
      const messageBuffer = encoder.encode(message);
      
      // Generate IV
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      encryptedData = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        publicKey, // In this case, this is actually a symmetric key
        messageBuffer
      );
      
      // Prepend IV to the encrypted data
      const result = new Uint8Array(iv.length + encryptedData.byteLength);
      result.set(iv);
      result.set(new Uint8Array(encryptedData), iv.length);
      
      encryptedData = result.buffer;
    } else {
      throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
    }
    
    const endTime = performance.now();
    this.recordPerformance(algorithm, 0, 'encrypt', endTime - startTime, message.length);
    
    return arrayBufferToBase64(encryptedData);
  }
  
  async decryptMessage(encryptedMessage, privateKey, algorithm = 'RSA') {
    const startTime = performance.now();
    
    const encryptedBuffer = base64ToArrayBuffer(encryptedMessage);
    let decryptedBuffer;
    
    if (algorithm === 'RSA') {
      // For RSA, decrypt directly
      decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedBuffer
      );
    } else if (algorithm === 'AES') {
      // For AES, extract IV and decrypt
      const iv = new Uint8Array(encryptedBuffer, 0, 12);
      const ciphertext = new Uint8Array(encryptedBuffer, 12);
      
      decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        privateKey, // In this case, this is actually a symmetric key
        ciphertext
      );
    } else {
      throw new Error(`Unsupported decryption algorithm: ${algorithm}`);
    }
    
    // Convert ArrayBuffer to text
    const decoder = new TextDecoder();
    const plaintext = decoder.decode(decryptedBuffer);
    
    const endTime = performance.now();
    this.recordPerformance(algorithm, 0, 'decrypt', endTime - startTime, encryptedBuffer.byteLength);
    
    return plaintext;
  }
  
  async deriveSharedKey(privateKey, publicKey) {
    const startTime = performance.now();
    
    // Derive raw shared secret using ECDH
    const sharedSecret = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      256 // Length in bits
    );
    
    // Derive an AES key from the shared secret
    const derivedKey = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );
    
    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(16), // Salt should be random but same for both parties
        info: new Uint8Array(0)
      },
      derivedKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    
    const endTime = performance.now();
    this.recordPerformance('ECDH', 256, 'deriveSharedKey', endTime - startTime);
    
    // Export the key for storage
    const exportedKey = await window.crypto.subtle.exportKey('raw', aesKey);
    
    return {
      key: aesKey,
      keyData: arrayBufferToBase64(exportedKey)
    };
  }
  
  async createHMAC(message, key) {
    const startTime = performance.now();
    
    // Convert key to ArrayBuffer if needed
    let keyBuffer;
    if (typeof key === 'string') {
      keyBuffer = base64ToArrayBuffer(key);
    } else {
      keyBuffer = key;
    }
    
    // Convert message to ArrayBuffer if needed
    let messageBuffer;
    if (typeof message === 'string') {
      const encoder = new TextEncoder();
      messageBuffer = encoder.encode(message);
    } else {
      messageBuffer = message;
    }
    
    // Import key for HMAC
    const hmacKey = await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    // Calculate HMAC
    const signature = await window.crypto.subtle.sign(
      'HMAC',
      hmacKey,
      messageBuffer
    );
    
    const endTime = performance.now();
    this.recordPerformance('HMAC-SHA256', 256, 'sign', endTime - startTime, messageBuffer.byteLength);
    
    return arrayBufferToBase64(signature);
  }
  
  async verifyHMAC(message, signature, key) {
    const startTime = performance.now();
    
    // Convert key to ArrayBuffer if needed
    let keyBuffer;
    if (typeof key === 'string') {
      keyBuffer = base64ToArrayBuffer(key);
    } else {
      keyBuffer = key;
    }
    
    // Convert message to ArrayBuffer if needed
    let messageBuffer;
    if (typeof message === 'string') {
      const encoder = new TextEncoder();
      messageBuffer = encoder.encode(message);
    } else {
      messageBuffer = message;
    }
    
    // Convert signature to ArrayBuffer if needed
    let signatureBuffer;
    if (typeof signature === 'string') {
      signatureBuffer = base64ToArrayBuffer(signature);
    } else {
      signatureBuffer = signature;
    }
    
    // Import key for HMAC
    const hmacKey = await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    // Verify HMAC
    const isValid = await window.crypto.subtle.verify(
      'HMAC',
      hmacKey,
      signatureBuffer,
      messageBuffer
    );
    
    const endTime = performance.now();
    this.recordPerformance('HMAC-SHA256', 256, 'verify', endTime - startTime, messageBuffer.byteLength);
    
    return isValid;
  }
  
  recordPerformance(algorithm, keySize, operation, duration, dataSize = 0) {
    if (!this.performanceMetrics[algorithm]) {
      this.performanceMetrics[algorithm] = {};
    }
    
    if (!this.performanceMetrics[algorithm][keySize]) {
      this.performanceMetrics[algorithm][keySize] = {};
    }
    
    if (!this.performanceMetrics[algorithm][keySize][operation]) {
      this.performanceMetrics[algorithm][keySize][operation] = [];
    }
    
    this.performanceMetrics[algorithm][keySize][operation].push({
      duration,
      dataSize,
      timestamp: Date.now()
    });
  }
  
  getPerformanceMetrics() {
    return this.performanceMetrics;
  }
}

// Create a singleton instance
export default new CryptoService();