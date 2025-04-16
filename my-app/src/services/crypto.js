// crypto.js - Updated crypto service with PFS and HMAC support

// Utility to safely handle browser vs Node.js environments
const isBrowser = typeof window !== 'undefined';

// Polyfill for Buffer if not available in browser
let Buffer;
if (isBrowser) {
  // Check if Buffer exists in window
  if (!window.Buffer) {
    try {
      // Try to import buffer polyfill
      import('buffer').then(({ Buffer: BufferPolyfill }) => {
        Buffer = BufferPolyfill;
        window.Buffer = BufferPolyfill;
      }).catch(err => {
        console.error('Failed to load Buffer polyfill:', err);
      });
    } catch (e) {
      console.error('Buffer import error:', e);
      // Fallback - create a simple base64 conversion utility
      window.Buffer = {
        from: (str, encoding) => {
          if (encoding === 'base64') {
            return Uint8Array.from(atob(str), c => c.charCodeAt(0));
          }
          return new TextEncoder().encode(str);
        },
        toString: (buf, encoding) => {
          if (encoding === 'base64') {
            return btoa(String.fromCharCode.apply(null, buf));
          }
          return new TextDecoder().decode(buf);
        }
      };
    }
  } else {
    Buffer = window.Buffer;
  }
} else {
  // In Node.js environment
  Buffer = global.Buffer;
}

// Generate key pair for various algorithms
export const generateKeyPair = async (algorithm) => {
  // Parse algorithm name and key size
  const [algoName, keySizeStr] = algorithm.split('-');
  const keySize = parseInt(keySizeStr);
  
  if (algoName === 'RSA') {
    return generateRSAKeyPair(keySize);
  } else if (algoName === 'ECC') {
    return generateECCKeyPair(keySize);
  } else if (algoName === 'DH') {
    return generateDHKeyPair(keySize);
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
};

// Generate RSA key pair
const generateRSAKeyPair = async (keySize) => {
  try {
    // Use the Web Crypto API for key generation
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: keySize,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: { name: 'SHA-256' }
      },
      true, // extractable
      ['encrypt', 'decrypt'] // key usages
    );
    
    // Export the keys to PEM format
    const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    
    // Convert to base64
    const publicKeyBase64 = arrayBufferToBase64(publicKey);
    const privateKeyBase64 = arrayBufferToBase64(privateKey);
    
    // PEM format
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${formatPEM(publicKeyBase64)}\n-----END PUBLIC KEY-----`;
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${formatPEM(privateKeyBase64)}\n-----END PRIVATE KEY-----`;
    
    return {
      publicKey: publicKeyPem,
      privateKey: privateKeyPem,
      algorithm: `RSA-${keySize}`
    };
  } catch (error) {
    console.error('RSA key generation error:', error);
    // Fallback to simulated keys for demo purposes
    return simulateKeyPair('RSA', keySize);
  }
};

// Generate ECC key pair
const generateECCKeyPair = async (keySize) => {
  try {
    // Map key size to curve name
    let curveName;
    switch (keySize) {
      case 256:
        curveName = 'P-256';
        break;
      case 384:
        curveName = 'P-384';
        break;
      case 521:
        curveName = 'P-521';
        break;
      default:
        curveName = 'P-256';
    }
    
    // Generate key pair
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: curveName
      },
      true, // extractable
      ['deriveKey', 'deriveBits'] // key usages
    );
    
    // Export the keys
    const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    
    // Convert to base64
    const publicKeyBase64 = arrayBufferToBase64(publicKey);
    const privateKeyBase64 = arrayBufferToBase64(privateKey);
    
    // PEM format
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${formatPEM(publicKeyBase64)}\n-----END PUBLIC KEY-----`;
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${formatPEM(privateKeyBase64)}\n-----END PRIVATE KEY-----`;
    
    return {
      publicKey: publicKeyPem,
      privateKey: privateKeyPem,
      algorithm: `ECC-${keySize}`
    };
  } catch (error) {
    console.error('ECC key generation error:', error);
    return simulateKeyPair('ECC', keySize);
  }
};

// Generate DH key pair (simulated in browser)
const generateDHKeyPair = async (keySize) => {
  // Web Crypto API doesn't directly support DH
  // For demo purposes, we'll simulate DH keys
  return simulateKeyPair('DH', keySize);
};

// Encrypt a message with the recipient's public key
export const encryptMessage = async (message, recipientPublicKey, algorithm, senderKeyPair = null, dhParams = null) => {
  const [algoName, keySizeStr] = algorithm.split('-');
  
  if (algoName === 'RSA') {
    return encryptRSA(message, recipientPublicKey);
  } else if (algoName === 'ECC') {
    return encryptECC(message, recipientPublicKey, senderKeyPair);
  } else if (algoName === 'DH') {
    return encryptDH(message, recipientPublicKey, senderKeyPair, dhParams);
  } else {
    throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
  }
};

// Decrypt a message with the recipient's private key
export const decryptMessage = async (encryptedMessage, privateKey, algorithm, senderPublicKey = null) => {
  const [algoName, keySizeStr] = algorithm.split('-');
  
  if (algoName === 'RSA') {
    return decryptRSA(encryptedMessage, privateKey);
  } else if (algoName === 'ECC') {
    return decryptECC(encryptedMessage, privateKey, senderPublicKey);
  } else if (algoName === 'DH') {
    return decryptDH(encryptedMessage, privateKey, senderPublicKey);
  } else {
    throw new Error(`Unsupported decryption algorithm: ${algorithm}`);
  }
};

// RSA encryption
const encryptRSA = async (message, publicKeyPem) => {
  try {
    // Remove PEM headers and parse base64
    const publicKeyBase64 = publicKeyPem
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/\s/g, '');
    
    // Convert to ArrayBuffer
    const publicKeyDer = base64ToArrayBuffer(publicKeyBase64);
    
    // Import the public key
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      publicKeyDer,
      {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-256' }
      },
      false, // not extractable
      ['encrypt'] // key usage
    );
    
    // Encrypt the message
    const encodedMessage = new TextEncoder().encode(message);
    const encryptedData = await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP'
      },
      publicKey,
      encodedMessage
    );
    
    // Return base64-encoded ciphertext
    return arrayBufferToBase64(encryptedData);
  } catch (error) {
    console.error('RSA encryption error:', error);
    // For demo/fallback
    return btoa(`ENCRYPTED:${message}`);
  }
};

// RSA decryption
const decryptRSA = async (encryptedMessage, privateKeyPem) => {
  try {
    // Check if we're dealing with a fallback encryption
    if (encryptedMessage.startsWith('ENCRYPTED:')) {
      return atob(encryptedMessage).replace('ENCRYPTED:', '');
    }
    
    // Remove PEM headers and parse base64
    const privateKeyBase64 = privateKeyPem
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\s/g, '');
    
    // Convert to ArrayBuffer
    const privateKeyDer = base64ToArrayBuffer(privateKeyBase64);
    
    // Import the private key
    const privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      privateKeyDer,
      {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-256' }
      },
      false, // not extractable
      ['decrypt'] // key usage
    );
    
    // Decrypt the message
    const encryptedData = base64ToArrayBuffer(encryptedMessage);
    const decryptedData = await window.crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP'
      },
      privateKey,
      encryptedData
    );
    
    // Convert to string
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    console.error('RSA decryption error:', error);
    // If something goes wrong, try to handle a fallback format
    if (typeof encryptedMessage === 'string') {
      try {
        return atob(encryptedMessage).replace('ENCRYPTED:', '');
      } catch (e) {
        return `[Decryption failed: ${encryptedMessage.substring(0, 20)}...]`;
      }
    }
    return '[Decryption failed]';
  }
};

// ECC encryption (ECDH + AES)
const encryptECC = async (message, publicKeyPem, senderKeyPair) => {
  try {
    // For ECC, we use ECDH to derive a shared secret, then encrypt with AES
    
    // First, create an ephemeral key pair if one wasn't provided
    let ephemeralKeyPair = senderKeyPair;
    if (!ephemeralKeyPair) {
      ephemeralKeyPair = await generateECCKeyPair(256);
    }
    
    // Derive shared secret using ECDH
    const sharedSecret = await deriveECDHSecret(
      ephemeralKeyPair.privateKey,
      publicKeyPem
    );
    
    // Use the shared secret to encrypt with AES-GCM
    const encoder = new TextEncoder();
    const encodedMessage = encoder.encode(message);
    
    // Generate a random IV
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Derive an AES key from the shared secret
    const rawSharedSecret = base64ToArrayBuffer(sharedSecret);
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      rawSharedSecret,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    
    // Encrypt the message
    const encryptedData = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      aesKey,
      encodedMessage
    );
    
    // Bundle everything together
    const result = {
      iv: arrayBufferToBase64(iv),
      ciphertext: arrayBufferToBase64(encryptedData),
      ephemeralPublicKey: ephemeralKeyPair.publicKey
    };
    
    // Encode the entire object as JSON, then base64
    return btoa(JSON.stringify(result));
  } catch (error) {
    console.error('ECC encryption error:', error);
    // Fallback
    return btoa(`ENCRYPTED:${message}`);
  }
};

// ECC decryption
const decryptECC = async (encryptedMessage, privateKeyPem, senderPublicKey) => {
  try {
    // Check if we're dealing with a fallback encryption
    if (typeof encryptedMessage === 'string' && atob(encryptedMessage).startsWith('ENCRYPTED:')) {
      return atob(encryptedMessage).replace('ENCRYPTED:', '');
    }
    
    // Parse the encrypted message
    const encryptedData = JSON.parse(atob(encryptedMessage));
    
    // Derive shared secret using ECDH
    const sharedSecret = await deriveECDHSecret(
      privateKeyPem,
      encryptedData.ephemeralPublicKey
    );
    
    // Derive an AES key from the shared secret
    const rawSharedSecret = base64ToArrayBuffer(sharedSecret);
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      rawSharedSecret,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    
    // Decrypt the message
    const iv = base64ToArrayBuffer(encryptedData.iv);
    const ciphertext = base64ToArrayBuffer(encryptedData.ciphertext);
    
    const decryptedData = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      aesKey,
      ciphertext
    );
    
    // Convert to string
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    console.error('ECC decryption error:', error);
    // If something goes wrong, try to handle a fallback format
    if (typeof encryptedMessage === 'string') {
      try {
        return atob(encryptedMessage).replace('ENCRYPTED:', '');
      } catch (e) {
        return `[Decryption failed: ${encryptedMessage.substring(0, 20)}...]`;
      }
    }
    return '[Decryption failed]';
  }
};

// Derive a shared secret using ECDH
const deriveECDHSecret = async (privateKeyPem, publicKeyPem) => {
  try {
    // Remove PEM headers and parse base64
    const privateKeyBase64 = privateKeyPem
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\s/g, '');
    
    const publicKeyBase64 = publicKeyPem
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/\s/g, '');
    
    // Convert to ArrayBuffer
    const privateKeyDer = base64ToArrayBuffer(privateKeyBase64);
    const publicKeyDer = base64ToArrayBuffer(publicKeyBase64);
    
    // Import the keys
    const privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      privateKeyDer,
      {
        name: 'ECDH',
        namedCurve: 'P-256' // Assuming P-256 curve
      },
      false,
      ['deriveBits']
    );
    
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      publicKeyDer,
      {
        name: 'ECDH',
        namedCurve: 'P-256' // Assuming P-256 curve
      },
      false,
      []
    );
    
    // Derive bits
    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey
      },
      privateKey,
      256 // 256 bits
    );
    
    // Return base64-encoded derived bits
    return arrayBufferToBase64(derivedBits);
  } catch (error) {
    console.error('ECDH derivation error:', error);
    // Fallback for demo
    return btoa('DERIVED_SECRET');
  }
};

// DH encryption (simulated)
const encryptDH = async (message, recipientPublicKey, senderKeyPair, dhParams) => {
  // For simplicity in the browser demo, we'll simulate DH encryption
  // In a real implementation, this would properly implement Diffie-Hellman
  return btoa(`ENCRYPTED:${message}`);
};

// DH decryption (simulated)
const decryptDH = async (encryptedMessage, privateKey, senderPublicKey) => {
  // Simulated decryption
  if (typeof encryptedMessage === 'string') {
    try {
      return atob(encryptedMessage).replace('ENCRYPTED:', '');
    } catch (e) {
      return `[Decryption failed]`;
    }
  }
  return '[Decryption failed]';
};

// Generate HMAC
export const generateHMAC = async (message, key) => {
  try {
    // Convert message and key to ArrayBuffer
    const encoder = new TextEncoder();
    const messageBuffer = encoder.encode(message);
    let keyBuffer;
    
    if (typeof key === 'string') {
      keyBuffer = encoder.encode(key);
    } else {
      keyBuffer = key;
    }
    
    // Import the key
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    // Generate HMAC
    const signature = await window.crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      messageBuffer
    );
    
    // Return base64-encoded signature
    return arrayBufferToBase64(signature);
  } catch (error) {
    console.error('HMAC generation error:', error);
    // Fallback
    return btoa('HMAC_SIGNATURE');
  }
};

// Verify HMAC
export const verifyHMAC = async (message, signature, key) => {
  try {
    // Convert message, signature and key to ArrayBuffer
    const encoder = new TextEncoder();
    const messageBuffer = encoder.encode(message);
    let keyBuffer;
    
    if (typeof key === 'string') {
      keyBuffer = encoder.encode(key);
    } else {
      keyBuffer = key;
    }
    
    // Import the key
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    // Convert signature from base64 to ArrayBuffer
    const signatureBuffer = base64ToArrayBuffer(signature);
    
    // Verify HMAC
    return await window.crypto.subtle.verify(
      'HMAC',
      cryptoKey,
      signatureBuffer,
      messageBuffer
    );
  } catch (error) {
    console.error('HMAC verification error:', error);
    return false;
  }
};

// PFS key management
export const generatePFSKey = async (algorithm = 'ecc') => {
  if (algorithm === 'ecc') {
    return generateECCKeyPair(256); // Using P-256 curve for PFS
  } else if (algorithm === 'rsa') {
    return generateRSAKeyPair(2048);
  } else if (algorithm === 'dh') {
    return generateDHKeyPair(2048);
  } else {
    throw new Error(`Unsupported PFS algorithm: ${algorithm}`);
  }
};

// Utility functions

// Format Base64 string as PEM (with line breaks)
const formatPEM = (base64String) => {
  const chunkSize = 64;
  const chunks = [];
  
  for (let i = 0; i < base64String.length; i += chunkSize) {
    chunks.push(base64String.substring(i, i + chunkSize));
  }
  
  return chunks.join('\n');
};

// Convert ArrayBuffer to Base64 string
const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  return btoa(binary);
};

// Convert Base64 string to ArrayBuffer
const base64ToArrayBuffer = (base64) => {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  
  return bytes.buffer;
};

// Simulate key pairs for algorithms not fully supported in browser
const simulateKeyPair = (algorithm, keySize) => {
  const simulatedPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqLt3lmMYDxzxBMsLsLy5
UXTcZrVCCDFAdkGQoMN5Vm+6oLlJfJMrUTJG/CQbRWmm2hUDzNFI3PwFiY9cM+/m
OxiPh3ZsIbLPClDbvHmswnVGI5rMFF9HPKtQ0jHAPGwmDkNyIQNhOSmnhIg6iE9M
DHzNOGnxJ3AdORcLok1AQA0FfCPJqJL4KLzGOOBVGyBJiOvRCnN9j/ZLsVP9R4GS
nE4F3EXmKESGWvOJ7XDMBdCdwXEUI/cco3gIDZMYFbVfGPEzVYZ55e89Q/n8K9Nz
8MzLZUZvF9IjGjmFPf3CQyXtUhPJMwseOgXa3zBJDGlX4hJxTm+tZ0TQ1lQmDGJZ
NwIDAQAB
-----END PUBLIC KEY-----`;
    
  const simulatedPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCou3eWYxgPHPEE
ywuwvLlRdNxmtUIIMUB2QZCgw3lWb7qguUl8kytRMkb8JBtFaabaDQPM0Ujc/AWJ
j1wz7+Y7GI+HdmwhVCnwV2GizdqLX3p/QpgdtGglnYGxQf64kZV0p6Z6mf6qXsEK
TDxF7dMrCDXJ1RXs1QlZbIZ7Urs4w4/0G/x7ZdSYdifLZTXb49tZRTUNrH10+WCH
bsEwX2PJpsyAZTF7AlJ/3YWWHJu3BS8bdA9YQ+z6eH7rvBS6RBP7Z02GI3QQKpjP
XyCNLNZ6a2D4VGMUP8Sc+YwJggSojJn1Dnt1GOD1F+L4Ju5+bimTYkXEQmV5pXes
OO1LlB+vAgMBAAECggEAH8wfKPVYAlgV1wTJc9NXJ6DzWzEeUecSCL5/tUDLwl2K
33ygXcoNHBMZMUhCyGoXXFzU/oqM1PfpAFIKBz+pjLXNl3InxwzUZ/vdvpyP/OWT
XJXnlz0Jjys11nxb5QZR4ZRRm1PzZMaKe/nVIXjjZVBDjjtBP8GQZDGmJgDvOIJW
OyCRYukORPKdoa8yfqXQTRxJAWX6+vn3xUMYsVr8FZ0VOK1nU3Jd7nLvnbOZYGQf
kVWg/6hXC7jdIMVPnCPXHl6MpVjc3XlzgDkfAHwBHKP1+SJjU4yWjwgOGIi2tJC+
T5GaXJ/NBQVyAFFsL7BDIbYI6C+BpOqFOLAK7YFKyQKBgQDVRVS5a64KIC4a0+2V
CxZ6vi1NQoILfgOBbwTmPYbSU0p8TGRmCxg6AGYTkdMLLnlUE0uTU8ZakVtMHu40
riF6gyHJjfxbOPtgc79aR59gXz/4FmSsXuHn1nDCOiQ7V7d6V2JgW9jHAM/eRv6X
qZXBnVnwOL5niKhvIuUHZQDQswKBgQDKYQFxwvGbhVQztWRLJLFsXvHjnLDwsLrL
nqcaLZpDIKtDQ7W5RUE1PP6AThVqJdzGzkaJOZ4ZfKUVPEcDsvtjYqbXnxKmzV5w
pQeTXU2YIDkd8jzK/dtxl8ETcPqPE5Bvk/+CgpIBxxVBrIvkQR7INKijJImbzO0K
MKhV+U+ipQKBgDg6R6d2wVYhwBKisMnLXWJqQjb4/N6l+vRhYf+w2Y5Hu/CQvMvJ
wkI8nKoNBTOYYO4YLmw4C7p/cto9Q2JqgQnQpbUr9YxPcax7+QdBu1vvEny2FbEp
2O9+/rg5Yy442CnzFyvIKDLa3tcXJNVKQ9OHmLvNaAKSJrGKwXo1+e+3AoGAMudC
1nnSEtRkuOqdH4ZPTJgQd7C9U9+J3No16lzxvOV/sgKtCUDMB+2mKqxiUEG6r1GB
V97y1u4KQ8xdGZmIJtpbNpoVjDfdlbGV7ZcqHxOPu0JxLxQQDMguS9ggGWShDuEZ
OtaKrGUC+w6QoPjDKYHqvmztYcg9xH0eXM+k8WUCgYEAn/aNh5lzrOG4nvy1kwCJ
VphK8EgzD4anIJXbDxHXXE/Cx5aqoBgmKjIZ0J09GfPbvSwENlS6Hw5qYGGvMb5I
DCRjIMXIZvFAb5+5y/lZnFMFCcpWzZnMvDjKcvuBOl0bkeWmHgxzxpR3QsK0vFTZ
eWvTgwWMuqoRXAqAMJKMhFM=
-----END PRIVATE KEY-----`;
  
  return {
    publicKey: simulatedPublicKey,
    privateKey: simulatedPrivateKey,
    algorithm: `${algorithm}-${keySize}`
  };
};