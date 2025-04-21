/**
 * Dịch vụ mã hóa cho ứng dụng chat đầu cuối
 * Cung cấp các chức năng mã hóa, giải mã và tạo cặp khóa
 */

// Tạo cặp khóa mới cho thuật toán cụ thể
export const generateKeyPair = async (algorithm) => {
  console.log(`Generating key pair for ${algorithm}`);
  
  const [algoBase, keySize] = algorithm.split('-');
  
  try {
    const subtle = window.crypto.subtle;
    let keyPair;
    
    if (algoBase === 'RSA') {
      // Tạo cặp khóa RSA
      const size = parseInt(keySize, 10);
      
      keyPair = await subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: size,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: { name: size <= 2048 ? 'SHA-256' : 'SHA-512' },
        },
        true,
        ['encrypt', 'decrypt']
      );
      
      // Xuất khóa thành định dạng JWK
      const publicKey = await subtle.exportKey('jwk', keyPair.publicKey);
      const privateKey = await subtle.exportKey('jwk', keyPair.privateKey);
      
      return {
        publicKey: JSON.stringify(publicKey),
        privateKey: JSON.stringify(privateKey)
      };
    }
    
    else if (algoBase === 'ECC') {
      // Tạo cặp khóa ECC
      const namedCurve = (() => {
        switch (keySize) {
          case '256': return 'P-256';
          case '384': return 'P-384';
          case '521': return 'P-521';
          default: return 'P-256';
        }
      })();
      
      keyPair = await subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve
        },
        true,
        ['deriveKey', 'deriveBits']
      );
      
      // Xuất khóa thành định dạng JWK
      const publicKey = await subtle.exportKey('jwk', keyPair.publicKey);
      const privateKey = await subtle.exportKey('jwk', keyPair.privateKey);
      
      return {
        publicKey: JSON.stringify(publicKey),
        privateKey: JSON.stringify(privateKey)
      };
    }
    
    else if (algoBase === 'DH') {
      // Mô phỏng cặp khóa DH (Web Crypto API không hỗ trợ trực tiếp DH)
      // Trong thực tế, bạn sẽ cần một thư viện DH đầy đủ
      
      const mockKeyPair = {
        publicKey: JSON.stringify({
          kty: "DH",
          key_ops: ["deriveKey", "deriveBits"],
          ext: true,
          size: keySize,
          x: btoa(Math.random().toString(36).substring(2, 15))
        }),
        privateKey: JSON.stringify({
          kty: "DH",
          key_ops: ["deriveKey", "deriveBits"],
          ext: false,
          size: keySize,
          d: btoa(Math.random().toString(36).substring(2, 15))
        }),
        parameters: JSON.stringify({
          prime: btoa(Math.random().toString(36).substring(2, 15)),
          generator: "2"
        })
      };
      
      return mockKeyPair;
    }
    
    throw new Error(`Unsupported algorithm: ${algorithm}`);
    
  } catch (error) {
    console.error(`Error generating ${algorithm} key pair:`, error);
    throw error;
  }
};

// Mã hóa tin nhắn
export const encryptMessage = async (plaintext, recipientPublicKey, algorithm, keyPair, parameters = null) => {
  console.log(`Encrypting message with ${algorithm}`);
  
  try {
    const subtle = window.crypto.subtle;
    const algoBase = algorithm.split('-')[0];
    
    if (algoBase === 'RSA') {
      // Mã hóa RSA
      const keySize = parseInt(algorithm.split('-')[1], 10);
      
      // Parse khóa công khai
      const publicKeyObj = JSON.parse(recipientPublicKey);
      
      // Import khóa công khai
      const importedKey = await subtle.importKey(
        'jwk',
        publicKeyObj,
        {
          name: 'RSA-OAEP',
          hash: { name: keySize <= 2048 ? 'SHA-256' : 'SHA-512' },
        },
        false,
        ['encrypt']
      );
      
      // Mã hóa dữ liệu
      const encodedData = new TextEncoder().encode(plaintext);
      const encryptedData = await subtle.encrypt(
        { name: 'RSA-OAEP' },
        importedKey,
        encodedData
      );
      
      // Chuyển đổi thành base64 để truyền qua JSON
      return btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
    }
    
    else if (algoBase === 'ECC') {
      // Mã hóa ECC (thực ra là ECDH + AES)
      
      // Parse khóa công khai
      const publicKeyObj = JSON.parse(recipientPublicKey);
      const privateKeyObj = JSON.parse(keyPair.privateKey);
      
      // Xác định đường cong
      const namedCurve = (() => {
        switch (algorithm.split('-')[1]) {
          case '256': return 'P-256';
          case '384': return 'P-384';
          case '521': return 'P-521';
          default: return 'P-256';
        }
      })();
      
      // Import khóa
      const importedPublicKey = await subtle.importKey(
        'jwk',
        publicKeyObj,
        { name: 'ECDH', namedCurve },
        false,
        []
      );
      
      const importedPrivateKey = await subtle.importKey(
        'jwk',
        privateKeyObj,
        { name: 'ECDH',
          namedCurve },
        false,
        ['deriveKey', 'deriveBits']
      );
      
      // Tạo bí mật chung
      const sharedSecret = await subtle.deriveBits(
        { name: 'ECDH', public: importedPublicKey },
        importedPrivateKey,
        256
      );
      
      // Tạo khóa AES từ bí mật chung
      const derivedKey = await subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );
      
      // Tạo iv (initialization vector)
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      // Mã hóa dữ liệu bằng AES-GCM
      const encodedData = new TextEncoder().encode(plaintext);
      const encryptedData = await subtle.encrypt(
        { name: 'AES-GCM', iv },
        derivedKey,
        encodedData
      );
      
      // Kết hợp iv và dữ liệu mã hóa
      const result = new Uint8Array(iv.length + encryptedData.byteLength);
      result.set(iv);
      result.set(new Uint8Array(encryptedData), iv.length);
      
      // Chuyển đổi thành base64
      return btoa(String.fromCharCode(...result));
    }
    
    else if (algoBase === 'DH') {
      // Mô phỏng mã hóa DH (trong thực tế cần sử dụng thư viện hoàn chỉnh)
      
      // Trong triển khai thực tế, bạn sẽ:
      // 1. Thực hiện trao đổi khóa DH để có bí mật chung
      // 2. Sử dụng bí mật chung để mã hóa với thuật toán đối xứng (như AES)
      
      // Mã hóa mô phỏng đơn giản
      const encodedText = plaintext
        .split('')
        .map(c => String.fromCharCode(c.charCodeAt(0) + 1))
        .join('');
        
      return btoa(encodedText + "__DH_ENCRYPTED__");
    }
    
    throw new Error(`Unsupported algorithm: ${algorithm}`);
    
  } catch (error) {
    console.error(`Error encrypting with ${algorithm}:`, error);
    throw error;
  }
};

// Giải mã tin nhắn
export const decryptMessage = async (encryptedContent, privateKey, algorithm, senderPublicKey = null) => {
  console.log(`Decrypting message with ${algorithm}`);
  console.log("privateKey", privateKey)
  console.log("senderPublicKey", senderPublicKey)
  
  try {
    const subtle = window.crypto.subtle;
    const algoBase = algorithm.split('-')[0];
    
    // Đảm bảo chúng ta đang làm việc với chuỗi base64
    let base64Content;
    if (typeof encryptedContent === 'string') {
      // Nếu đã là chuỗi, giả định đó là base64
      base64Content = encryptedContent;
    } else if (encryptedContent instanceof ArrayBuffer || encryptedContent instanceof Uint8Array) {
      // Nếu là dữ liệu nhị phân, chuyển đổi sang base64
      base64Content = btoa(String.fromCharCode(...new Uint8Array(encryptedContent)));
    } else {
      // Nếu là kiểu khác, chuyển đổi sang chuỗi
      base64Content = btoa(String(encryptedContent));
    }
    
    if (algoBase === 'RSA') {
      // Giải mã RSA
      const keySize = parseInt(algorithm.split('-')[1], 10);
      
      // Parse khóa riêng tư
      const privateKeyObj = JSON.parse(privateKey);
      
      // Import khóa riêng tư
      const importedKey = await subtle.importKey(
        'jwk',
        privateKeyObj,
        {
          name: 'RSA-OAEP',
          hash: { name: keySize <= 2048 ? 'SHA-256' : 'SHA-512' },
        },
        false,
        ['decrypt']
      );
      
      // Giải mã dữ liệu
      const encryptedBytes = Uint8Array.from(atob(base64Content), c => c.charCodeAt(0));
      const decryptedBuffer = await subtle.decrypt(
        { name: 'RSA-OAEP' },
        importedKey,
        encryptedBytes
      );
      
      // Chuyển đổi thành văn bản
      return new TextDecoder().decode(decryptedBuffer);
    }
    
    else if (algoBase === 'ECC') {
      // Giải mã ECC (ECDH + AES)
      
      // Parse khóa
      const privateKeyObj = JSON.parse(privateKey);
      const publicKeyObj = JSON.parse(senderPublicKey || '{}');
      
      if (!senderPublicKey) {
        throw new Error('Sender public key is required for ECC decryption');
      }
      
      // Xác định đường cong
      const namedCurve = (() => {
        switch (algorithm.split('-')[1]) {
          case '256': return 'P-256';
          case '384': return 'P-384';
          case '521': return 'P-521';
          default: return 'P-256';
        }
      })();
      
      // Import khóa
      const importedPublicKey = await subtle.importKey(
        'jwk',
        publicKeyObj,
        { name: 'ECDH', namedCurve },
        false,
        []
      );
      
      const importedPrivateKey = await subtle.importKey(
        'jwk',
        privateKeyObj,
        { name: 'ECDH', namedCurve },
        false,
        ['deriveKey', 'deriveBits']
      );
      
      // Tạo bí mật chung
      const sharedSecret = await subtle.deriveBits(
        { name: 'ECDH', public: importedPublicKey },
        importedPrivateKey,
        256
      );
      
      // Tạo khóa AES từ bí mật chung
      const derivedKey = await subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );
      
      // Chuyển đổi base64 thành mảng byte
      const encryptedBytes = Uint8Array.from(atob(base64Content), c => c.charCodeAt(0));
      
      // Tách iv và dữ liệu mã hóa
      const iv = encryptedBytes.slice(0, 12);
      const encryptedData = encryptedBytes.slice(12);
      
      // Giải mã dữ liệu
      const decryptedBuffer = await subtle.decrypt(
        { name: 'AES-GCM', iv },
        derivedKey,
        encryptedData
      );
      
      // Chuyển đổi thành văn bản
      return new TextDecoder().decode(decryptedBuffer);
    }
    
    else if (algoBase === 'DH') {
      // Mô phỏng giải mã DH 
      
      // Giải mã mô phỏng đơn giản (phù hợp với mã hóa mô phỏng ở trên)
      const encodedText = atob(base64Content).replace('__DH_ENCRYPTED__', '');
      
      return encodedText
        .split('')
        .map(c => String.fromCharCode(c.charCodeAt(0) - 1))
        .join('');
    }
    
    throw new Error(`Unsupported algorithm: ${algorithm}`);
    
  } catch (error) {
    console.error(`Error decrypting with ${algorithm}:`, error);
    throw error;
  }
};

// Tạo HMAC cho tin nhắn (cho backend)
export const generateHMAC = async (message, key) => {
  try {
    const subtle = window.crypto.subtle;
    
    // Import khóa HMAC
    const importedKey = await subtle.importKey(
      'raw',
      typeof key === 'string' ? new TextEncoder().encode(key) : key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    // Tạo chữ ký
    const signature = await subtle.sign(
      'HMAC',
      importedKey,
      typeof message === 'string' ? new TextEncoder().encode(message) : message
    );
    
    // Chuyển đổi thành base64
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
  } catch (error) {
    console.error('Error generating HMAC:', error);
    throw error;
  }
};

// Xác minh HMAC cho tin nhắn (cho backend)
export const verifyHMAC = async (message, signature, key) => {
  try {
    const subtle = window.crypto.subtle;
    
    // Import khóa HMAC
    const importedKey = await subtle.importKey(
      'raw',
      typeof key === 'string' ? new TextEncoder().encode(key) : key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    // Chuyển đổi chữ ký từ base64
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    
    // Xác minh chữ ký
    return await subtle.verify(
      'HMAC',
      importedKey,
      signatureBytes,
      typeof message === 'string' ? new TextEncoder().encode(message) : message
    );
  } catch (error) {
    console.error('Error verifying HMAC:', error);
    return false;
  }
};