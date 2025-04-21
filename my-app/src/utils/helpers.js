// src/utils/helpers.js
export const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  
  export const arrayBufferToBase64 = (buffer) => {
    const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
    return window.btoa(binary);
  };
  
  export const base64ToArrayBuffer = (base64) => {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  };
  
  export const truncateString = (str, maxLength = 30) => {
    if (!str) return '';
    
    if (str.length <= maxLength) {
      return str;
    }
    
    return str.substring(0, maxLength - 3) + '...';
  };
  
  export const generateRandomId = () => {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  };
  
  export const debounce = (func, wait) => {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  };
  
  export const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };
  
  export const downloadBlob = (content, filename, contentType) => {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 100);
  };
  
  export const copyToClipboard = (text) => {
    return new Promise((resolve, reject) => {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text)
          .then(() => resolve(true))
          .catch(err => reject(err));
      } else {
        // Fallback for older browsers
        try {
          const textarea = document.createElement('textarea');
          textarea.value = text;
          textarea.style.position = 'fixed';
          document.body.appendChild(textarea);
          textarea.focus();
          textarea.select();
          
          const successful = document.execCommand('copy');
          document.body.removeChild(textarea);
          
          if (successful) {
            resolve(true);
          } else {
            reject(new Error('Unable to copy'));
          }
        } catch (err) {
          reject(err);
        }
      }
    });
  };
  
  export const calculateHash = async (data) => {
    // Convert string to ArrayBuffer if needed
    let buffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      buffer = encoder.encode(data);
    } else {
      buffer = data;
    }
    
    // Calculate SHA-256 hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    
    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };
  
  export const getRandomColor = (seed) => {
    // Simple hash function to generate a deterministic but random-looking color
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
      hash = seed.charCodeAt(i) + ((hash << 5) - hash);
    }
    
    const hue = hash % 360;
    return `hsl(${hue}, 70%, 80%)`;
  };