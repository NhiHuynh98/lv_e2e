"""
hmac_manager.py - HMAC Implementation for Message Authentication

This module implements Hash-based Message Authentication Code (HMAC) for
verifying message integrity and authenticity in an end-to-end encryption system.
"""

import hmac
import hashlib
import os
import base64
import time
import secrets
from typing import Dict, Optional, Tuple, Union, Any

class HMACManager:
    """
    Enhanced HMAC implementation with key rotation and constant-time verification
    to prevent timing attacks.
    """
    
    def __init__(self, default_hash_algorithm='sha256'):
        """
        Initialize HMAC Manager
        
        Args:
            default_hash_algorithm: Default hash algorithm to use ('sha256', 'sha384', 'sha512')
        """
        self.default_hash_algorithm = default_hash_algorithm
        
        # Verify hash algorithm is supported
        self._get_hash_algorithm(default_hash_algorithm)
        
        # Store MAC keys for different channels or sessions
        self.mac_keys = {}
    
    def _get_hash_algorithm(self, algorithm: str):
        """Get hash algorithm by name"""
        algorithm = algorithm.lower()
        if algorithm == 'sha256':
            return hashlib.sha256
        elif algorithm == 'sha384':
            return hashlib.sha384
        elif algorithm == 'sha512':
            return hashlib.sha512
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    def generate_mac_key(self, session_id: str, size: int = 32) -> bytes:
        """
        Generate a new MAC key for a session
        
        Args:
            session_id: Identifier for the session
            size: Size of the key in bytes (32 = 256 bits)
            
        Returns:
            The generated key
        """
        # Generate a cryptographically secure key
        key = secrets.token_bytes(size)
        
        # Store the key
        self.mac_keys[session_id] = key
        
        return key
    
    def get_mac_key(self, session_id: str) -> Optional[bytes]:
        """Get the MAC key for a session"""
        return self.mac_keys.get(session_id)
    
    def set_mac_key(self, session_id: str, key: bytes):
        """Set a MAC key for a session"""
        if len(key) < 16:  # Minimum 128 bits
            raise ValueError("MAC key is too short (minimum 16 bytes / 128 bits)")
        
        self.mac_keys[session_id] = key
    
    def generate_hmac(self, 
                     message: bytes, 
                     key: Optional[bytes] = None, 
                     session_id: Optional[str] = None,
                     hash_algorithm: Optional[str] = None) -> bytes:
        """
        Generate HMAC for message authentication
        
        Args:
            message: Message to authenticate
            key: HMAC key (if not provided, uses session key)
            session_id: Session identifier (required if key not provided)
            hash_algorithm: Hash algorithm to use
            
        Returns:
            HMAC digest
        """
        # Get key to use
        if key is None:
            if session_id is None:
                raise ValueError("Either key or session_id must be provided")
            
            key = self.get_mac_key(session_id)
            if key is None:
                raise ValueError(f"No MAC key found for session {session_id}")
        
        # Get hash algorithm
        hash_algo = self._get_hash_algorithm(hash_algorithm or self.default_hash_algorithm)
        
        # Generate HMAC
        h = hmac.new(key, message, hash_algo)
        return h.digest()
    
    def generate_hmac_hex(self, 
                         message: bytes, 
                         key: Optional[bytes] = None, 
                         session_id: Optional[str] = None,
                         hash_algorithm: Optional[str] = None) -> str:
        """Generate HMAC and return as hex string"""
        hmac_digest = self.generate_hmac(message, key, session_id, hash_algorithm)
        return hmac_digest.hex()
    
    def generate_hmac_b64(self, 
                         message: bytes, 
                         key: Optional[bytes] = None, 
                         session_id: Optional[str] = None,
                         hash_algorithm: Optional[str] = None) -> str:
        """Generate HMAC and return as base64 string"""
        hmac_digest = self.generate_hmac(message, key, session_id, hash_algorithm)
        return base64.b64encode(hmac_digest).decode('ascii')
    
    def get_hmac_session(self, session_id):
        """
        Lấy thông tin phiên HMAC dựa trên session_id
        
        Args:
            session_id (str): ID của phiên
                
        Returns:
            dict: Thông tin phiên HMAC hoặc None nếu không tìm thấy
        """
        # Kiểm tra nếu session_id tồn tại trong mac_keys
        key = self.mac_keys.get(session_id)
        if key:
            return {"key": key}  # Return a dict with the key
        return None
    def verify_hmac(self, 
                   message: bytes, 
                   signature: bytes, 
                   key: Optional[bytes] = None, 
                   session_id: Optional[str] = None,
                   hash_algorithm: Optional[str] = None) -> bool:
        """
        Verify HMAC signature using constant-time comparison to prevent timing attacks
        
        Args:
            message: Original message
            signature: HMAC signature to verify
            key: HMAC key (if not provided, uses session key)
            session_id: Session identifier (required if key not provided)
            hash_algorithm: Hash algorithm to use
            
        Returns:
            True if signature is valid, False otherwise
        """
        # Get key to use
        if key is None:
            if session_id is None:
                raise ValueError("Either key or session_id must be provided")
            
            key = self.get_mac_key(session_id)
            if key is None:
                return False  # No key for this session
        
        # Get hash algorithm
        hash_algo = self._get_hash_algorithm(hash_algorithm or self.default_hash_algorithm)
        
        # Compute HMAC
        h = hmac.new(key, message, hash_algo)
        
        # Use constant-time comparison to prevent timing attacks
        try:
            return hmac.compare_digest(h.digest(), signature)
        except Exception:
            return False
    
    def verify_hmac_hex(self, 
                       message: bytes, 
                       signature_hex: str, 
                       key: Optional[bytes] = None, 
                       session_id: Optional[str] = None,
                       hash_algorithm: Optional[str] = None) -> bool:
        """Verify HMAC signature provided as hex string"""
        try:
            signature = bytes.fromhex(signature_hex)
            return self.verify_hmac(message, signature, key, session_id, hash_algorithm)
        except Exception:
            return False
    
    def verify_hmac_b64(self, 
                       message: bytes, 
                       signature_b64: str, 
                       key: Optional[bytes] = None, 
                       session_id: Optional[str] = None,
                       hash_algorithm: Optional[str] = None) -> bool:
        """Verify HMAC signature provided as base64 string"""
        try:
            signature = base64.b64decode(signature_b64)
            return self.verify_hmac(message, signature, key, session_id, hash_algorithm)
        except Exception:
            return False
    
    def authenticate_and_verify_message(self, 
                                       encrypted_message: bytes, 
                                       hmac_signature: bytes,
                                       key: Optional[bytes] = None, 
                                       session_id: Optional[str] = None,
                                       hash_algorithm: Optional[str] = None) -> bool:
        """
        Authenticate and verify an encrypted message
        
        Args:
            encrypted_message: Encrypted message to verify
            hmac_signature: HMAC signature to verify
            key: HMAC key (if not provided, uses session key)
            session_id: Session identifier (required if key not provided)
            hash_algorithm: Hash algorithm to use
            
        Returns:
            True if signature is valid, False otherwise
        """
        return self.verify_hmac(encrypted_message, hmac_signature, key, session_id, hash_algorithm)
    
    def cleanup(self):
        """Clean up resources"""
        # Securely clear MAC keys from memory
        for session_id in list(self.mac_keys.keys()):
            self.mac_keys[session_id] = b'\x00' * len(self.mac_keys[session_id])
            del self.mac_keys[session_id]

class SecureMessagePacker:
    """
    Utility for packing messages with HMAC for authentication and integrity protection
    """
    
    def __init__(self, hmac_manager: HMACManager):
        """
        Initialize Message Packer
        
        Args:
            hmac_manager: HMAC Manager instance
        """
        self.hmac_manager = hmac_manager
    
    def pack_message(self, 
                    message: bytes, 
                    key: Optional[bytes] = None, 
                    session_id: Optional[str] = None,
                    hash_algorithm: Optional[str] = None) -> Dict[str, str]:
        """
        Pack a message with HMAC for authentication
        
        Args:
            message: Message to pack
            key: HMAC key (if not provided, uses session key)
            session_id: Session identifier (required if key not provided)
            hash_algorithm: Hash algorithm to use
            
        Returns:
            Dictionary with message and signature
        """
        # Convert message to bytes if needed
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Generate HMAC
        signature = self.hmac_manager.generate_hmac(message, key, session_id, hash_algorithm)
        
        # Encode message and signature
        message_b64 = base64.b64encode(message).decode('ascii')
        signature_b64 = base64.b64encode(signature).decode('ascii')
        
        return {
            "message": message_b64,
            "signature": signature_b64,
            "timestamp": int(time.time())
        }
    
    def unpack_message(self, 
                     packed_message: Dict[str, str], 
                     key: Optional[bytes] = None, 
                     session_id: Optional[str] = None,
                     hash_algorithm: Optional[str] = None) -> Optional[bytes]:
        """
        Unpack and verify a message with HMAC authentication
        
        Args:
            packed_message: Packed message with signature
            key: HMAC key (if not provided, uses session key)
            session_id: Session identifier (required if key not provided)
            hash_algorithm: Hash algorithm to use
            
        Returns:
            Original message if signature is valid, None otherwise
        """
        try:
            # Extract message and signature
            message_b64 = packed_message.get("message")
            signature_b64 = packed_message.get("signature")
            
            if not message_b64 or not signature_b64:
                return None
            
            # Decode message and signature
            message = base64.b64decode(message_b64)
            
            # Verify HMAC
            if self.hmac_manager.verify_hmac_b64(message, signature_b64, key, session_id, hash_algorithm):
                return message
            
            return None
        except Exception:
            return None