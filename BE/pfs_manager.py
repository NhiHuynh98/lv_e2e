"""
pfs_manager.py - Perfect Forward Secrecy Implementation

This module implements Perfect Forward Secrecy (PFS) for an end-to-end encryption system.
It manages key rotation and secure session key lifecycle.
"""
import threading
import time
from datetime import datetime, timedelta
import os
import secrets
import logging
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SessionKey:
    """Class for storing session key data with metadata"""
    key_pair: Dict[str, bytes]  # Contains 'private_key' and 'public_key'
    algorithm: str
    created_at: float
    expires_at: float
    params: Dict = None
    used: bool = False
    marked_for_deletion: bool = False
    
    @property
    def age(self) -> float:
        """Get the age of the key in seconds"""
        return time.time() - self.created_at
    
    @property
    def is_expired(self) -> bool:
        """Check if the key is expired"""
        return time.time() >= self.expires_at

class PFSManager:
    """
    Enhanced Perfect Forward Secrecy manager with key rotation,
    secure cleanup, and multiple algorithm support
    """
    
    def __init__(self, 
                rotation_interval: int = 300,  # 5 minutes
                key_lifespan: int = 1800,      # 30 minutes
                cleanup_interval: int = 3600): # 1 hour
        
        self.rotation_interval = rotation_interval
        self.key_lifespan = key_lifespan
        self.cleanup_interval = cleanup_interval
        
        # Session key storage
        self.session_keys: Dict[str, Dict[str, SessionKey]] = {}
        
        # Background task management
        self.lock = threading.RLock()
        self.cleanup_thread = threading.Thread(target=self._background_cleanup, daemon=True)
        self.running = False
        
        # Statistics for monitoring
        self.stats = {
            "rotations_performed": 0,
            "keys_cleaned_up": 0,
            "active_sessions": 0
        }
    
    def start(self):
        """Start the PFS manager background tasks"""
        with self.lock:
            if not self.running:
                self.running = True
                self.cleanup_thread.start()
                logger.info("PFS Manager started")
    
    def stop(self):
        """Stop the PFS manager background tasks"""
        with self.lock:
            self.running = False
            # Wait for cleanup to finish
            if self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=10)
            logger.info("PFS Manager stopped")
    
    def _background_cleanup(self):
        """Background thread to clean up expired keys"""
        while self.running:
            try:
                self._cleanup_expired_keys()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in PFS cleanup thread: {e}")
    
    def _cleanup_expired_keys(self):
        """Clean up expired and marked-for-deletion keys"""
        with self.lock:
            current_time = time.time()
            cleanup_count = 0
            
            # Process all sessions
            sessions_to_remove = []
            for session_id, algorithm_keys in self.session_keys.items():
                # Process all algorithm keys in this session
                algorithms_to_remove = []
                for algorithm, session_key in algorithm_keys.items():
                    # Check if key is expired or marked for deletion
                    if session_key.is_expired or session_key.marked_for_deletion:
                        # Securely clear the private key from memory (best effort)
                        if hasattr(session_key.key_pair, 'private_key'):
                            session_key.key_pair['private_key'] = b'\x00' * len(session_key.key_pair['private_key'])
                        
                        algorithms_to_remove.append(algorithm)
                        cleanup_count += 1
                
                # Remove keys for algorithms that are expired
                for algorithm in algorithms_to_remove:
                    del algorithm_keys[algorithm]
                
                # If all algorithm keys are gone, mark this session for removal
                if not algorithm_keys:
                    sessions_to_remove.append(session_id)
            
            # Remove empty sessions
            for session_id in sessions_to_remove:
                del self.session_keys[session_id]
            
            # Update stats
            self.stats["keys_cleaned_up"] += cleanup_count
            self.stats["active_sessions"] = len(self.session_keys)
            
            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} expired keys")
    
    def _generate_key_pair(self, algorithm: str, key_size: int = None) -> Dict:
        """Generate a new key pair using the specified algorithm"""
        if algorithm == "rsa":
            key_size = key_size or 2048
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Serialize keys to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                "private_key": private_pem,
                "public_key": public_pem
            }
            
        elif algorithm == "ecc":
            curve = ec.SECP256R1()  # P-256 curve (NIST)
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()
            
            # Serialize keys to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                "private_key": private_pem,
                "public_key": public_pem
            }
            
        elif algorithm == "dh":
            key_size = key_size or 2048
            parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
            
            parameter_numbers = parameters.parameter_numbers()
            params = {
                "p": parameter_numbers.p,
                "g": parameter_numbers.g
            }
            
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Serialize keys to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            key_pair = {
                "private_key": private_pem,
                "public_key": public_pem
            }
            
            key_pair["params"] = params
            return key_pair
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def should_rotate_keys(self, session_id: str, algorithm: str) -> bool:
        """Check if keys should be rotated for a session"""
        with self.lock:
            # If session doesn't exist, we definitely need new keys
            if session_id not in self.session_keys:
                return True
            
            # If algorithm doesn't exist for this session, we need new keys
            if algorithm not in self.session_keys[session_id]:
                return True
            
            # Check if the current key is expired or too old
            session_key = self.session_keys[session_id][algorithm]
            
            # If key has been used and is older than rotation interval, rotate
            if session_key.used and session_key.age > self.rotation_interval:
                return True
            
            # If key is expired, rotate
            if session_key.is_expired:
                return True
            
            # No need to rotate
            return False
    
    def rotate_session_keys(self, 
                           session_id: str, 
                           algorithm: str = "ecc", 
                           key_size: int = None) -> Dict:
        """
        Generate new session keys using the specified algorithm
        
        Args:
            session_id: Identifier for the session
            algorithm: Encryption algorithm ("rsa", "ecc", "dh")
            key_size: Size of the key in bits
            
        Returns:
            Dict with public key and other necessary information
        """
        with self.lock:
            # Generate new key pair
            key_pair = self._generate_key_pair(algorithm, key_size)
            
            current_time = time.time()
            expires_at = current_time + self.key_lifespan
            
            # Create session key object
            session_key = SessionKey(
                key_pair=key_pair,
                algorithm=algorithm,
                created_at=current_time,
                expires_at=expires_at,
                params=key_pair.get("params")
            )
            
            # Store the session key
            if session_id not in self.session_keys:
                self.session_keys[session_id] = {}
            
            # If there's an existing key, mark it for deletion
            if algorithm in self.session_keys[session_id]:
                self.session_keys[session_id][algorithm].marked_for_deletion = True
            
            # Store the new key
            self.session_keys[session_id][algorithm] = session_key
            
            # Update stats
            self.stats["rotations_performed"] += 1
            self.stats["active_sessions"] = len(self.session_keys)
            
            logger.info(f"Rotated {algorithm} keys for session {session_id[:8]}...")
            
            # Return public information
            result = {
                "public_key": key_pair["public_key"],
                "timestamp": current_time,
                "expires_at": expires_at
            }
            
            if "params" in key_pair:
                result["params"] = key_pair["params"]
            
            return result
    
    def get_private_key(self, session_id: str, algorithm: str) -> Optional[bytes]:
        """Get the current private key for a session"""
        with self.lock:
            if session_id in self.session_keys and algorithm in self.session_keys[session_id]:
                session_key = self.session_keys[session_id][algorithm]
                
                # Mark as used so it will be rotated after the rotation interval
                session_key.used = True
                
                if not session_key.is_expired:
                    return session_key.key_pair["private_key"]
            
            return None
    
    def get_session_info(self, session_id: str) -> Dict:
        """Get information about a session's keys"""
        with self.lock:
            if session_id not in self.session_keys:
                return {"exists": False}
            
            result = {"exists": True, "algorithms": {}}
            
            for algorithm, session_key in self.session_keys[session_id].items():
                result["algorithms"][algorithm] = {
                    "created_at": datetime.fromtimestamp(session_key.created_at).isoformat(),
                    "expires_at": datetime.fromtimestamp(session_key.expires_at).isoformat(),
                    "age_seconds": session_key.age,
                    "is_expired": session_key.is_expired,
                    "used": session_key.used
                }
            
            return result
    
    def get_stats(self) -> Dict:
        """Get statistics about the PFS manager"""
        with self.lock:
            return self.stats.copy()