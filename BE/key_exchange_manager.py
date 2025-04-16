"""
key_exchange_manager.py - Key Exchange Implementation

This module implements secure key exchange protocols for establishing
shared secrets between users in an end-to-end encryption system.
"""
import os
import time
import uuid
import base64
import json
import logging
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass, field
from datetime import datetime

# Cryptography imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class KeyExchangeSession:
    """Class for storing key exchange session data"""
    id: str
    initiator: str
    target: str
    algorithm: str
    status: str
    created_at: float
    initiator_private_key: bytes
    initiator_public_key: bytes
    target_public_key: Optional[bytes] = None
    shared_key: Optional[bytes] = None
    completed_at: Optional[float] = None
    params: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)

class KeyExchangeManager:
    """
    Enhanced Key Exchange Manager with support for multiple algorithms,
    secure key derivation, and improved error handling.
    """
    
    def __init__(self, session_timeout: int = 3600):
        """
        Initialize Key Exchange Manager
        
        Args:
            session_timeout: Timeout for key exchange sessions in seconds
        """
        self.session_timeout = session_timeout
        self.sessions = {}
        
        # Default parameters
        self.default_rsa_key_size = 2048
        self.default_dh_key_size = 2048
        self.default_ec_curve = ec.SECP256R1()
        
        # Supported algorithms
        self.supported_algorithms = ["rsa", "ecc", "dh"]
    
    def _generate_rsa_key_pair(self, key_size: int = None) -> Dict[str, bytes]:
        """Generate RSA key pair"""
        key_size = key_size or self.default_rsa_key_size
        
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
    
    def _generate_ecc_key_pair(self, curve=None) -> Dict[str, bytes]:
        """Generate ECC key pair"""
        curve = curve or self.default_ec_curve
        
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
    
    def _generate_dh_parameters(self, key_size: int = None) -> Dict:
        """Generate Diffie-Hellman parameters"""
        key_size = key_size or self.default_dh_key_size
        
        parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
        parameter_numbers = parameters.parameter_numbers()
        
        return {
            "p": parameter_numbers.p,
            "g": parameter_numbers.g
        }
    
    def _generate_dh_key_pair(self, params: Dict) -> Dict[str, bytes]:
        """Generate Diffie-Hellman key pair from parameters"""
        p = params["p"]
        g = params["g"]
        
        parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
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
        
        return {
            "private_key": private_pem,
            "public_key": public_pem
        }
    
    def initiate_key_exchange(self, 
                             initiator: str, 
                             target: str, 
                             algorithm: str = "ecc", 
                             key_size: int = None,
                             metadata: Dict = None) -> Dict:
        """
        Initiate a key exchange session
        
        Args:
            initiator: Identifier for the initiator
            target: Identifier for the target
            algorithm: Key exchange algorithm (rsa, ecc, dh)
            key_size: Key size in bits
            metadata: Additional metadata for the exchange
            
        Returns:
            Dict with exchange session info
        """
        # Validate algorithm
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Generate key pair
        if algorithm == "rsa":
            key_pair = self._generate_rsa_key_pair(key_size)
            params = None
        elif algorithm == "ecc":
            key_pair = self._generate_ecc_key_pair()
            params = None
        elif algorithm == "dh":
            params = self._generate_dh_parameters(key_size)
            key_pair = self._generate_dh_key_pair(params)
        
        # Create exchange session
        exchange_id = str(uuid.uuid4())
        
        # Create session object
        session = KeyExchangeSession(
            id=exchange_id,
            initiator=initiator,
            target=target,
            algorithm=algorithm,
            status="initiated",
            created_at=time.time(),
            initiator_private_key=key_pair["private_key"],
            initiator_public_key=key_pair["public_key"],
            params=params or {},
            metadata=metadata or {}
        )
        
        # Store session
        self.sessions[exchange_id] = session
        
        # Return public information
        result = {
            "exchange_id": exchange_id,
            "algorithm": algorithm,
            "public_key": key_pair["public_key"]
        }
        
        if params:
            result["params"] = params
        
        return result
    
    def complete_key_exchange(self, 
                             exchange_id: str, 
                             responder: str, 
                             public_key: bytes) -> Dict:
        """
        Complete a key exchange session
        
        Args:
            exchange_id: ID of the exchange session
            responder: Identifier for the responder
            public_key: Responder's public key
            
        Returns:
            Dict with exchange completion status
        """
        # Check if exchange session exists
        if exchange_id not in self.sessions:
            raise ValueError(f"Exchange session not found: {exchange_id}")
        
        session = self.sessions[exchange_id]
        
        # Check if responder matches target
        if responder != session.target:
            raise ValueError(f"Responder {responder} does not match target {session.target}")
        
        # Check if session has expired
        if time.time() - session.created_at > self.session_timeout:
            raise ValueError(f"Exchange session has expired")
        
        # Check if session has already been completed
        if session.status == "completed":
            raise ValueError(f"Exchange session has already been completed")
        
        # Store responder's public key
        session.target_public_key = public_key
        
        # Derive shared key based on algorithm
        try:
            if session.algorithm == "rsa":
                # For RSA, we encrypt a random key with the public key
                session_key = os.urandom(32)
                
                responder_public_key = load_pem_public_key(
                    public_key,
                    backend=default_backend()
                )
                
                encrypted_session_key = responder_public_key.encrypt(
                    session_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Store the session key
                session.shared_key = session_key
                
            elif session.algorithm == "ecc":
                # For ECC, use ECDH
                initiator_private_key = load_pem_private_key(
                    session.initiator_private_key,
                    password=None,
                    backend=default_backend()
                )
                
                responder_public_key = load_pem_public_key(
                    public_key,
                    backend=default_backend()
                )
                
                shared_key = initiator_private_key.exchange(ec.ECDH(), responder_public_key)
                
                # Derive a key using HKDF
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(shared_key)
                
                # Store the derived key
                session.shared_key = derived_key
                
            elif session.algorithm == "dh":
                # For DH, use the DH key exchange
                initiator_private_key = load_pem_private_key(
                    session.initiator_private_key,
                    password=None,
                    backend=default_backend()
                )
                
                responder_public_key = load_pem_public_key(
                    public_key,
                    backend=default_backend()
                )
                
                shared_key = initiator_private_key.exchange(responder_public_key)
                
                # Derive a key using HKDF
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                    backend=default_backend()
                ).derive(shared_key)
                
                # Store the derived key
                session.shared_key = derived_key
            
            # Update session status
            session.status = "completed"
            session.completed_at = time.time()
            
            # Return completion status
            return {
                "exchange_id": exchange_id,
                "status": "completed",
                "shared_key_generated": True
            }
            
        except Exception as e:
            logger.error(f"Error completing key exchange: {e}")
            session.status = "failed"
            raise
    
    def get_shared_key(self, exchange_id: str) -> Optional[bytes]:
        """
        Get the shared key for a completed exchange
        
        Args:
            exchange_id: ID of the exchange session
            
        Returns:
            Shared key if available, None otherwise
        """
        if exchange_id not in self.sessions:
            return None
        
        session = self.sessions[exchange_id]
        
        if session.status != "completed" or not session.shared_key:
            return None
        
        return session.shared_key
    
    def get_exchange_info(self, exchange_id: str) -> Optional[Dict]:
        """
        Get information about an exchange session
        
        Args:
            exchange_id: ID of the exchange session
            
        Returns:
            Dict with exchange session info if found, None otherwise
        """
        if exchange_id not in self.sessions:
            return None
        
        session = self.sessions[exchange_id]
        
        return {
            "exchange_id": session.id,
            "initiator": session.initiator,
            "target": session.target,
            "algorithm": session.algorithm,
            "status": session.status,
            "created_at": datetime.fromtimestamp(session.created_at).isoformat(),
            "completed_at": datetime.fromtimestamp(session.completed_at).isoformat() if session.completed_at else None,
            "shared_key_available": session.shared_key is not None,
            "metadata": session.metadata
        }
    
    def clean_up_expired_sessions(self):
        """Clean up expired exchange sessions"""
        current_time = time.time()
        
        expired_sessions = []
        for exchange_id, session in self.sessions.items():
            if current_time - session.created_at > self.session_timeout:
                expired_sessions.append(exchange_id)
        
        for exchange_id in expired_sessions:
            # Securely clear the private key and shared key
            if self.sessions[exchange_id].initiator_private_key:
                self.sessions[exchange_id].initiator_private_key = b'\x00' * len(self.sessions[exchange_id].initiator_private_key)
            
            if self.sessions[exchange_id].shared_key:
                self.sessions[exchange_id].shared_key = b'\x00' * len(self.sessions[exchange_id].shared_key)
            
            del self.sessions[exchange_id]
        
        return len(expired_sessions)
    
    def get_active_exchanges(self, user_id: str, as_initiator: bool = True, as_target: bool = True) -> List[Dict]:
        """
        Get all active exchanges for a user
        
        Args:
            user_id: User ID to search for
            as_initiator: Include exchanges where user is initiator
            as_target: Include exchanges where user is target
            
        Returns:
            List of exchange info dictionaries
        """
        result = []
        
        for exchange_id, session in self.sessions.items():
            if (as_initiator and session.initiator == user_id) or (as_target and session.target == user_id):
                result.append(self.get_exchange_info(exchange_id))
        
        return result
    
    def cancel_exchange(self, exchange_id: str, user_id: str) -> bool:
        """
        Cancel a key exchange session
        
        Args:
            exchange_id: ID of the exchange session
            user_id: ID of the user canceling the exchange
            
        Returns:
            True if successfully canceled, False otherwise
        """
        if exchange_id not in self.sessions:
            return False
        
        session = self.sessions[exchange_id]
        
        # Check if user is authorized to cancel
        if session.initiator != user_id and session.target != user_id:
            return False
        
        # Check if session is already completed
        if session.status == "completed":
            return False
        
        # Securely clear keys
        if session.initiator_private_key:
            session.initiator_private_key = b'\x00' * len(session.initiator_private_key)
        
        if session.shared_key:
            session.shared_key = b'\x00' * len(session.shared_key)
        
        # Update status
        session.status = "canceled"
        
        # Delete session
        del self.sessions[exchange_id]
        
        return True