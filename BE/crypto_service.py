"""
crypto_service.py - Integrated Cryptographic Service

This module integrates Perfect Forward Secrecy (PFS), Hash-based Message
Authentication Code (HMAC), and Key Exchange components into a unified
cryptographic service.
"""
import os
import time
import json
import base64
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Cryptography imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

# Import the enhanced components
from pfs_manager import PFSManager
from hmac_manager import HMACManager, SecureMessagePacker
from key_exchange_manager import KeyExchangeManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CryptoService:
    """
    Integrated cryptographic service with enhanced security components
    """
    
    def __init__(self):
        """Initialize the crypto service with enhanced components"""
        # Initialize the enhanced components
        self.pfs_manager = PFSManager(
            rotation_interval=300,  # 5 minutes
            key_lifespan=1800,      # 30 minutes
            cleanup_interval=3600   # 1 hour
        )
        
        self.hmac_manager = HMACManager(default_hash_algorithm='sha256')
        self.secure_packer = SecureMessagePacker(self.hmac_manager)
        
        self.key_exchange_manager = KeyExchangeManager(session_timeout=3600)
        
        # Start the PFS manager background tasks
        self.pfs_manager.start()
        
        # Keep track of algorithm benchmark results
        self.benchmark_results = {}
    
    def generate_rsa_keys(self, key_size: int = 2048) -> Dict[str, str]:
        """
        Generate RSA key pair
        
        Args:
            key_size: Size of RSA key in bits
            
        Returns:
            Dict with 'private_key' and 'public_key' in PEM format
        """
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
            "private_key": private_pem.decode('utf-8'),
            "public_key": public_pem.decode('utf-8')
        }
    
    def generate_ecc_keys(self, curve_name: str = 'SECP256R1') -> Dict[str, str]:
        """
        Generate ECC key pair
        
        Args:
            curve_name: Name of the elliptic curve to use
            
        Returns:
            Dict with 'private_key' and 'public_key' in PEM format
        """
        curve = getattr(ec, curve_name.upper())()
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
            "private_key": private_pem.decode('utf-8'),
            "public_key": public_pem.decode('utf-8')
        }
    
    def generate_dh_parameters(self, key_size: int = 2048) -> Dict:
        """
        Generate Diffie-Hellman parameters
        
        Args:
            key_size: Size of DH parameters in bits
            
        Returns:
            Dict with 'p' and 'g' parameters
        """
        parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
        parameter_numbers = parameters.parameter_numbers()
        
        return {
            "p": str(parameter_numbers.p),
            "g": str(parameter_numbers.g)
        }
    
    def generate_dh_keys(self, params: Dict) -> Dict[str, str]:
        """
        Generate DH key pair from parameters
        
        Args:
            params: Dict with 'p' and 'g' parameters
            
        Returns:
            Dict with 'private_key' and 'public_key' in PEM format
        """
        try:
            p = int(params["p"])
            g = int(params["g"])
            
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
                "private_key": private_pem.decode('utf-8'),
                "public_key": public_pem.decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Error generating DH keys: {e}")
            raise ValueError(f"Invalid DH parameters: {e}")
    
    def initiate_key_exchange(self, 
                             initiator: str, 
                             target: str, 
                             algorithm: str = "ecc", 
                             key_size: int = None) -> Dict:
        """
        Initiate a key exchange session using the enhanced KeyExchangeManager
        
        Args:
            initiator: Identifier for the initiator
            target: Identifier for the target
            algorithm: Key exchange algorithm (rsa, ecc, dh)
            key_size: Key size in bits
            
        Returns:
            Dict with exchange session info
        """
        metadata = {
            "initiated_by": initiator,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return self.key_exchange_manager.initiate_key_exchange(
            initiator=initiator,
            target=target,
            algorithm=algorithm,
            key_size=key_size,
            metadata=metadata
        )
    
    def complete_key_exchange(self, 
                             exchange_id: str, 
                             responder: str, 
                             public_key: str) -> Dict:
        """
        Complete a key exchange session
        
        Args:
            exchange_id: ID of the exchange session
            responder: Identifier for the responder
            public_key: Responder's public key (PEM format)
            
        Returns:
            Dict with exchange completion status
        """
        return self.key_exchange_manager.complete_key_exchange(
            exchange_id=exchange_id,
            responder=responder,
            public_key=public_key.encode() if isinstance(public_key, str) else public_key
        )
    
    def create_pfs_session(self, session_id: str, algorithm: str = "ecc", key_size: int = None) -> Dict:
        """
        Create a Perfect Forward Secrecy session
        
        Args:
            session_id: Identifier for the session
            algorithm: Encryption algorithm (rsa, ecc, dh)
            key_size: Key size in bits
            
        Returns:
            Dict with public key info for the session
        """
        return self.pfs_manager.rotate_session_keys(
            session_id=session_id,
            algorithm=algorithm,
            key_size=key_size
        )
    
    def get_pfs_private_key(self, session_id: str, algorithm: str) -> Optional[bytes]:
        """
        Get the current private key for a PFS session
        
        Args:
            session_id: Identifier for the session
            algorithm: Encryption algorithm (rsa, ecc, dh)
            
        Returns:
            Private key bytes if available, None otherwise
        """
        return self.pfs_manager.get_private_key(session_id, algorithm)
    
    def create_hmac_session(self, session_id: str, key_size: int = 32) -> bytes:
        """
        Create an HMAC session with a secure key
        
        Args:
            session_id: Identifier for the session
            key_size: Size of the HMAC key in bytes
            
        Returns:
            HMAC key bytes
        """
        return self.hmac_manager.generate_mac_key(session_id, key_size)
    
    def sign_message(self, 
                    message: bytes, 
                    session_id: str) -> Dict[str, str]:
        """
        Sign a message using HMAC
        
        Args:
            message: Message to sign
            session_id: Identifier for the session
            
        Returns:
            Dict with message and signature
        """
        return self.secure_packer.pack_message(
            message=message,
            session_id=session_id
        )
    
    def verify_message(self, 
                      packed_message: Dict[str, str], 
                      session_id: str) -> Optional[bytes]:
        """
        Verify and unpack a message
        
        Args:
            packed_message: Packed message with signature
            session_id: Identifier for the session
            
        Returns:
            Original message if signature is valid, None otherwise
        """
        return self.secure_packer.unpack_message(
            packed_message=packed_message,
            session_id=session_id
        )
    
    def encrypt_with_public_key(self, 
                               public_key_pem: str, 
                               message: bytes, 
                               algorithm: str = "rsa") -> Dict[str, str]:
        """
        Encrypt a message using a public key
        
        Args:
            public_key_pem: Public key in PEM format
            message: Message to encrypt
            algorithm: Encryption algorithm (rsa, ecc)
            
        Returns:
            Dict with encrypted message
        """
        if algorithm == "rsa":
            public_key = load_pem_public_key(
                public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
                backend=default_backend()
            )
            
            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return {
                "algorithm": algorithm,
                "ciphertext": base64.b64encode(ciphertext).decode('ascii')
            }
        
        elif algorithm == "ecc":
            # For ECC, we typically use hybrid encryption
            # Generate a random symmetric key
            symmetric_key = os.urandom(32)
            
            # Encrypt the symmetric key with ECC (using ECDH)
            public_key = load_pem_public_key(
                public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
                backend=default_backend()
            )
            
            # Generate ephemeral key pair for ECDH
            private_key = ec.generate_private_key(
                curve=public_key.curve,
                backend=default_backend()
            )
            ephemeral_public_key = private_key.public_key()
            
            # Perform ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            
            # Derive encryption key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'encryption',
                backend=default_backend()
            ).derive(shared_key)
            
            # Encrypt message with symmetric key
            iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            
            # Serialize ephemeral public key
            ephemeral_public_pem = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                "algorithm": algorithm,
                "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
                "ephemeral_public_key": base64.b64encode(ephemeral_public_pem).decode('ascii'),
                "iv": base64.b64encode(iv).decode('ascii'),
                "tag": base64.b64encode(encryptor.tag).decode('ascii')
            }
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt_with_private_key(self, 
                                private_key_pem: str, 
                                encrypted_data: Dict[str, str]) -> bytes:
        """
        Decrypt a message using a private key
        
        Args:
            private_key_pem: Private key in PEM format
            encrypted_data: Dict with encrypted message
            
        Returns:
            Decrypted message
        """
        algorithm = encrypted_data.get("algorithm")
        
        if algorithm == "rsa":
            private_key = load_pem_private_key(
                private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext
        
        elif algorithm == "ecc":
            private_key = load_pem_private_key(
                private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Get data from encrypted message
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            ephemeral_public_pem = base64.b64decode(encrypted_data["ephemeral_public_key"])
            iv = base64.b64decode(encrypted_data["iv"])
            tag = base64.b64decode(encrypted_data["tag"])
            
            # Load ephemeral public key
            ephemeral_public_key = load_pem_public_key(
                ephemeral_public_pem,
                backend=default_backend()
            )
            
            # Perform ECDH
            shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            
            # Derive decryption key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'encryption',
                backend=default_backend()
            ).derive(shared_key)
            
            # Decrypt message
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def benchmark(self, message_sizes: List[int], iterations: int = 5) -> Dict[str, Any]:
        """Run comprehensive benchmark of all algorithms"""
        # This is a simplified benchmark implementation
        results = {
            "encryption": {},
            "key_exchange": {},
            "hmac": {}
        }
        
        # Benchmark RSA
        for key_size in [2048, 3072, 4096]:
            rsa_keys = self.generate_rsa_keys(key_size)
            private_key = rsa_keys["private_key"]
            public_key = rsa_keys["public_key"]
            
            for msg_size in message_sizes:
                # For RSA, we encrypt a hash or symmetric key, not the full message
                message = os.urandom(min(msg_size, key_size // 8 - 66))
                
                # Encryption benchmark
                start_time = time.time()
                for _ in range(iterations):
                    encrypted = self.encrypt_with_public_key(public_key, message, "rsa")
                end_time = time.time()
                encryption_time = (end_time - start_time) / iterations
                
                # Decryption benchmark
                start_time = time.time()
                for _ in range(iterations):
                    decrypted = self.decrypt_with_private_key(private_key, encrypted)
                end_time = time.time()
                decryption_time = (end_time - start_time) / iterations
                
                if "RSA" not in results["encryption"]:
                    results["encryption"]["RSA"] = {}
                
                results["encryption"]["RSA"][f"{key_size}_{msg_size}"] = {
                    "key_size": key_size,
                    "message_size": len(message),
                    "encryption_time_ms": round(encryption_time * 1000, 3),
                    "decryption_time_ms": round(decryption_time * 1000, 3),
                }
        
        # Benchmark HMAC
        hmac_key = os.urandom(32)
        session_id = str(uuid.uuid4())
        self.hmac_manager.set_mac_key(session_id, hmac_key)
        
        for msg_size in message_sizes:
            message = os.urandom(msg_size)
            
            # HMAC generation benchmark
            start_time = time.time()
            for _ in range(iterations):
                signature = self.hmac_manager.generate_hmac(message, session_id=session_id)
            end_time = time.time()
            hmac_gen_time = (end_time - start_time) / iterations
            
            # HMAC verification benchmark
            start_time = time.time()
            for _ in range(iterations):
                verified = self.hmac_manager.verify_hmac(message, signature, session_id=session_id)
            end_time = time.time()
            hmac_verify_time = (end_time - start_time) / iterations
            
            results["hmac"][f"{msg_size}"] = {
                "message_size": msg_size,
                "generation_time_ms": round(hmac_gen_time * 1000, 3),
                "verification_time_ms": round(hmac_verify_time * 1000, 3),
            }
        
        # Benchmark Key Exchange
        for algorithm in ["rsa", "ecc", "dh"]:
            start_time = time.time()
            
            for _ in range(iterations):
                # Initiate key exchange
                exchange = self.key_exchange_manager.initiate_key_exchange(
                    initiator="benchmark_initiator",
                    target="benchmark_target",
                    algorithm=algorithm
                )
                
                # Generate responder keys
                if algorithm == "rsa":
                    responder_keys = self.generate_rsa_keys()
                elif algorithm == "ecc":
                    responder_keys = self.generate_ecc_keys()
                elif algorithm == "dh":
                    params = exchange.get("params", self.generate_dh_parameters())
                    responder_keys = self.generate_dh_keys(params)
                
                # Complete key exchange
                self.key_exchange_manager.complete_key_exchange(
                    exchange_id=exchange["exchange_id"],
                    responder="benchmark_target",
                    public_key=responder_keys["public_key"].encode()
                )
            
            end_time = time.time()
            key_exchange_time = (end_time - start_time) / iterations
            
            results["key_exchange"][algorithm] = {
                "time_ms": round(key_exchange_time * 1000, 3)
            }
        
        self.benchmark_results = results
        return results
    
    def cleanup(self):
        """Clean up resources"""
        self.pfs_manager.stop()
        self.hmac_manager.cleanup()
        logger.info("Crypto service cleaned up")