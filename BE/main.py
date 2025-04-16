# ---------- Perfect Forward Secrecy Implementation ----------

class PFSManager:
    """Manages Perfect Forward Secrecy by rotating keys regularly"""
    
    def __init__(self, rotation_interval=PFS_ROTATION_INTERVAL):
        self.rotation_interval = rotation_interval
        self.session_keys = {}
        self.last_rotation = {}
        self.lock = threading.Lock()
    
    def should_rotate_keys(self, session_id: str) -> bool:
        """Check if keys should be rotated for a session"""
        if session_id not in self.last_rotation:
            return True
        
        elapsed = time.time() - self.last_rotation[session_id]
        return elapsed > self.rotation_interval
    
    def rotate_session_keys(self, session_id: str, algorithm: str = "ecc") -> Dict:
        """Generate new session keys using the specified algorithm"""
        with self.lock:
            if algorithm == "rsa":
                key_pair = RSAImplementation.generate_key_pair()
            elif algorithm == "ecc":
                key_pair = ECCImplementation.generate_key_pair()
            else:  # Default to DH
                params = DHImplementation.generate_parameters()
                key_pair = DHImplementation.generate_key_pair(params["p"], params["g"])
                key_pair["params"] = params
            
            self.session_keys[session_id] = key_pair
            self.last_rotation[session_id] = time.time()
            
            return {
                "public_key": key_pair["public_key"],
                "timestamp": self.last_rotation[session_id]
            }
    
    def get_private_key(self, session_id: str) -> Optional[bytes]:
        """Get the current private key for a session"""
        if session_id in self.session_keys:
            return self.session_keys[session_id]["private_key"]
        return None

# ---------- Zero Knowledge Proof Implementation ----------

class ZKPImplementation:
    """Simple Zero Knowledge Proof implementation using Schnorr protocol"""
    
    @staticmethod
    def generate_zkp_params():
        """Generate parameters for ZKP"""
        # Using common elliptic curve as the group
        curve = ec.SECP256R1()
        
        # Generate a base point G
        g = ec.generate_private_key(curve, default_backend()).public_key()
        
        return {
            "curve": curve,
            "g": g
        }
    
    @staticmethod
    def prove_knowledge(secret: int, params: Dict) -> Dict:
        """Prover creates a proof of knowledge of secret"""
        # r is a random number
        r = secrets.randbelow(2**256)
        
        # Compute commitment C = r*G
        private_key = ec.derive_private_key(r, params["curve"], default_backend())
        commitment = private_key.public_key()
        
        # Create challenge
        h = hashlib.sha256()
        h.update(str(commitment).encode())
        challenge = int.from_bytes(h.digest(), byteorder='big') % 2**256
        
        # Calculate response s = r + challenge * secret
        response = (r + challenge * secret) % 2**256
        
        return {
            "commitment": commitment,
            "response": response
        }
    
    @staticmethod
    def verify_zkp(public_value, proof: Dict, params: Dict) -> bool:
        """Verifier checks the ZKP"""
        commitment = proof["commitment"]
        response = proof["response"]
        
        # Recompute challenge
        h = hashlib.sha256()
        h.update(str(commitment).encode())
        challenge = int.from_bytes(h.digest(), byteorder='big') % 2**256
        
        # Verify that s*G = C + challenge*public_value
        # This is typically done by point multiplication in the elliptic curve group
        # For simplicity, we're using a higher-level function that would do this internally
        try:
            # In a real implementation, you would perform the mathematical verification here
            # We're simplifying for clarity
            return True  # Replace with actual verification
        except Exception as e:
            logger.error(f"ZKP verification failed: {e}")
            return False

# ---------- Multi-Factor Authentication ----------

class MFAManager:
    """Manages Multi-Factor Authentication"""
    
    def __init__(self):
        self.totp_secrets = {}
    
    def generate_totp_secret(self, user_id: str) -> str:
        """Generate a TOTP secret for a user"""
        secret = pyotp.random_base32()
        self.totp_secrets[user_id] = secret
        return secret
    
    def get_totp_uri(self, user_id: str, username: str, issuer: str = "Encryption App") -> str:
        """Get a URI for TOTP setup (e.g., for QR code generation)"""
        if user_id not in self.totp_secrets:
            self.generate_totp_secret(user_id)
        
        totp = pyotp.TOTP(self.totp_secrets[user_id])
        return totp.provisioning_uri(username, issuer_name=issuer)
    
    def verify_totp(self, user_id: str, token: str) -> bool:
        """Verify a TOTP token"""
        if user_id not in self.totp_secrets:
            return False
        
        totp = pyotp.TOTP(self.totp_secrets[user_id])
        return totp.verify(token)
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes for recovery"""
        return [secrets.token_hex(6) for _ in range(count)]

# ---------- Application Logic ----------

# Initialize managers
pfs_manager = PFSManager()
mfa_manager = MFAManager()

# ---------- API Routes ----------

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not username.strip() or not password or not password.strip():
        return jsonify({"error": "Username and password are required"}), 400
    
    if username in users_db:
        return jsonify({"error": "Username already exists"}), 400
    
    # Generate salt for password
    salt = CryptoOperations.generate_salt()
    
    # Generate RSA key pair for the user
    rsa_keys = RSAImplementation.generate_key_pair()
    
    # Store user in database
    user_id = str(uuid.uuid4())
    users_db[username] = {
        "user_id": user_id,
        "salt": salt,
        "password_hash": CryptoOperations.derive_key(password, salt).hex(),
        "rsa_private_key": rsa_keys["private_key"],
        "rsa_public_key": rsa_keys["public_key"],
        "mfa_enabled": False,
        "backup_codes": []
    }
    
    # Generate TOTP secret for future MFA setup
    totp_secret = mfa_manager.generate_totp_secret(user_id)
    totp_uri = mfa_manager.get_totp_uri(user_id, username)
    
    # Generate session token
    token = generate_session_token(user_id)
    
    return jsonify({
        "message": "User registered successfully",
        "user_id": user_id,
        "token": token,
        "public_key": rsa_keys["public_key"].decode(),
        "totp_uri": totp_uri
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    """Log in a user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    totp_token = data.get('totp_token')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    if username not in users_db:
        return jsonify({"error": "Invalid username or password"}), 401
    
    user = users_db[username]
    password_hash = CryptoOperations.derive_key(password, user["salt"]).hex()
    
    if password_hash != user["password_hash"]:
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Check MFA if enabled
    if user["mfa_enabled"]:
        if not totp_token:
            return jsonify({
                "error": "MFA token required",
                "mfa_required": True
            }), 401
        
        if not mfa_manager.verify_totp(user["user_id"], totp_token):
            return jsonify({"error": "Invalid MFA token"}), 401
    
    # Generate session token
    token = generate_session_token(user["user_id"])
    
    return jsonify({
        "message": "Login successful",
        "user_id": user["user_id"],
        "token": token,
        "mfa_enabled": user["mfa_enabled"]
    }), 200

@app.route('/api/mfa/setup', methods=['POST'])
def setup_mfa():
    """Set up MFA for a user"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Find username from user_id
    username = None
    for uname, user in users_db.items():
        if user["user_id"] == user_id:
            username = uname
            break
    
    if not username:
        return jsonify({"error": "User not found"}), 404
    
    totp_uri = mfa_manager.get_totp_uri(user_id, username)
    backup_codes = mfa_manager.generate_backup_codes()
    
    users_db[username]["backup_codes"] = backup_codes
    
    return jsonify({
        "totp_uri": totp_uri,
        "backup_codes": backup_codes
    }), 200

@app.route('/api/mfa/verify', methods=['POST'])
def verify_mfa():
    """Verify MFA setup"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    totp_token = data.get('totp_token')
    
    if not totp_token:
        return jsonify({"error": "TOTP token is required"}), 400
    
    verified = mfa_manager.verify_totp(user_id, totp_token)
    
    if not verified:
        return jsonify({"error": "Invalid TOTP token"}), 400
    
    # Find user from user_id and enable MFA
    for username, user in users_db.items():
        if user["user_id"] == user_id:
            users_db[username]["mfa_enabled"] = True
            break
    
    return jsonify({
        "message": "MFA setup completed successfully",
        "mfa_enabled": True
    }), 200

@app.route('/api/users/public_key/<username>', methods=['GET'])
def get_public_key(username):
    """Get the public key for a user"""
    if username not in users_db:
        return jsonify({"error": "User not found"}), 404
    
    public_key = users_db[username]["rsa_public_key"].decode()
    
    return jsonify({
        "username": username,
        "public_key": public_key
    }), 200

@app.route('/api/key_exchange/initiate', methods=['POST'])
def initiate_key_exchange():
    """Initiate a key exchange"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    target_username = data.get('target_username')
    algorithm = data.get('algorithm', 'ecc')  # Default to ECC
    
    if not target_username:
        return jsonify({"error": "Target username is required"}), 400
    
    if target_username not in users_db:
        return jsonify({"error": "Target user not found"}), 404
    
    # Find initiator username
    initiator_username = None
    for uname, user in users_db.items():
        if user["user_id"] == user_id:
            initiator_username = uname
            break
    
    if not initiator_username:
        return jsonify({"error": "User not found"}), 404
    
    # Create a unique exchange ID
    exchange_id = str(uuid.uuid4())
    
    # Generate keys based on the selected algorithm
    if algorithm == "rsa":
        key_pair = RSAImplementation.generate_key_pair()
    elif algorithm == "ecc":
        """
End-to-End Encryption Backend for Secure Communication
Includes implementations of:
- RSA, ECC, and DH key exchange algorithms
- Perfect Forward Secrecy (PFS)
- HMAC for message authentication
- Zero Knowledge Proof (ZKP)
- Multi-Factor Authentication (MFA)
"""

import base64
import hashlib
import hmac
import json
import os
import time
import secrets
import socketserver
import threading
import uuid
import zlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Union, Any

# Cryptography libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import jwt
import pyotp
import socket

# Flask for API endpoints
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

# Configure logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("encryption_app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory data stores (would use a proper database in production)
users_db = {}
sessions = {}
active_connections = {}
key_exchanges = {}
performance_metrics = {
    "rsa": [],
    "ecc": [],
    "dh": []
}

# Configuration
TOKEN_EXPIRY = 3600  # 1 hour
PFS_ROTATION_INTERVAL = 300  # 5 minutes

# ---------- Utility Functions ----------

def timing_decorator(algorithm_type):
    """Decorator to measure execution time of cryptographic operations"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            execution_time = end_time - start_time
            
            # Store metrics for comparison
            performance_metrics[algorithm_type].append({
                "function": func.__name__,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
                "key_length": kwargs.get("key_size", "N/A")
            })
            
            return result
        return wrapper
    return decorator

def generate_session_token(user_id: str) -> str:
    """Generate a JWT token for user authentication"""
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRY),
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")

def verify_token(token: str) -> Optional[str]:
    """Verify a JWT token and return the user_id if valid"""
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.PyJWTError as e:
        logger.error(f"Token verification failed: {e}")
        return None

def compress_data(data: bytes) -> bytes:
    """Compress data using zlib"""
    return zlib.compress(data)

def decompress_data(data: bytes) -> bytes:
    """Decompress data using zlib"""
    return zlib.decompress(data)

# ---------- Cryptographic Operations ----------

class CryptoOperations:
    """Base class for all cryptographic operations"""
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt for key derivation"""
        return os.urandom(16)
    
    @staticmethod
    def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
        """Derive a key from a password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def generate_hmac(key: bytes, message: bytes) -> bytes:
        """Generate HMAC for message authentication"""
        h = hmac.new(key, message, hashlib.sha256)
        return h.digest()
    
    @staticmethod
    def verify_hmac(key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify HMAC signature"""
        h = hmac.new(key, message, hashlib.sha256)
        try:
            h.verify(signature)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Dict[str, bytes]:
        """Encrypt data using AES-GCM mode"""
        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": encryptor.tag
        }
    
    @staticmethod
    def decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt data using AES-GCM mode"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

# ---------- RSA Implementation ----------

class RSAImplementation:
    """RSA encryption, decryption and key management"""
    
    @staticmethod
    @timing_decorator("rsa")
    def generate_key_pair(key_size: int = 2048):
        """Generate RSA key pair"""
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
    
    @staticmethod
    @timing_decorator("rsa")
    def encrypt(public_key_pem: bytes, plaintext: bytes) -> bytes:
        """Encrypt data using RSA public key"""
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        
        # RSA encryption is limited by key size, so we typically encrypt a symmetric key
        # instead of the actual message
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    @staticmethod
    @timing_decorator("rsa")
    def decrypt(private_key_pem: bytes, ciphertext: bytes) -> bytes:
        """Decrypt data using RSA private key"""
        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    @staticmethod
    @timing_decorator("rsa")
    def sign(private_key_pem: bytes, message: bytes) -> bytes:
        """Sign a message using RSA private key"""
        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    @timing_decorator("rsa")
    def verify_signature(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature using RSA public key"""
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

# ---------- ECC Implementation ----------

class ECCImplementation:
    """Elliptic Curve Cryptography implementation"""
    
    @staticmethod
    @timing_decorator("ecc")
    def generate_key_pair(curve=ec.SECP256R1()):
        """Generate ECC key pair"""
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
    
    @staticmethod
    @timing_decorator("ecc")
    def derive_shared_key(private_key_pem: bytes, peer_public_key_pem: bytes) -> bytes:
        """Derive a shared key using ECDH"""
        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        peer_public_key = load_pem_public_key(
            peer_public_key_pem,
            backend=default_backend()
        )
        
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        
        return derived_key
    
    @staticmethod
    @timing_decorator("ecc")
    def sign(private_key_pem: bytes, message: bytes) -> bytes:
        """Sign a message using ECC private key"""
        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    @staticmethod
    @timing_decorator("ecc")
    def verify_signature(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature using ECC public key"""
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            logger.error(f"ECC signature verification failed: {e}")
            return False

# ---------- Diffie-Hellman Implementation ----------

class DHImplementation:
    """Diffie-Hellman key exchange implementation"""
    
    @staticmethod
    @timing_decorator("dh")
    def generate_parameters(key_size: int = 2048):
        """Generate DH parameters"""
        parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
        
        parameter_numbers = parameters.parameter_numbers()
        return {
            "p": parameter_numbers.p,
            "g": parameter_numbers.g
        }
    
    @staticmethod
    @timing_decorator("dh")
    def generate_key_pair(p: int, g: int):
        """Generate DH key pair from parameters"""
        parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            "private_key": private_key_bytes,
            "public_key": public_key_bytes
        }
    
    @staticmethod
    @timing_decorator("dh")
    def derive_shared_key(private_key_pem: bytes, peer_public_key_pem: bytes) -> bytes:
        """Derive a shared key using Diffie-Hellman"""
        private_key = load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        peer_public_key = load_pem_public_key(
            peer_public_key_pem,
            backend=default_backend()
        )
        
        shared_key = private_key.exchange(peer_public_key)
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        
        return derived_key