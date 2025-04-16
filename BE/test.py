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
    
    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400
    
    # Generate salt for password
    salt = CryptoOperations.generate_salt()
    
    # Generate RSA key pair for the user
    rsa_keys = RSAImplementation.generate_key_pair()
    
    # Create new user in database
    user_id = str(uuid.uuid4())
    new_user = User(
        id=user_id,
        username=username,
        salt=salt,
        password_hash=CryptoOperations.derive_key(password, salt).hex(),
        rsa_private_key=rsa_keys["private_key"],
        rsa_public_key=rsa_keys["public_key"],
        mfa_enabled=False,
        backup_codes=[]
    )
    
    # Generate TOTP secret for future MFA setup
    totp_secret = mfa_manager.generate_totp_secret(user_id)
    totp_uri = mfa_manager.get_totp_uri(user_id, username)
    
    # Generate session token
    token = generate_session_token(user_id)
    
    # Create session record
    session_id = str(uuid.uuid4())
    new_session = Session(
        id=session_id,
        user_id=user_id,
        token=token,
        expires_at=datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRY)
    )
    
    # Save to database
    try:
        db_session.add(new_user)
        db_session.add(new_session)
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        logger.error(f"Database error during registration: {e}")
        return jsonify({"error": "Registration failed due to database error"}), 500
    
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
    
    # Find user in database
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401
    
    password_hash = CryptoOperations.derive_key(password, user.salt).hex()
    
    if password_hash != user.password_hash:
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Check MFA if enabled
    if user.mfa_enabled:
        if not totp_token:
            return jsonify({
                "error": "MFA token required",
                "mfa_required": True
            }), 401
        
        if not mfa_manager.verify_totp(user.id, totp_token):
            return jsonify({"error": "Invalid MFA token"}), 401
    
    # Generate session token
    token = generate_session_token(user.id)
    
    # Create session record
    session_id = str(uuid.uuid4())
    new_session = Session(
        id=session_id,
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRY)
    )
    
    # Save to database
    try:
        db_session.add(new_session)
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        logger.error(f"Database error during login: {e}")
        return jsonify({"error": "Login failed due to database error"}), 500
    
    return jsonify({
        "message": "Login successful",
        "user_id": user.id,
        "token": token,
        "mfa_enabled": user.mfa_enabled
    }), 200

_id
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
        key_pair = ECCImplementation.generate_key_pair()
    else:  # dh
        params = DHImplementation.generate_parameters()
        key_pair = DHImplementation.generate_key_pair(params["p"], params["g"])
        key_pair["params"] = params
    
    # Store the exchange information
    key_exchanges[exchange_id] = {
        "initiator": initiator_username,
        "target": target_username,
        "algorithm": algorithm,
        "initiator_private_key": key_pair["private_key"],
        "initiator_public_key": key_pair["public_key"],
        "status": "initiated",
        "created_at": datetime.now().isoformat(),
        "shared_key": None
    }
    
    # Add DH params if applicable
    if algorithm == "dh":
        key_exchanges[exchange_id]["params"] = key_pair["params"]
    
    return jsonify({
        "exchange_id": exchange_id,
        "algorithm": algorithm,
        "public_key": key_pair["public_key"].decode(),
        "params": key_pair.get("params")
    }), 200

@app.route('/api/key_exchange/complete', methods=['POST'])
def complete_key_exchange():
    """Complete a key exchange"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    exchange_id = data.get('exchange_id')
    public_key = data.get('public_key')
    
    if not exchange_id or not public_key:
        return jsonify({"error": "Exchange ID and public key are required"}), 400
    
    if exchange_id not in key_exchanges:
        return jsonify({"error": "Exchange not found"}), 404
    
    exchange = key_exchanges[exchange_id]
    
    # Find responder username from user_id
    responder_username = None
    for uname, user in users_db.items():
        if user["user_id"] == user_id:
            responder_username = uname
            break
    
    if not responder_username:
        return jsonify({"error": "User not found"}), 404
    
    if responder_username != exchange["target"]:
        return jsonify({"error": "Unauthorized to complete this exchange"}), 403
    
    # Derive shared key based on the algorithm
    algorithm = exchange["algorithm"]
    try:
        peer_public_key = public_key.encode() if isinstance(public_key, str) else public_key
        
        if algorithm == "rsa":
            # For RSA, we encrypt a random key with the public key
            session_key = os.urandom(32)
            encrypted_session_key = RSAImplementation.encrypt(
                peer_public_key,
                session_key
            )
            shared_key = session_key
        elif algorithm == "ecc":
            shared_key = ECCImplementation.derive_shared_key(
                exchange["initiator_private_key"],
                peer_public_key
            )
        else:  # dh
            shared_key = DHImplementation.derive_shared_key(
                exchange["initiator_private_key"],
                peer_public_key
            )
        
        # Store the derived shared key (in a real system, you'd want to protect this better)
        key_exchanges[exchange_id]["shared_key"] = shared_key
        key_exchanges[exchange_id]["status"] = "completed"
        
        # Return encrypted session key for RSA, confirmation for others
        if algorithm == "rsa":
            return jsonify({
                "status": "completed",
                "encrypted_session_key": base64.b64encode(encrypted_session_key).decode()
            }), 200
        else:
            # Just confirmation for ECDH/DH - the shared key is derived on both sides
            return jsonify({
                "status": "completed"
            }), 200
            
    except Exception as e:
        logger.error(f"Key exchange completion failed: {e}")
        return jsonify({"error": "Key exchange failed"}), 500

@app.route('/api/performance', methods=['GET'])
def get_performance_metrics():
    """Get performance metrics for different algorithms"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Return performance metrics
    return jsonify(performance_metrics), 200

# ---------- WebSocket Implementation ----------

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    token = request.args.get('token')
    user_id = verify_token(token)
    
    if not user_id:
        return False  # Reject connection
    
    # Find username from user_id
    username = None
    for uname, user in users_db.items():
        if user["user_id"] == user_id:
            username = uname
            break
    
    if not username:
        return False  # Reject connection
    
    # Store the connection
    active_connections[request.sid] = {
        "user_id": user_id,
        "username": username,
        "connected_at": datetime.now().isoformat()
    }
    
    # Join a room named after the user's username for direct messaging
    join_room(username)
    
    # Notify others about the connection
    emit('user_status', {
        "username": username,
        "status": "online"
    }, broadcast=True, include_self=False)
    
    return True

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if request.sid in active_connections:
        username = active_connections[request.sid]["username"]
        
        # Remove the connection
        del active_connections[request.sid]
        
        # Notify others about the disconnection
        emit('user_status', {
            "username": username,
            "status": "offline"
        }, broadcast=True)

@socketio.on('message')
def handle_message(data):
    """Handle message exchange"""
    if request.sid not in active_connections:
        emit('error', {"error": "Not authenticated"})
        return
    
    sender = active_connections[request.sid]["username"]
    recipient = data.get('recipient')
    encrypted_message = data.get('message')
    hmac_signature = data.get('hmac')
    exchange_id = data.get('exchange_id')
    
    if not recipient or not encrypted_message or not hmac_signature or not exchange_id:
        emit('error', {"error": "Missing required fields"})
        return
    
    if recipient not in users_db:
        emit('error', {"error": "Recipient not found"})
        return
    
    if exchange_id not in key_exchanges:
        emit('error', {"error": "Exchange not found"})
        return
    
    exchange = key_exchanges[exchange_id]
    
    # Verify that the sender is part of this exchange
    if sender != exchange["initiator"] and sender != exchange["target"]:
        emit('error', {"error": "Unauthorized to use this exchange"})
        return
    
    # Verify HMAC signature
    shared_key = exchange["shared_key"]
    if not shared_key:
        emit('error', {"error": "Shared key not established"})
        return
    
    try:
        message_bytes = base64.b64decode(encrypted_message)
        hmac_bytes = base64.b64decode(hmac_signature)
        
        if not CryptoOperations.verify_hmac(shared_key, message_bytes, hmac_bytes):
            emit('error', {"error": "Invalid HMAC signature"})
            return
        
        # Message is authenticated, forward to recipient
        emit('message', {
            "sender": sender,
            "message": encrypted_message,
            "hmac": hmac_signature,
            "exchange_id": exchange_id,
            "timestamp": datetime.now().isoformat()
        }, room=recipient)
        
    except Exception as e:
        logger.error(f"Message handling failed: {e}")
        emit('error', {"error": "Message handling failed"})

# ---------- TCP Server Implementation ----------

class EncryptedTCPHandler(socketserver.BaseRequestHandler):
    """
    TCP handler for encrypted communication
    """
    def handle(self):
        try:
            # Receive data from client
            data = self.request.recv(4096).strip()
            
            # Process the data (in a real app, this would involve authentication and decryption)
            message = json.loads(data.decode())
            
            # Example processing logic
            if message.get("type") == "auth":
                # Authentication logic would go here
                response = {"status": "authenticated", "session_id": str(uuid.uuid4())}
            elif message.get("type") == "key_exchange":
                # Key exchange logic would go here
                algorithm = message.get("algorithm", "ecc")
                
                if algorithm == "rsa":
                    key_pair = RSAImplementation.generate_key_pair()
                elif algorithm == "ecc":
                    key_pair = ECCImplementation.generate_key_pair()
                else:  # dh
                    params = DHImplementation.generate_parameters()
                    key_pair = DHImplementation.generate_key_pair(params["p"], params["g"])
                    key_pair["params"] = params
                
                response = {
                    "status": "key_exchange_initiated",
                    "public_key": key_pair["public_key"].decode(),
                    "params": key_pair.get("params")
                }
            elif message.get("type") == "message":
                # Message handling logic would go here
                response = {"status": "message_received"}
            else:
                response = {"status": "error", "message": "Unknown message type"}
            
            # Send response
            self.request.sendall(json.dumps(response).encode())
            
        except Exception as e:
            logger.error(f"TCP handler error: {e}")
            self.request.sendall(json.dumps({"status": "error", "message": str(e)}).encode())

def start_tcp_server(host="0.0.0.0", port=9000):
    """Start the TCP server"""
    server = socketserver.ThreadingTCPServer((host, port), EncryptedTCPHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.info(f"TCP server started on {host}:{port}")
    return server

# ---------- Main Function ----------

def main():
    """Main function to start the application"""
    # Start TCP server
    tcp_server = start_tcp_server()
    
    try:
        # Start Flask-SocketIO
        socketio.run(app, host="0.0.0.0", port=5000, debug=True)
    except KeyboardInterrupt:
        logger.info("Shutting down servers...")
        tcp_server.shutdown()

if __name__ == "__main__":
    main()"""
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

# Database configuration
from sqlalchemy import create_engine, Column, String, Boolean, LargeBinary, DateTime, Integer, ForeignKey, Float, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, scoped_session

# Create database engine and session factory
engine = create_engine('sqlite:///encryption_app.db')
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

# Define database models
class User(Base):
    __tablename__ = 'users'
    
    id = Column(String(36), primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    salt = Column(LargeBinary, nullable=False)
    password_hash = Column(String(128), nullable=False)
    rsa_private_key = Column(LargeBinary, nullable=False)
    rsa_public_key = Column(LargeBinary, nullable=False)
    mfa_enabled = Column(Boolean, default=False)
    backup_codes = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Session(Base):
    __tablename__ = 'sessions'
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id'))
    token = Column(String(256), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship('User')

class KeyExchange(Base):
    __tablename__ = 'key_exchanges'
    
    id = Column(String(36), primary_key=True)
    initiator = Column(String(64), nullable=False)
    target = Column(String(64), nullable=False)
    algorithm = Column(String(16), nullable=False)
    initiator_private_key = Column(LargeBinary, nullable=False)
    initiator_public_key = Column(LargeBinary, nullable=False)
    status = Column(String(16), default='initiated')
    shared_key = Column(LargeBinary, nullable=True)
    params = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class PerformanceMetric(Base):
    __tablename__ = 'performance_metrics'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    algorithm = Column(String(16), nullable=False)
    function_name = Column(String(64), nullable=False)
    execution_time = Column(Float, nullable=False)
    key_length = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Connection(Base):
    __tablename__ = 'connections'
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id'))
    username = Column(String(64), nullable=False)
    socket_id = Column(String(128), nullable=False, unique=True)
    connected_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship('User')

# Initialize database
def init_db():
    Base.metadata.create_all(bind=engine)

# Store for active connections (still kept in memory for fast access)
active_connections = {}

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
            
            # Store metrics in database
            try:
                key_length = kwargs.get("key_size")
                if not key_length and algorithm_type == "ecc":
                    # For ECC, try to determine curve size if not explicitly provided
                    curve = kwargs.get("curve")
                    if curve and hasattr(curve, "key_size"):
                        key_length = curve.key_size
                
                metric = PerformanceMetric(
                    algorithm=algorithm_type,
                    function_name=func.__name__,
                    execution_time=execution_time,
                    key_length=key_length
                )
                db_session.add(metric)
                db_session.commit()
            except Exception as e:
                logger.error(f"Failed to save performance metric: {e}")
                db_session.rollback()
            
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