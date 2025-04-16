"""
main.py - FastAPI Application with Enhanced Security Components

This is the main application file that integrates the enhanced security components
(PFS, HMAC, and Key Exchange) into a FastAPI application for end-to-end encrypted chat.
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import json
import asyncio
import uuid
import jwt
from datetime import datetime, timedelta
import os
import secrets
import logging
import atexit
import base64
import uvicorn


# Import our enhanced security components
from pfs_manager import PFSManager
from hmac_manager import HMACManager
from key_exchange_manager import KeyExchangeManager
from crypto_service import CryptoService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="End-to-End Encrypted Chat with Enhanced Security")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print(f"WARNING: Generated temporary secret key: {SECRET_KEY[:5]}...{SECRET_KEY[-5:]}")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# File path for user database
USER_DB_FILE = "users_db.json"
USER_KEYS_FILE = "user_keys.json"

# Initialize crypto service
crypto_service = CryptoService()

# Register cleanup function to be called on application shutdown
def cleanup_crypto_service():
    """Clean up crypto service resources on shutdown"""
    crypto_service.cleanup()
    logger.info("Crypto service resources cleaned up")

atexit.register(cleanup_crypto_service)

# Models
class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    username: str
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class Message(BaseModel):
    recipient: str
    content: Dict
    algorithm: str

class KeyExchange(BaseModel):
    username: str
    algorithm: str
    public_key: str
    parameters: Optional[str] = None

class PFSRequest(BaseModel):
    session_id: str
    algorithm: str = "ecc"
    key_size: Optional[int] = None

class HMACRequest(BaseModel):
    session_id: str
    key_size: Optional[int] = 32

class KeyExchangeInitiate(BaseModel):
    target: str
    algorithm: str = "ecc"
    key_size: Optional[int] = None

class KeyExchangeComplete(BaseModel):
    exchange_id: str
    public_key: str

# Helper functions for user database
def load_users_db() -> Dict[str, Any]:
    """Load users from JSON file"""
    if not os.path.exists(USER_DB_FILE):
        # Create empty database if file doesn't exist
        with open(USER_DB_FILE, 'w') as f:
            json.dump({}, f)
        return {}
    
    try:
        with open(USER_DB_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        # Handle corrupted file
        return {}

def save_users_db(users_db: Dict[str, Any]) -> None:
    """Save users to JSON file"""
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users_db, f, indent=4)

def load_user_keys() -> Dict[str, Any]:
    """Load user keys from JSON file"""
    if not os.path.exists(USER_KEYS_FILE):
        with open(USER_KEYS_FILE, 'w') as f:
            json.dump({}, f)
        return {}
    
    try:
        with open(USER_KEYS_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_user_keys(user_keys: Dict[str, Any]) -> None:
    """Save user keys to JSON file"""
    with open(USER_KEYS_FILE, 'w') as f:
        json.dump(user_keys, f, indent=4)

# Authentication functions
def get_password_hash(password: str) -> str:
    """Hash a password - in production, use a secure password hashing library"""
    # This is a placeholder - use bcrypt or similar in production
    return f"hashed_{password}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    # This is a placeholder - use bcrypt or similar in production
    return hashed_password == f"hashed_{plain_password}"

def get_user(username: str) -> Optional[UserInDB]:
    """Get a user from the database"""
    users_db = load_users_db()
    
    if username in users_db:
        user_data = users_db[username]
        # Ensure password field is present for BaseModel
        if "password" not in user_data and "hashed_password" in user_data:
            user_data["password"] = ""
        return UserInDB(**user_data)
    return None

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate a user"""
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """Verify token and get current user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError as e:
        logger.error(f"Token verification failed: {e}")
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# WebSocket connection manager
class ConnectionManager:
    """
    Manages WebSocket connections and secure sessions
    """
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.secure_sessions: Dict[str, Dict[str, str]] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        """Connect a new WebSocket and set up security"""
        await websocket.accept()
        self.active_connections[user_id] = websocket
        
        # Create a unique session ID for this connection
        session_id = f"{user_id}_{uuid.uuid4()}"
        
        # Initialize a PFS session for this connection
        pfs_info = crypto_service.create_pfs_session(session_id, algorithm="ecc")
        
        # Create an HMAC session for this connection
        hmac_key = crypto_service.create_hmac_session(session_id)
        
        # Store session information
        self.secure_sessions[user_id] = {
            "session_id": session_id,
            "pfs_algorithm": "ecc",
            "hmac_key_size": len(hmac_key)
        }
        
        logger.info(f"Secure session created for user {user_id}: {session_id}")
        
        # Send session information to client
        await websocket.send_json({
            "type": "session_info",
            "session_id": session_id,
            "pfs": {
                "algorithm": "ecc",
                "public_key": pfs_info["public_key"].decode() if isinstance(pfs_info["public_key"], bytes) else pfs_info["public_key"],
                "expires_at": pfs_info["expires_at"]
            }
        })

    def disconnect(self, user_id: str):
        """Disconnect WebSocket and clean up session"""
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        
        # Clean up secure session
        if user_id in self.secure_sessions:
            del self.secure_sessions[user_id]

    async def send_personal_message(self, message: str, user_id: str):
        """Send a message to a specific user"""
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)

    async def broadcast(self, message: str, exclude: Optional[str] = None):
        """Broadcast a message to all users except the excluded one"""
        for user_id, connection in self.active_connections.items():
            if exclude is None or user_id != exclude:
                await connection.send_text(message)

    def get_session_id(self, user_id: str) -> Optional[str]:
        """Get the secure session ID for a user"""
        if user_id in self.secure_sessions:
            return self.secure_sessions[user_id]["session_id"]
        return None

# Create connection manager instance
manager = ConnectionManager()

# API Routes
@app.post("/register", response_model=Token)
async def register_user(user: User):
    """Register a new user"""
    users_db = load_users_db()
    if user.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    hashed_password = get_password_hash(user.password)
    users_db[user.username] = {
        "username": user.username,
        "hashed_password": hashed_password
    }

    save_users_db(users_db)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and get access token"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    """Get current user information"""
    return {"username": current_user.username}

@app.post("/key-exchange")
async def exchange_keys(key_data: KeyExchange, current_user: UserInDB = Depends(get_current_user)):
    """
    Handle key exchange between users - legacy endpoint
    """
    if current_user.username != key_data.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only submit keys for yourself"
        )
    
    user_keys = load_user_keys()

    # Store user's public key
    if key_data.username not in user_keys:
        user_keys[key_data.username] = {}
    
    user_keys[key_data.username][key_data.algorithm] = {
        "public_key": key_data.public_key,
        "parameters": key_data.parameters,
        "timestamp": datetime.utcnow().isoformat()
    }

    save_user_keys(user_keys)
    
    return {"status": "success", "message": "Public key registered"}

@app.get("/users/{username}/public-key/{algorithm}")
async def get_public_key(username: str, algorithm: str, current_user: UserInDB = Depends(get_current_user)):
    """
    Retrieve public key for a specific user and algorithm
    """
    user_keys = load_user_keys()
    if username not in user_keys or algorithm not in user_keys[username]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Public key not found for user {username} with algorithm {algorithm}"
        )
    
    return user_keys[username][algorithm]

# New endpoints for enhanced security components

@app.post("/pfs/create")
async def create_pfs_session(request: PFSRequest, current_user: UserInDB = Depends(get_current_user)):
    """
    Create a new Perfect Forward Secrecy session
    """
    try:
        # Create a session ID that includes the username for authorization purposes
        session_id = f"{current_user.username}_{request.session_id}"
        
        # Create PFS session
        pfs_info = crypto_service.create_pfs_session(
            session_id=session_id,
            algorithm=request.algorithm,
            key_size=request.key_size
        )
        
        # Convert the public key to string if it's bytes
        if isinstance(pfs_info["public_key"], bytes):
            pfs_info["public_key"] = pfs_info["public_key"].decode()
        
        return {
            "status": "success",
            "session_id": session_id,
            "algorithm": request.algorithm,
            "public_key": pfs_info["public_key"],
            "expires_at": pfs_info["expires_at"]
        }
        
    except Exception as e:
        logger.error(f"Error creating PFS session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating PFS session: {str(e)}"
        )

@app.get("/pfs/info/{session_id}")
async def get_pfs_session_info(session_id: str, current_user: UserInDB = Depends(get_current_user)):
    """
    Get information about a PFS session
    """
    # Verify that the session belongs to the current user
    if not session_id.startswith(f"{current_user.username}_"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this session"
        )
    
    # Get session info
    session_info = crypto_service.pfs_manager.get_session_info(session_id)
    
    if not session_info["exists"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return session_info

@app.post("/hmac/create")
async def create_hmac_session(request: HMACRequest, current_user: UserInDB = Depends(get_current_user)):
    """
    Create a new HMAC session
    """
    try:
        # Create a session ID that includes the username for authorization purposes
        session_id = f"{current_user.username}_{request.session_id}"
        
        # Create HMAC session
        crypto_service.create_hmac_session(
            session_id=session_id,
            key_size=request.key_size
        )
        
        return {
            "status": "success",
            "session_id": session_id,
            "key_size": request.key_size
        }
        
    except Exception as e:
        logger.error(f"Error creating HMAC session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating HMAC session: {str(e)}"
        )

@app.post("/key-exchange/initiate")
async def initiate_key_exchange(request: KeyExchangeInitiate, current_user: UserInDB = Depends(get_current_user)):
    """
    Initiate a key exchange with another user
    """
    try:
        # Initiate key exchange
        exchange_info = crypto_service.initiate_key_exchange(
            initiator=current_user.username,
            target=request.target,
            algorithm=request.algorithm,
            key_size=request.key_size
        )
        
        # Convert the public key to string if it's bytes
        if isinstance(exchange_info["public_key"], bytes):
            exchange_info["public_key"] = exchange_info["public_key"].decode()
        
        return {
            "status": "success",
            "exchange_id": exchange_info["exchange_id"],
            "algorithm": request.algorithm,
            "public_key": exchange_info["public_key"],
            "params": exchange_info.get("params")
        }
        
    except Exception as e:
        logger.error(f"Error initiating key exchange: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error initiating key exchange: {str(e)}"
        )

@app.post("/key-exchange/complete")
async def complete_key_exchange(request: KeyExchangeComplete, current_user: UserInDB = Depends(get_current_user)):
    """
    Complete a key exchange initiated by another user
    """
    try:
        # Complete key exchange
        result = crypto_service.complete_key_exchange(
            exchange_id=request.exchange_id,
            responder=current_user.username,
            public_key=request.public_key
        )
        
        return {
            "status": "success",
            "exchange_id": request.exchange_id,
            "shared_key_generated": result["shared_key_generated"]
        }
        
    except Exception as e:
        logger.error(f"Error completing key exchange: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error completing key exchange: {str(e)}"
        )

@app.get("/benchmark")
async def run_benchmark(current_user: UserInDB = Depends(get_current_user)):
    """
    Run benchmark for all supported algorithms
    """
    # Define message sizes for benchmarking
    message_sizes = [64, 1024, 16384, 65536]  # bytes
    iterations = 5
    
    # Run benchmark
    results = crypto_service.benchmark(message_sizes, iterations)
    
    return results

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """WebSocket endpoint for realtime communication"""
    # Verify token from query parameter
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_username = payload.get("sub")
        if token_username != username:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except jwt.PyJWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await manager.connect(websocket, username)
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Get the session ID for this user
            session_id = manager.get_session_id(username)
            if not session_id:
                await websocket.send_json({
                    "error": "No secure session established"
                })
                continue
            
            message_type = message_data.get("type", "message")
            
            if message_type == "pfs_rotation":
                # Handle PFS key rotation request
                algorithm = message_data.get("algorithm", "ecc")
                pfs_info = crypto_service.create_pfs_session(session_id, algorithm)
                
                # Send new public key to client
                await websocket.send_json({
                    "type": "pfs_update",
                    "algorithm": algorithm,
                    "public_key": pfs_info["public_key"].decode() if isinstance(pfs_info["public_key"], bytes) else pfs_info["public_key"],
                    "expires_at": pfs_info["expires_at"]
                })
                continue
                
            recipient = message_data.get("recipient")
            content = message_data.get("content")
            algorithm = message_data.get("algorithm")
            signature = message_data.get("signature")

            print("sss", message_data)
            
            # Verify HMAC signature if provided
            if signature:
                is_valid = crypto_service.verify_message(
                    {
                        "message": content,
                        "signature": signature
                    },
                    session_id
                )
                
                if not is_valid:
                    await websocket.send_json({
                        "error": "Invalid message signature"
                    })
                    continue
            
            # Forward encrypted message to recipient
            if recipient in manager.active_connections:
                recipient_session_id = manager.get_session_id(recipient)
                
                # Add HMAC signature to the message using recipient's session
                if recipient_session_id:
                    # Convert content to bytes if it's a string
                    if isinstance(content, str):
                        content_bytes = content.encode()
                    elif isinstance(content, dict):
                        content_bytes = json.dumps(content).encode()
                    else:
                        content_bytes = base64.b64decode(content)
                    
                    # Sign the message
                    signed_message = crypto_service.sign_message(content_bytes, recipient_session_id)
                    
                    forward_message = {
                        "type": "message",
                        "sender": username,
                        "content": signed_message["message"],
                        "signature": signed_message["signature"],
                        "algorithm": algorithm,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    await manager.send_personal_message(
                        json.dumps(forward_message), 
                        recipient
                    )
                else:
                    # Recipient doesn't have a secure session
                    forward_message = {
                        "type": "message",
                        "sender": username,
                        "content": content,
                        "algorithm": algorithm,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    await manager.send_personal_message(
                        json.dumps(forward_message), 
                        recipient
                    )
            else:
                # Recipient not online, store message for later delivery
                # In a real application, you would persist this message
                await manager.send_personal_message(
                    json.dumps({
                        "type": "error",
                        "error": "Recipient not online",
                        "recipient": recipient
                    }),
                    username
                )
    
    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(username)

if __name__ == "__main__":
    # Load user keys and database
    load_user_keys()
    load_users_db()
    
    # Start the server
    uvicorn.run(app, host="0.0.0.0", port=8000)