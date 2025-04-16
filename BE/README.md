"""
Integration Guide for Enhanced Security Components
This guide explains how to integrate PFS, HMAC, and Key Exchange in your end-to-end encryption application.
"""

# Integration Guide for Enhanced Security Components

## Introduction

This guide explains how to integrate the enhanced security components:
- Perfect Forward Secrecy (PFS)
- Hash-based Message Authentication Code (HMAC)
- Secure Key Exchange

## Directory Structure

Ensure your project has the following structure:

```
your_project/
├── pfs_manager.py           # Perfect Forward Secrecy implementation
├── hmac_manager.py          # HMAC implementation
├── key_exchange_manager.py  # Key Exchange implementation
├── crypto_service.py        # Integrated crypto service
├── main.py                  # Your FastAPI application
├── users_db.json            # User database (persistent)
└── user_keys.json           # User keys storage (persistent)
```

## Step 1: Install Required Dependencies

Ensure all required dependencies are installed:

```bash
pip install fastapi uvicorn cryptography python-jose pyjwt
```

## Step 2: Copy Component Files

Copy the following files to your project directory:
- `pfs_manager.py` (Perfect Forward Secrecy)
- `hmac_manager.py` (HMAC implementation)
- `key_exchange_manager.py` (Key Exchange implementation)
- `crypto_service.py` (Integrated crypto service)

## Step 3: Initialize Components in Your Application

In your FastAPI application, import and initialize the crypto service:

```python
from crypto_service import CryptoService
import atexit

# Initialize crypto service
crypto_service = CryptoService()

# Register cleanup function for proper shutdown
def cleanup_crypto_service():
    crypto_service.cleanup()

atexit.register(cleanup_crypto_service)
```

## Step 4: Add New API Endpoints

Add the following endpoints to your FastAPI application:

1. **PFS Session Creation**
```python
@app.post("/pfs/create")
async def create_pfs_session(request: PFSRequest, current_user: UserInDB = Depends(get_current_user)):
    """Create a new Perfect Forward Secrecy session"""
    session_id = f"{current_user.username}_{request.session_id}"
    pfs_info = crypto_service.create_pfs_session(
        session_id=session_id,
        algorithm=request.algorithm,
        key_size=request.key_size
    )
    return {
        "status": "success",
        "session_id": session_id,
        "algorithm": request.algorithm,
        "public_key": pfs_info["public_key"].decode() if isinstance(pfs_info["public_key"], bytes) else pfs_info["public_key"],
        "expires_at": pfs_info["expires_at"]
    }
```

2. **HMAC Session Creation**
```python
@app.post("/hmac/create")
async def create_hmac_session(request: HMACRequest, current_user: UserInDB = Depends(get_current_user)):
    """Create a new HMAC session"""
    session_id = f"{current_user.username}_{request.session_id}"
    crypto_service.create_hmac_session(
        session_id=session_id,
        key_size=request.key_size
    )
    return {
        "status": "success",
        "session_id": session_id,
        "key_size": request.key_size
    }
```

3. **Key Exchange Initiation**
```python
@app.post("/key-exchange/initiate")
async def initiate_key_exchange(request: KeyExchangeInitiate, current_user: UserInDB = Depends(get_current_user)):
    """Initiate a key exchange with another user"""
    exchange_info = crypto_service.initiate_key_exchange(
        initiator=current_user.username,
        target=request.target,
        algorithm=request.algorithm,
        key_size=request.key_size
    )
    return {
        "status": "success",
        "exchange_id": exchange_info["exchange_id"],
        "algorithm": request.algorithm,
        "public_key": exchange_info["public_key"].decode() if isinstance(exchange_info["public_key"], bytes) else exchange_info["public_key"],
        "params": exchange_info.get("params")
    }
```

4. **Key Exchange Completion**
```python
@app.post("/key-exchange/complete")
async def complete_key_exchange(request: KeyExchangeComplete, current_user: UserInDB = Depends(get_current_user)):
    """Complete a key exchange initiated by another user"""
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
```

## Step 5: Enhance WebSocket Messaging

Update your WebSocket handler to integrate PFS and HMAC:

```python
@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    # Authentication code...
    
    # Create a secure session with PFS and HMAC
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
            
            # Handle different message types
            message_type = message_data.get("type", "message")
            
            if message_type == "pfs_rotation":
                # Handle PFS key rotation
                algorithm = message_data.get("algorithm", "ecc")
                pfs_info = crypto_service.create_pfs_session(session_id, algorithm)
                await websocket.send_json({
                    "type": "pfs_update",
                    "algorithm": algorithm,
                    "public_key": pfs_info["public_key"].decode() if isinstance(pfs_info["public_key"], bytes) else pfs_info["public_key"],
                    "expires_at": pfs_info["expires_at"]
                })
                continue
            
            # Handle regular message with HMAC verification
            recipient = message_data.get("recipient")
            content = message_data.get("content")
            signature = message_data.get("signature")
            
            # Verify signature if provided
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
            
            # Forward the message to recipient with HMAC...
    except WebSocketDisconnect:
        manager.disconnect(username)
```

## Step 6: Connection Manager Enhancements

Update your `ConnectionManager` class to handle secure sessions:

```python
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.secure_sessions: Dict[str, Dict[str, str]] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        
        # Create secure session
        session_id = f"{user_id}_{uuid.uuid4()}"
        
        # Create PFS session
        pfs_info = crypto_service.create_pfs_session(session_id, algorithm="ecc")
        
        # Create HMAC session
        hmac_key = crypto_service.create_hmac_session(session_id)
        
        # Store session info
        self.secure_sessions[user_id] = {
            "session_id": session_id,
            "pfs_algorithm": "ecc",
            "hmac_key_size": len(hmac_key)
        }
        
        # Send session info to client
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
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        
        # Clean up secure session
        if user_id in self.secure_sessions:
            del self.secure_sessions[user_id]

    def get_session_id(self, user_id: str) -> Optional[str]:
        """Get the secure session ID for a user"""
        if user_id in self.secure_sessions:
            return self.secure_sessions[user_id]["session_id"]
        return None
```

## Step 7: Client-Side Integration

On the client side, implement the following:

1. **Store session information** received from the server
2. **Rotate PFS keys periodically** by sending a PFS rotation request
3. **Sign messages with HMAC** before sending
4. **Verify HMAC signatures** on received messages

Example client-side code for PFS key rotation:

```javascript
// Request PFS key rotation every 5 minutes
setInterval(() => {
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({
            type: "pfs_rotation",
            algorithm: "ecc"
        }));
    }
}, 5 * 60 * 1000);
```

## Step 8: Testing

Test the implementation with these scenarios:

1. **Session Establishment**: Verify PFS and HMAC sessions are created on connection
2. **Key Rotation**: Test regular rotation of PFS keys
3. **Message Authentication**: Verify HMAC signatures are working correctly
4. **Key Exchange**: Test secure key exchange between users

## Security Considerations

1. **Key Storage**: Secure the storage of cryptographic keys
2. **Rotation Intervals**: Set appropriate key rotation intervals based on your security requirements
3. **Error Handling**: Implement robust error handling for cryptographic operations
4. **Session Management**: Properly manage and clean up expired sessions

## Conclusion

By integrating these enhanced security components, your end-to-end encryption application now has:

1. **Perfect Forward Secrecy** through regular key rotation
2. **Message Authentication** through HMAC signatures
3. **Secure Key Exchange** for initial key establishment

These mechanisms significantly improve the security of your encrypted communication channel against various attacks.