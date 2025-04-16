import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../context/AuthContext.tsx';
import EncryptionSelector from '../EncryptionSelector/EncryptionSelector.tsx';
import MessageList from '../MessageList/MessageList.tsx';
import { encryptMessage, decryptMessage, generateKeyPair } from '../../services/crypto';

const Chat = () => {
  const { user, token } = useAuth();
  const [messages, setMessages] = useState([]);
  const [recipient, setRecipient] = useState('');
  const [messageText, setMessageText] = useState('');
  const [encryptionAlgorithm, setEncryptionAlgorithm] = useState('RSA-2048');
  const [keyPairs, setKeyPairs] = useState({});
  const [peerKeys, setPeerKeys] = useState({});
  const [isConnected, setIsConnected] = useState(false);
  const [selectedRecipient, setSelectedRecipient] = useState(null);
  const [receivedMessages, setReceivedMessages] = useState({});
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [benchmarkResults, setBenchmarkResults] = useState(null);
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  
  // New state for enhanced security features
  const [sessionInfo, setSessionInfo] = useState(null);
  const [securityStatus, setSecurityStatus] = useState({
    pfsActive: false,
    hmacActive: false,
    keyExchangeActive: false
  });
  
  const wsRef = useRef(null);
  const pfsRotationTimerRef = useRef(null);
  
  // Connect to WebSocket
  useEffect(() => {
    if (user && token) {
      const ws = new WebSocket(`ws://localhost:8000/ws/${user.username}?token=${token}`);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setIsConnected(true);
      };
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('WebSocket message received:', data);
        
        // Handle session information (PFS setup)
        if (data.type === 'session_info') {
          handleSessionInfo(data);
          return;
        }
        
        // Handle PFS key rotation updates
        if (data.type === 'pfs_update') {
          handlePFSUpdate(data);
          return;
        }
        
        // Handle regular messages
        if (data.sender || data.type === 'message') {
          handleIncomingMessage(data);
        } else if (data.error) {
          console.error('Error:', data.error);
        }
      };
      
      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setIsConnected(false);
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
      
      wsRef.current = ws;
      
      // Set up PFS key rotation timer
      setupPFSRotationTimer();
      
      return () => {
        ws.close();
        clearPFSRotationTimer();
      };
    }
  }, [user, token]);
  
  // Generate key pairs for each algorithm when component mounts
  useEffect(() => {
    if (user) {
      generateAllKeyPairs();
    }
  }, [user]);
  
  // Handle PFS session information
  const handleSessionInfo = (data) => {
    console.log('Session info received:', data);
    setSessionInfo(data);
    
    // Update security status
    setSecurityStatus(prev => ({
      ...prev,
      pfsActive: true,
      hmacActive: true
    }));
  };
  
  // Handle PFS key rotation updates
  const handlePFSUpdate = (data) => {
    console.log('PFS update received:', data);
    
    // Update session information with new PFS public key
    setSessionInfo(prev => {
      if (!prev) return data;
      
      return {
        ...prev,
        pfs: {
          algorithm: data.algorithm,
          public_key: data.public_key,
          expires_at: data.expires_at
        }
      };
    });
    
    // Show a system message about key rotation
    const systemMessage = {
      sender: 'System',
      recipient: user.username,
      content: 'Perfect Forward Secrecy keys have been rotated',
      timestamp: new Date().toISOString(),
      status: 'system'
    };
    
    setMessages(prev => [...prev, systemMessage]);
  };
  
  // Set up PFS key rotation timer
  const setupPFSRotationTimer = () => {
    // Request key rotation every 4.5 minutes (slightly less than the 5-minute server rotation)
    pfsRotationTimerRef.current = setInterval(() => {
      requestPFSKeyRotation();
    }, 4.5 * 60 * 1000);
  };
  
  // Clear PFS rotation timer
  const clearPFSRotationTimer = () => {
    if (pfsRotationTimerRef.current) {
      clearInterval(pfsRotationTimerRef.current);
    }
  };
  
  // Request PFS key rotation
  const requestPFSKeyRotation = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      console.log('Requesting PFS key rotation');
      wsRef.current.send(JSON.stringify({
        type: 'pfs_rotation',
        algorithm: 'ecc' // Using ECC for PFS by default
      }));
    }
  };
  
  // Manual PFS key rotation (for testing)
  const manualKeyRotation = () => {
    requestPFSKeyRotation();
  };
  
  const generateAllKeyPairs = async () => {
    setIsGeneratingKeys(true);
    
    try {
      const algorithms = [
        'RSA-2048', 'RSA-3072', 'RSA-4096', 
        'ECC-256', 'ECC-384', 'ECC-521',
        'DH-2048', 'DH-3072', 'DH-4096'
      ];
      
      const newKeyPairs = {};
      
      for (const algo of algorithms) {
        const keyPair = await generateKeyPair(algo);
        newKeyPairs[algo] = keyPair;
        
        // Register public key with the server
        await registerPublicKey(algo, keyPair);
      }
      
      setKeyPairs(newKeyPairs);
    } catch (error) {
      console.error('Error generating key pairs:', error);
    } finally {
      setIsGeneratingKeys(false);
    }
  };
  
  const registerPublicKey = async (algorithm, keyPair) => {
    try {
      const response = await fetch('http://localhost:8000/key-exchange', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          username: user.username,
          algorithm: algorithm,
          public_key: keyPair.publicKey,
          parameters: keyPair.parameters || null
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to register public key');
      }
    } catch (error) {
      console.error('Error registering public key:', error);
    }
  };
  
  // Initiate key exchange with another user
  const initiateKeyExchange = async (targetUsername) => {
    try {
      const response = await fetch('http://localhost:8000/key-exchange/initiate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          target: targetUsername,
          algorithm: 'ecc' // Using ECC for key exchange by default
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to initiate key exchange');
      }
      
      const data = await response.json();
      
      // Update security status
      setSecurityStatus(prev => ({
        ...prev,
        keyExchangeActive: true
      }));
      
      // Show a system message about key exchange
      const systemMessage = {
        sender: 'System',
        recipient: user.username,
        content: `Secure key exchange initiated with ${targetUsername}`,
        timestamp: new Date().toISOString(),
        status: 'system'
      };
      
      setMessages(prev => [...prev, systemMessage]);
      
      return data;
    } catch (error) {
      console.error('Error initiating key exchange:', error);
      return null;
    }
  };
  
  const fetchPeerPublicKey = async (username, algorithm) => {
    try {
      const algoBase = algorithm.split('-')[0];
      const response = await fetch(`http://localhost:8000/users/${username}/public-key/${algorithm}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch peer public key');
      }
      
      const keyData = await response.json();
      
      if (!peerKeys[username]) {
        setPeerKeys(prev => ({ ...prev, [username]: {} }));
      }
      
      setPeerKeys(prev => ({
        ...prev,
        [username]: {
          ...prev[username],
          [algorithm]: keyData
        }
      }));
      
      return keyData;
    } catch (error) {
      console.error('Error fetching peer public key:', error);
      return null;
    }
  };
  
  const handleSendMessage = async (e) => {
    e.preventDefault();
    
    if (!messageText.trim() || !selectedRecipient) return;
    
    try {
      // Make sure we have the recipient's public key
      let peerKey = peerKeys[selectedRecipient]?.[encryptionAlgorithm];
      
      if (!peerKey) {
        peerKey = await fetchPeerPublicKey(selectedRecipient, encryptionAlgorithm);
        if (!peerKey) {
          throw new Error(`Could not get public key for ${selectedRecipient}`);
        }
      }
      
      // Encrypt the message using the user-selected algorithm
      const encrypted = await encryptMessage(
        messageText, 
        peerKey.public_key, 
        encryptionAlgorithm, 
        keyPairs[encryptionAlgorithm],
        peerKey.parameters
      );
      
      // Send the encrypted message via WebSocket
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          recipient: selectedRecipient,
          content: encrypted,
          algorithm: encryptionAlgorithm
        }));
        
        // Add to local messages
        const newMessage = {
          sender: user.username,
          recipient: selectedRecipient,
          content: messageText, // Store plain text for display
          algorithm: encryptionAlgorithm,
          timestamp: new Date().toISOString(),
          status: 'sent'
        };
        
        setMessages(prev => [...prev, newMessage]);
        
        // Update conversation
        updateConversation(selectedRecipient, newMessage);
        
        // Clear message input
        setMessageText('');
      } else {
        throw new Error('WebSocket not connected');
      }
    } catch (error) {
      console.error('Error sending message:', error);
      alert(`Error sending message: ${error.message}`);
    }
  };
  
  const handleIncomingMessage = async (data) => {
    try {
      const { sender, content, algorithm, timestamp, signature, type } = data;
      
      // Create a message object
      let newMessage;
      
      // For HMAC-verified messages
      if (signature) {
        console.log('Received HMAC-verified message');
        
        // For messages that already include HMAC verification
        let decryptedContent;
        
        try {
          // If content is base64-encoded
          const contentBytes = typeof content === 'string' ? 
            atob(content) : 
            content;
          
          decryptedContent = contentBytes;
        } catch (e) {
          // If decoding fails, use as is
          decryptedContent = content;
        }
        
        newMessage = {
          sender,
          recipient: user.username,
          content: decryptedContent,
          algorithm: algorithm || 'pfs-hmac',
          timestamp: timestamp || new Date().toISOString(),
          status: 'received',
          authenticated: true // Mark as HMAC-authenticated
        };
      } else {
        // For regular messages using the old encryption method
        const algoBase = algorithm.split('-')[0];
        const keyPair = keyPairs[algorithm];
        
        if (!keyPair) {
          throw new Error(`No key pair found for algorithm ${algorithm}`);
        }
        
        let decrypted;
        
        // For DH, we need to establish a shared secret
        if (algoBase === 'DH') {
          // Make sure we have the sender's public key
          let senderPublicKey = peerKeys[sender]?.[algorithm]?.public_key;
          
          if (!senderPublicKey) {
            const keyData = await fetchPeerPublicKey(sender, algorithm);
            senderPublicKey = keyData.public_key;
          }
          
          // Use the shared secret to decrypt
          decrypted = await decryptMessage(
            content,
            keyPair.privateKey,
            algorithm,
            senderPublicKey
          );
        } else {
          // For RSA and ECC
          decrypted = await decryptMessage(
            content,
            keyPair.privateKey,
            algorithm
          );
        }
        
        newMessage = {
          sender,
          recipient: user.username,
          content: decrypted, // Decrypted content
          algorithm,
          timestamp: timestamp || new Date().toISOString(),
          status: 'received'
        };
      }
      
      // Add to messages
      setMessages(prev => [...prev, newMessage]);
      
      // Update conversation
      updateConversation(sender, newMessage);
      
    } catch (error) {
      console.error('Error processing incoming message:', error);
    }
  };
  
  const updateConversation = (contactUsername, message) => {
    setReceivedMessages(prev => {
      const existing = prev[contactUsername] || [];
      return {
        ...prev,
        [contactUsername]: [...existing, message]
      };
    });
  };
  
  const selectRecipient = (username) => {
    setSelectedRecipient(username);
    
    // Initiate key exchange when selecting a new recipient
    if (!securityStatus.keyExchangeActive) {
      initiateKeyExchange(username);
    }
  };
  
  const handleBenchmark = async () => {
    setIsBenchmarking(true);
    try {
      const response = await fetch('http://localhost:8000/benchmark', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Benchmark failed');
      }
      
      const results = await response.json();
      setBenchmarkResults(results);
    } catch (error) {
      console.error('Error during benchmark:', error);
    } finally {
      setIsBenchmarking(false);
    }
  };

  // Get security status
  const getSecurityStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/security/status', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        return;
      }
      
      const status = await response.json();
      console.log('Security status:', status);
      
      // Update security status
      setSecurityStatus({
        pfsActive: status.has_active_session && Object.keys(status.pfs).length > 0,
        hmacActive: status.has_active_session && status.hmac?.active,
        keyExchangeActive: status.key_exchanges.length > 0
      });
    } catch (error) {
      console.error('Error getting security status:', error);
    }
  };
  
  return (
    <div className="flex flex-col h-screen">
      <div className="bg-gray-800 text-white p-4">
        <div className="container mx-auto flex justify-between items-center">
          <h1 className="text-xl font-bold">E2E Encrypted Chat</h1>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <span className={`w-3 h-3 rounded-full ${securityStatus.pfsActive ? 'bg-green-400' : 'bg-red-400'}`}></span>
              <span className="text-xs">PFS</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`w-3 h-3 rounded-full ${securityStatus.hmacActive ? 'bg-green-400' : 'bg-red-400'}`}></span>
              <span className="text-xs">HMAC</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`w-3 h-3 rounded-full ${securityStatus.keyExchangeActive ? 'bg-green-400' : 'bg-red-400'}`}></span>
              <span className="text-xs">Key Exchange</span>
            </div>
            <span className="mx-2">|</span>
            <span className="mr-2">
              {isConnected ? (
                <span className="text-green-400">●</span>
              ) : (
                <span className="text-red-400">●</span>
              )}
              {isConnected ? ' Connected' : ' Disconnected'}
            </span>
            <span className="font-medium">{user?.username}</span>
          </div>
        </div>
      </div>
      
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <div className="w-1/4 bg-gray-100 p-4 border-r">
          <div className="mb-4">
            <h2 className="font-bold mb-2">Encryption Settings</h2>
            <EncryptionSelector 
              selectedAlgorithm={encryptionAlgorithm}
              onChange={setEncryptionAlgorithm} 
            />
            <div className="mt-4 space-y-2">
              <button 
                className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 w-full"
                onClick={generateAllKeyPairs}
                disabled={isGeneratingKeys}
              >
                {isGeneratingKeys ? 'Generating Keys...' : 'Regenerate Keys'}
              </button>
              
              <button 
                className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 w-full"
                onClick={manualKeyRotation}
                disabled={!isConnected}
              >
                Rotate PFS Keys
              </button>
            </div>
          </div>
          
          <h2 className="font-bold mb-2">Contacts</h2>
          <div className="mb-4">
            <div className="flex">
              <input
                type="text"
                className="flex-1 p-2 border rounded-l"
                placeholder="Username"
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
              />
              <button
                className="bg-green-500 text-white px-4 py-2 rounded-r hover:bg-green-600"
                onClick={() => {
                  if (recipient && recipient !== user.username) {
                    selectRecipient(recipient);
                    if (!receivedMessages[recipient]) {
                      setReceivedMessages(prev => ({
                        ...prev,
                        [recipient]: []
                      }));
                    }
                  }
                }}
              >
                Chat
              </button>
            </div>
          </div>
          
          <div className="overflow-y-auto max-h-64">
            {Object.keys(receivedMessages).map((username) => (
              <div 
                key={username}
                className={`p-2 mb-1 rounded cursor-pointer ${
                  selectedRecipient === username ? 'bg-blue-100' : 'hover:bg-gray-200'
                }`}
                onClick={() => selectRecipient(username)}
              >
                <div className="font-medium">{username}</div>
                <div className="text-sm text-gray-500 truncate">
                  {receivedMessages[username].length > 0
                    ? `${receivedMessages[username][receivedMessages[username].length - 1].content.substring(0, 30)}...`
                    : 'No messages yet'}
                </div>
              </div>
            ))}
          </div>
          
          <div className="mt-4">
            <h2 className="font-bold mb-2">Performance</h2>
            <button
              className="bg-purple-500 text-white px-4 py-2 rounded hover:bg-purple-600 w-full"
              onClick={handleBenchmark}
              disabled={isBenchmarking}
            >
              {isBenchmarking ? 'Running Benchmark...' : 'Run Benchmark'}
            </button>
          </div>
        </div>
        
        {/* Main Chat Area */}
        <div className="flex-1 flex flex-col">
          {selectedRecipient ? (
            <>
              <div className="bg-gray-200 p-3 border-b">
                <div className="font-medium">{selectedRecipient}</div>
                <div className="text-xs text-gray-500 flex items-center">
                  <span>Using {encryptionAlgorithm} encryption</span>
                  {securityStatus.pfsActive && (
                    <span className="ml-2 px-2 py-0.5 bg-green-100 text-green-800 rounded-full text-xs">
                      PFS Active
                    </span>
                  )}
                  {securityStatus.hmacActive && (
                    <span className="ml-2 px-2 py-0.5 bg-green-100 text-green-800 rounded-full text-xs">
                      HMAC Active
                    </span>
                  )}
                </div>
              </div>
              
              <div className="flex-1 overflow-y-auto p-4">
                <MessageList 
                  messages={messages.filter(msg => 
                    (msg.sender === user.username && msg.recipient === selectedRecipient) ||
                    (msg.sender === selectedRecipient && msg.recipient === user.username) ||
                    (msg.status === 'system')
                  )}
                  currentUser={user.username}
                />
              </div>
              
              <div className="p-4 border-t">
                <form onSubmit={handleSendMessage}>
                  <div className="flex">
                    <input
                      type="text"
                      className="flex-1 p-2 border rounded-l"
                      placeholder="Type a message..."
                      value={messageText}
                      onChange={(e) => setMessageText(e.target.value)}
                    />
                    <button
                      type="submit"
                      className="bg-blue-500 text-white px-4 py-2 rounded-r hover:bg-blue-600"
                      disabled={!isConnected}
                    >
                      Send
                    </button>
                  </div>
                </form>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-gray-400">
              Select a contact to start chatting
            </div>
          )}
        </div>
        
        {/* Benchmark Results Panel */}
        {benchmarkResults && (
          <div className="w-1/3 bg-gray-100 p-4 border-l overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h2 className="font-bold">Benchmark Results</h2>
              <button
                className="text-gray-500 hover:text-gray-700"
                onClick={() => setBenchmarkResults(null)}
              >
                ×
              </button>
            </div>
            
            {/* Display different sections of benchmark results */}
            <div>
              {/* Encryption benchmark results */}
              {benchmarkResults.encryption && (
                <div className="mb-6">
                  <h3 className="font-bold text-lg">Encryption</h3>
                  {Object.entries(benchmarkResults.encryption).map(([algo, data]) => (
                    <div key={algo} className="mb-4 border-b pb-2">
                      <h4 className="font-medium">{algo}</h4>
                      {Object.entries(data).map(([sizeKey, metrics]) => (
                        <div key={sizeKey} className="text-sm">
                          <div className="bg-gray-200 p-1 mt-1">Size: {metrics.key_size}/{metrics.message_size} bytes</div>
                          <div className="grid grid-cols-2 gap-x-2 text-xs p-1">
                            <div>Encrypt: {metrics.encryption_time_ms.toFixed(2)} ms</div>
                            <div>Decrypt: {metrics.decryption_time_ms.toFixed(2)} ms</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              )}
              
              {/* Key exchange benchmark results */}
              {benchmarkResults.key_exchange && (
                <div className="mb-6">
                  <h3 className="font-bold text-lg">Key Exchange</h3>
                  {Object.entries(benchmarkResults.key_exchange).map(([algo, data]) => (
                    <div key={algo} className="text-sm mb-2">
                      <div>{algo}: {data.time_ms.toFixed(2)} ms</div>
                    </div>
                  ))}
                </div>
              )}
              
              {/* HMAC benchmark results */}
              {benchmarkResults.hmac && (
                <div className="mb-6">
                  <h3 className="font-bold text-lg">HMAC</h3>
                  {Object.entries(benchmarkResults.hmac).map(([size, data]) => (
                    <div key={size} className="text-sm mb-2">
                      <div>Message size: {size} bytes</div>
                      <div className="grid grid-cols-2 gap-x-2 text-xs">
                        <div>Generate: {data.generation_time_ms.toFixed(2)} ms</div>
                        <div>Verify: {data.verification_time_ms.toFixed(2)} ms</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default Chat;