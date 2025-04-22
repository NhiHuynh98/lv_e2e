import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../context/AuthContext';
import EncryptionSelector from '../EncryptionSelector/EncryptionSelector';
import MessageList from '../MessageList/MessageList';
import DevTools from '../DevTools/DevTools';
import { encryptMessage, decryptMessage, generateKeyPair } from '../../services/crypto';

const API_URL = 'http://localhost:8000';
const API_URL_WS = 'ws://localhost:8000/ws';

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
  const [testMode, setTestMode] = useState(false);
  const [skipSignature, setSkipSignature] = useState(false);
  const [debugMode, setDebugMode] = useState(false);
  
  // Trạng thái cho tính năng bảo mật nâng cao
  const [sessionInfo, setSessionInfo] = useState(null);
  const [securityStatus, setSecurityStatus] = useState({
    pfsActive: false,
    hmacActive: false,
    keyExchangeActive: false
  });
  
  const wsRef = useRef(null);
  const pfsRotationTimerRef = useRef(null);
  
  // Kết nối WebSocket
  useEffect(() => {
    if (user && token) {
      const ws = new WebSocket(`${API_URL_WS}/${user.username}?token=${token}`);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setIsConnected(true);
      };
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('WebSocket message received:', data);
        
        // Xử lý thông tin phiên (thiết lập PFS)
        if (data.type === 'session_info') {
          handleSessionInfo(data);
          return;
        }
        
        // Xử lý cập nhật khóa PFS
        if (data.type === 'pfs_update') {
          handlePFSUpdate(data);
          return;
        }
        
        // Xử lý tin nhắn thông thường
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
      
      // Thiết lập bộ hẹn giờ xoay khóa PFS
      setupPFSRotationTimer();
      
      return () => {
        ws.close();
        clearPFSRotationTimer();
      };
    }
  }, [user, token]);
  
  // Tạo cặp khóa cho mỗi thuật toán khi component được mount
  useEffect(() => {
    if (user) {
      console.log("user", user);
      generateAllKeyPairs();
    }
  }, [user]);
  
  // Xử lý thông tin phiên PFS
  const handleSessionInfo = (data) => {
    console.log('Session info received:', data);
    setSessionInfo(data);
    
    // Cập nhật trạng thái bảo mật
    setSecurityStatus(prev => ({
      ...prev,
      pfsActive: true,
      hmacActive: true
    }));
  };
  
  // Xử lý cập nhật khóa PFS
  const handlePFSUpdate = (data) => {
    console.log('PFS update received:', data);
    
    // Cập nhật thông tin phiên với khóa công khai PFS mới
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
    
    // Hiển thị tin nhắn hệ thống về việc xoay khóa
    const systemMessage = {
      sender: 'System',
      recipient: user.username,
      content: 'Khóa PFS đã được xoay',
      timestamp: new Date().toISOString(),
      status: 'system'
    };
    
    setMessages(prev => [...prev, systemMessage]);
  };
  
  // Thiết lập bộ hẹn giờ xoay khóa PFS
  const setupPFSRotationTimer = () => {
    // Yêu cầu xoay khóa mỗi 4.5 phút (ít hơn một chút so với xoay 5 phút trên server)
    pfsRotationTimerRef.current = setInterval(() => {
      requestPFSKeyRotation();
    }, 4.5 * 60 * 1000);
  };
  
  // Xóa bộ hẹn giờ xoay khóa PFS
  const clearPFSRotationTimer = () => {
    if (pfsRotationTimerRef.current) {
      clearInterval(pfsRotationTimerRef.current);
    }
  };
  
  // Yêu cầu xoay khóa PFS
  const requestPFSKeyRotation = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      console.log('Requesting PFS key rotation');
      wsRef.current.send(JSON.stringify({
        type: 'pfs_rotation',
        algorithm: 'ecc' // Sử dụng ECC cho PFS mặc định
      }));
    }
  };
  
  // Xoay khóa PFS thủ công (để kiểm thử)
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
        
        // Đăng ký khóa công khai với máy chủ
        await registerPublicKey(algo, keyPair);
      }
      localStorage.setItem("keyPairs", JSON.stringify(newKeyPairs));

      setKeyPairs(newKeyPairs);
    } catch (error) {
      console.error('Error generating key pairs:', error);
    } finally {
      setIsGeneratingKeys(false);
    }
  };
  
  const registerPublicKey = async (algorithm, keyPair) => {
    try {
      const response = await fetch(`${API_URL}/key-exchange`, {
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
  
  // Bắt đầu trao đổi khóa với người dùng khác
  const initiateKeyExchange = async (targetUsername) => {
    try {
      const response = await fetch(`${API_URL}/key-exchange/initiate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          target: targetUsername,
          algorithm: 'ecc' // Sử dụng ECC cho trao đổi khóa mặc định
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to initiate key exchange');
      }
      
      const data = await response.json();
      
      // Cập nhật trạng thái bảo mật
      setSecurityStatus(prev => ({
        ...prev,
        keyExchangeActive: true
      }));
      
      // Hiển thị tin nhắn hệ thống về trao đổi khóa
      const systemMessage = {
        sender: 'System',
        recipient: user.username,
        content: `Trao đổi khóa an toàn đã được bắt đầu với ${targetUsername}`,
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
      const response = await fetch(`${API_URL}/users/${username}/public-key/${algorithm}`, {
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
      // Đảm bảo chúng ta có khóa công khai của người nhận
      let peerKey = peerKeys[selectedRecipient]?.[encryptionAlgorithm];
      
      if (!peerKey) {
        peerKey = await fetchPeerPublicKey(selectedRecipient, encryptionAlgorithm);
        if (!peerKey) {
          throw new Error(`Could not get public key for ${selectedRecipient}`);
        }
      }
      
      // Mã hóa tin nhắn bằng thuật toán do người dùng chọn
      const encrypted = await encryptMessage(
        messageText, 
        peerKey.public_key, 
        encryptionAlgorithm, 
        keyPairs[encryptionAlgorithm],
        peerKey.parameters
      );
      
      // Gửi tin nhắn đã mã hóa qua WebSocket
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          recipient: selectedRecipient,
          content: encrypted,
          algorithm: encryptionAlgorithm,
          skip_signature: skipSignature // Thêm tùy chọn bỏ qua chữ ký
        }));
        
        // Thêm vào tin nhắn cục bộ
        const newMessage = {
          sender: user.username,
          recipient: selectedRecipient,
          content: messageText, // Lưu trữ văn bản thuần túy để hiển thị
          algorithm: encryptionAlgorithm,
          timestamp: new Date().toISOString(),
          status: 'sent',
          skippedSignature: skipSignature // Đánh dấu nếu đã bỏ qua chữ ký
        };
        
        setMessages(prev => [...prev, newMessage]);
        
        // Cập nhật cuộc trò chuyện
        updateConversation(selectedRecipient, newMessage);
        
        // Xóa đầu vào tin nhắn
        setMessageText('');
      } else {
        throw new Error('WebSocket not connected');
      }
    } catch (error) {
      console.error('Error sending message:', error);
      alert(`Error sending message: ${error.message}`);
    }
  };
  
  // Phiên bản cải tiến đã sửa để xử lý tất cả các tin nhắn
  const handleIncomingMessage = async (data) => {
    try {
      const { sender, content, algorithm, timestamp, signature, type } = data;
      
      // Ghi log tin nhắn gốc để gỡ lỗi
      console.log('Processing incoming message:', {
        sender,
        contentType: typeof content,
        contentPreview: typeof content === 'string' ? 
          content.substring(0, 30) + '...' : 'non-string content',
        algorithm,
        hasSignature: Boolean(signature)
      });
      
      // Xác định thuật toán để sử dụng
      const actualAlgorithm = algorithm || 'RSA-2048'; // Fallback mặc định
      
      const stored = JSON.parse(localStorage.getItem("keyPairs"));
      console.log("stored", stored);

      // Lấy cặp khóa thích hợp để giải mã
      const keyPair = stored[actualAlgorithm];
      if (!keyPair) {
        throw new Error(`No key pair found for algorithm ${actualAlgorithm}`);
      }
      
      // Giải mã nội dung bất kể có chữ ký hay không
      let decryptedContent;
      const algoBase = actualAlgorithm.split('-')[0];
      
      console.log('Attempting to decrypt with algorithm:', actualAlgorithm);
      
      // Đối với DH, chúng ta cần khóa công khai của người gửi để thiết lập bí mật chung
      if (algoBase === 'DH') {
        // Đảm bảo chúng ta có khóa công khai của người gửi
        let senderPublicKey = peerKeys[sender]?.[actualAlgorithm]?.public_key;
        
        if (!senderPublicKey) {
          const keyData = await fetchPeerPublicKey(sender, actualAlgorithm);
          senderPublicKey = keyData.public_key;
        }
        
        // Sử dụng bí mật chung để giải mã
        decryptedContent = await decryptMessage(
          content,
          keyPair.privateKey,
          actualAlgorithm,
          senderPublicKey
        );
      } else {
        // Đối với RSA và ECC
        decryptedContent = await decryptMessage(
          content,
          keyPair.privateKey,
          actualAlgorithm
        );
      }
      
      console.log('Decryption successful:', decryptedContent);
      
      // Tạo đối tượng tin nhắn với nội dung đã giải mã
      const newMessage = {
        sender,
        recipient: user.username,
        content: decryptedContent, // Nội dung đã giải mã đúng
        algorithm: actualAlgorithm,
        timestamp: timestamp || new Date().toISOString(),
        status: 'received',
        authenticated: Boolean(signature) // Đánh dấu là đã xác thực HMAC nếu có chữ ký
      };
      
      // Thêm vào tin nhắn
      setMessages(prev => [...prev, newMessage]);
      
      // Cập nhật cuộc trò chuyện
      updateConversation(sender, newMessage);
      
    } catch (error) {
      console.error('Error processing incoming message:', error);
      // Thêm tin nhắn hệ thống về lỗi giải mã
      const errorMessage = {
        sender: 'System',
        recipient: user.username,
        content: `Không thể giải mã tin nhắn: ${error.message}`,
        timestamp: new Date().toISOString(),
        status: 'error'
      };
      setMessages(prev => [...prev, errorMessage]);
    }
  };
  
  // Mô phỏng tin nhắn không có chữ ký (cho kiểm thử)
  const simulateMessageWithoutSignature = () => {
    if (!selectedRecipient) return;
    
    // Tạo tin nhắn mô phỏng đã mã hóa
    const mockEncrypted = "MOCK_ENCRYPTED_CONTENT_" + Date.now();
    
    // Tạo tin nhắn giả không có chữ ký
    const mockMessage = {
      type: "message",
      sender: selectedRecipient,
      content: mockEncrypted,
      algorithm: encryptionAlgorithm,
      timestamp: new Date().toISOString()
      // không có chữ ký
    };
    
    console.log('Simulating message without signature:', mockMessage);
    
    // Xử lý tin nhắn mô phỏng
    handleIncomingMessage(mockMessage);
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
    
    // Bắt đầu trao đổi khóa khi chọn người nhận mới
    if (!securityStatus.keyExchangeActive) {
      initiateKeyExchange(username);
    }
  };
  
  const handleBenchmark = async () => {
    setIsBenchmarking(true);
    try {
      const response = await fetch(`${API_URL}/benchmark`, {
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

  // Lấy trạng thái bảo mật
  const getSecurityStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/security/status`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        return;
      }
      
      const status = await response.json();
      console.log('Security status:', status);
      
      // Cập nhật trạng thái bảo mật
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
          <h1 className="text-xl font-bold">Chat Mã Hóa Đầu Cuối</h1>
          <div className="flex items-center space-x-4">
            {/* Chế độ kiểm thử */}
            <div className="flex items-center">
              <label className="flex items-center cursor-pointer">
                <div className="relative">
                  <input 
                    type="checkbox" 
                    className="sr-only" 
                    checked={testMode} 
                    onChange={() => setTestMode(!testMode)} 
                  />
                  <div className={`block w-10 h-6 rounded-full ${testMode ? 'bg-green-400' : 'bg-gray-600'}`}></div>
                  <div className={`absolute left-1 top-1 bg-white w-4 h-4 rounded-full transition ${testMode ? 'transform translate-x-4' : ''}`}></div>
                </div>
                <div className="ml-2 text-sm">Chế độ kiểm thử</div>
              </label>
            </div>
            
            <span className="mx-2">|</span>
            
            {/* Trạng thái bảo mật */}
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
              <span className="text-xs">Trao đổi khóa</span>
            </div>
            
            <span className="mx-2">|</span>
            
            <span className="mr-2">
              {isConnected ? (
                <span className="text-green-400">●</span>
              ) : (
                <span className="text-red-400">●</span>
              )}
              {isConnected ? ' Đã kết nối' : ' Mất kết nối'}
            </span>
            <span className="font-medium">{user?.username}</span>
          </div>
        </div>
      </div>
      
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <div className="w-1/4 bg-gray-100 p-4 border-r">
          <div className="mb-4">
            <h2 className="font-bold mb-2">Cài đặt mã hóa</h2>
            <EncryptionSelector 
              selectedAlgorithm={encryptionAlgorithm}
              onChange={setEncryptionAlgorithm} 
            />
            
            {/* Tùy chọn bỏ qua HMAC cho kiểm thử */}
            <div className="mt-2 flex items-center">
              <input
                type="checkbox"
                id="skipSignature"
                checked={skipSignature}
                onChange={(e) => setSkipSignature(e.target.checked)}
                className="mr-2"
              />
              <label htmlFor="skipSignature" className="text-sm text-gray-600">
                Bỏ qua chữ ký HMAC (chỉ để kiểm thử)
              </label>
            </div>
            
            <div className="mt-4 space-y-2">
              <button 
                className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 w-full"
                onClick={generateAllKeyPairs}
                disabled={isGeneratingKeys}
              >
                {isGeneratingKeys ? 'Đang tạo khóa...' : 'Tạo lại khóa'}
              </button>
              
              <button 
                className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 w-full"
                onClick={manualKeyRotation}
                disabled={!isConnected}
              >
                Xoay khóa PFS
              </button>
              
              {testMode && (
                <button 
                  className="bg-orange-500 text-white px-4 py-2 rounded hover:bg-orange-600 w-full"
                  onClick={simulateMessageWithoutSignature}
                  disabled={!selectedRecipient}
                >
                  Mô phỏng tin nhắn không HMAC
                </button>
              )}
            </div>
          </div>
          
          <h2 className="font-bold mb-2">Danh bạ</h2>
          <div className="mb-4">
            <div className="flex">
              <input
                type="text"
                className="flex-1 p-2 border rounded-l"
                placeholder="Tên người dùng"
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
                    : 'Chưa có tin nhắn'}
                </div>
              </div>
            ))}
          </div>
          
          <div className="mt-4">
            <h2 className="font-bold mb-2">Hiệu suất</h2>
            <button
              className="bg-purple-500 text-white px-4 py-2 rounded hover:bg-purple-600 w-full"
              onClick={handleBenchmark}
              disabled={isBenchmarking}
            >
              {isBenchmarking ? 'Đang chạy benchmark...' : 'Chạy benchmark'}
            </button>
          </div>
        </div>
        
        {/* Khu vực chat chính */}
        <div className="flex-1 flex flex-col">
          {selectedRecipient ? (
            <>
              <div className="bg-gray-200 p-3 border-b">
                <div className="font-medium">{selectedRecipient}</div>
                <div className="text-xs text-gray-500 flex items-center">
                  <span>Sử dụng mã hóa {encryptionAlgorithm}</span>
                  {securityStatus.pfsActive && (
                    <span className="ml-2 px-2 py-0.5 bg-green-100 text-green-800 rounded-full text-xs">
                      PFS đang hoạt động
                    </span>
                  )}
                  {securityStatus.hmacActive && (
                    <span className="ml-2 px-2 py-0.5 bg-green-100 text-green-800 rounded-full text-xs">
                      HMAC đang hoạt động
                    </span>
                  )}
                </div>
              </div>
              
              <div className="flex-1 overflow-y-auto p-4">
                <MessageList 
                  messages={messages.filter(msg => 
                    (msg.sender === user.username && msg.recipient === selectedRecipient) ||
                    (msg.sender === selectedRecipient && msg.recipient === user.username) ||
                    (msg.status === 'system') || 
                    (msg.status === 'error')
                  )}
                  currentUser={user.username}
                  debugMode={debugMode}
                />
              </div>
              
              <div className="p-4 border-t">
                <form onSubmit={handleSendMessage}>
                  <div className="flex">
                    <input
                      type="text"
                      className="flex-1 p-2 border rounded-l"
                      placeholder="Nhập tin nhắn..."
                      value={messageText}
                      onChange={(e) => setMessageText(e.target.value)}
                    />
                    <button
                      type="submit"
                      className="bg-blue-500 text-white px-4 py-2 rounded-r hover:bg-blue-600"
                      disabled={!isConnected}
                    >
                      Gửi
                      </button>
                  </div>
                </form>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-gray-400">
              Chọn người liên hệ để bắt đầu trò chuyện
            </div>
          )}
        </div>
        
        {/* Panel kết quả benchmark */}
        {benchmarkResults && (
          <div className="w-1/3 bg-gray-100 p-4 border-l overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h2 className="font-bold">Kết quả Benchmark</h2>
              <button
                className="text-gray-500 hover:text-gray-700"
                onClick={() => setBenchmarkResults(null)}
              >
                ×
              </button>
            </div>
            
            {/* Hiển thị các phần khác nhau của kết quả benchmark */}
            <div>
              {/* Kết quả benchmark mã hóa */}
              {benchmarkResults.encryption && (
                <div className="mb-6">
                  <h3 className="font-bold text-lg">Mã hóa</h3>
                  {Object.entries(benchmarkResults.encryption).map(([algo, data]) => (
                    <div key={algo} className="mb-4 border-b pb-2">
                      <h4 className="font-medium">{algo}</h4>
                      {Object.entries(data).map(([sizeKey, metrics]) => (
                        <div key={sizeKey} className="text-sm">
                          <div className="bg-gray-200 p-1 mt-1">Kích thước: {metrics.key_size}/{metrics.message_size} bytes</div>
                          <div className="grid grid-cols-2 gap-x-2 text-xs p-1">
                            <div>Mã hóa: {metrics.encryption_time_ms.toFixed(2)} ms</div>
                            <div>Giải mã: {metrics.decryption_time_ms.toFixed(2)} ms</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              )}
              
              {/* Kết quả benchmark trao đổi khóa */}
              {benchmarkResults.key_exchange && (
                <div className="mb-6">
                  <h3 className="font-bold text-lg">Trao đổi khóa</h3>
                  {Object.entries(benchmarkResults.key_exchange).map(([algo, data]) => (
                    <div key={algo} className="text-sm mb-2">
                      <div>{algo}: {data.time_ms.toFixed(2)} ms</div>
                    </div>
                  ))}
                </div>
              )}
              
              {/* Kết quả benchmark HMAC */}
              {benchmarkResults.hmac && (
                <div className="mb-6">
                  <h3 className="font-bold text-lg">HMAC</h3>
                  {Object.entries(benchmarkResults.hmac).map(([size, data]) => (
                    <div key={size} className="text-sm mb-2">
                      <div>Kích thước tin nhắn: {size} bytes</div>
                      <div className="grid grid-cols-2 gap-x-2 text-xs">
                        <div>Tạo: {data.generation_time_ms.toFixed(2)} ms</div>
                        <div>Xác minh: {data.verification_time_ms.toFixed(2)} ms</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
      
      {/* Thêm DevTools chỉ trong chế độ phát triển */}
      {process.env.NODE_ENV === 'development' && <DevTools wsRef={wsRef} user={user} setMessages={setMessages} />}
    </div>
  );
};

export default Chat;