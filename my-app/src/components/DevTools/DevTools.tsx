import React, { useState } from 'react';

const DevTools = ({ wsRef, user, setMessages }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [testPayload, setTestPayload] = useState('');
  const [messageType, setMessageType] = useState('session_info');
  
  // Các mẫu tin nhắn để kiểm thử
  const templates = {
    'session_info': {
      type: 'session_info',
      session_id: `${user?.username}_test-session`,
      pfs: {
        algorithm: 'ecc',
        public_key: 'TEST_PUBLIC_KEY_HERE',
        expires_at: new Date(Date.now() + 300000).toISOString()
      }
    },
    'pfs_update': {
      type: 'pfs_update',
      algorithm: 'ecc',
      public_key: 'TEST_ROTATED_KEY_HERE',
      expires_at: new Date(Date.now() + 300000).toISOString()
    },
    'message_with_signature': {
      type: 'message',
      sender: 'test-sender',
      content: 'TEST_ENCRYPTED_CONTENT',
      algorithm: 'RSA-2048',
      signature: 'TEST_SIGNATURE',
      timestamp: new Date().toISOString()
    },
    'message_without_signature': {
      type: 'message',
      sender: 'test-sender',
      content: 'TEST_ENCRYPTED_CONTENT',
      algorithm: 'RSA-2048',
      timestamp: new Date().toISOString()
    }
  };
  
  // Chọn mẫu tin nhắn
  const handleTemplateSelect = (type) => {
    setMessageType(type);
    setTestPayload(JSON.stringify(templates[type], null, 2));
  };
  
  // Mô phỏng tin nhắn đến
  const simulateIncomingMessage = () => {
    try {
      const payload = JSON.parse(testPayload);
      
      // Kích hoạt trình xử lý tin nhắn thủ công như thể nó đến từ WebSocket
      const event = {
        data: JSON.stringify(payload)
      };
      
      // Ghi log vào console
      console.log('Simulating WebSocket message:', payload);
      
      // Thêm tin nhắn hệ thống để thông báo cho người dùng
      setMessages(prev => [
        ...prev, 
        {
          sender: 'System',
          recipient: user?.username,
          content: `Đã mô phỏng tin nhắn kiểm thử: ${payload.type}`,
          timestamp: new Date().toISOString(),
          status: 'system'
        }
      ]);
      
      // Gọi trực tiếp trình xử lý onmessage của WebSocket
      if (wsRef.current && wsRef.current.onmessage) {
        wsRef.current.onmessage(event);
      }
    } catch (error) {
      console.error('Error simulating message:', error);
      alert('Dữ liệu JSON không hợp lệ');
    }
  };
  
  // Nếu chưa mở rộng, chỉ hiển thị nút
  if (!isExpanded) {
    return (
      <div className="fixed bottom-4 right-4">
        <button 
          onClick={() => setIsExpanded(true)} 
          className="bg-gray-800 text-white p-2 rounded-full shadow-lg"
          title="Mở công cụ phát triển"
        >
          🛠️
        </button>
      </div>
    );
  }
  
  // Giao diện đầy đủ
  return (
    <div className="fixed bottom-0 right-0 w-96 bg-white border border-gray-300 shadow-lg rounded-t-lg overflow-hidden">
      <div className="bg-gray-800 text-white p-2 flex justify-between items-center">
        <span>Công cụ phát triển</span>
        <button onClick={() => setIsExpanded(false)}>×</button>
      </div>
      
      <div className="p-3">
        <div className="mb-3">
          <label className="block text-sm font-medium text-gray-700 mb-1">Loại tin nhắn</label>
          <div className="flex space-x-2 flex-wrap">
            {Object.keys(templates).map(type => (
              <button
                key={type}
                onClick={() => handleTemplateSelect(type)}
                className={`px-2 py-1 text-xs rounded mb-1 ${messageType === type ? 'bg-blue-500 text-white' : 'bg-gray-200'}`}
              >
                {type}
              </button>
            ))}
          </div>
        </div>
        
        <div className="mb-3">
          <label className="block text-sm font-medium text-gray-700 mb-1">Dữ liệu kiểm thử (JSON)</label>
          <textarea
            value={testPayload}
            onChange={(e) => setTestPayload(e.target.value)}
            className="w-full h-32 border rounded p-2 text-xs font-mono"
          />
        </div>
        
        <button
          onClick={simulateIncomingMessage}
          className="w-full bg-blue-500 text-white py-2 rounded hover:bg-blue-600"
        >
          Mô phỏng tin nhắn
        </button>
      </div>
    </div>
  );
};

export default DevTools;