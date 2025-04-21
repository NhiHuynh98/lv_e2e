import React from 'react';

const MessageList = ({ messages, currentUser, debugMode = false }) => {
  return (
    <div className="space-y-4">
      {messages.map((message, index) => {
        // Xác định loại tin nhắn (đã gửi, đã nhận, hệ thống, lỗi)
        const isSent = message.sender === currentUser;
        const isSystem = message.status === 'system';
        const isError = message.status === 'error';
        
        // Các lớp CSS dựa trên loại tin nhắn
        const messageClasses = `p-3 rounded-lg max-w-xs lg:max-w-md ${
          isSystem 
            ? 'bg-yellow-100 text-yellow-800 mx-auto' 
            : isError
              ? 'bg-red-100 text-red-800 mx-auto'
              : isSent
                ? 'bg-blue-500 text-white ml-auto' 
                : 'bg-gray-200 text-gray-800 mr-auto'
        }`;
        
        return (
          <div key={index} className="flex flex-col">
            {/* Hiển thị người gửi cho tin nhắn nhận được */}
            {!isSent && !isSystem && !isError && (
              <span className="text-xs text-gray-500 mb-1">{message.sender}</span>
            )}
            
            <div className={messageClasses}>
              {/* Nội dung tin nhắn */}
              <div className="break-words">{message.content}</div>
              
              {/* Thời gian và thông tin thêm */}
              <div className="mt-1 flex justify-between items-center">
                <span className="text-xs opacity-75">
                  {new Date(message.timestamp).toLocaleTimeString()}
                </span>
                
                {/* Thông tin chữ ký/xác thực */}
                {!isSystem && !isError && (
                  <span className="text-xs ml-2">
                    {message.authenticated 
                      ? <span className="text-green-300">✓ Đã xác thực</span>
                      : message.skippedSignature
                        ? <span className="text-red-300">Không có chữ ký</span>
                        : null
                    }
                  </span>
                )}
              </div>
              
              {/* Thông tin debug bổ sung */}
              {debugMode && !isSystem && !isError && (
                <div className="mt-2 text-xs border-t pt-1 opacity-75">
                  <div>Thuật toán: {message.algorithm}</div>
                  <div>Trạng thái: {message.status}</div>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default MessageList;