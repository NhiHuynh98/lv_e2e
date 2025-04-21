import React from 'react';

const EncryptionSelector = ({ selectedAlgorithm, onChange }) => {
  const algorithms = [
    { value: 'RSA-2048', label: 'RSA 2048', category: 'RSA' },
    { value: 'RSA-3072', label: 'RSA 3072', category: 'RSA' },
    { value: 'RSA-4096', label: 'RSA 4096', category: 'RSA' },
    { value: 'ECC-256', label: 'ECC P-256', category: 'ECC' },
    { value: 'ECC-384', label: 'ECC P-384', category: 'ECC' },
    { value: 'ECC-521', label: 'ECC P-521', category: 'ECC' },
    { value: 'DH-2048', label: 'DH 2048', category: 'DH' },
    { value: 'DH-3072', label: 'DH 3072', category: 'DH' },
    { value: 'DH-4096', label: 'DH 4096', category: 'DH' }
  ];
  
  // Nhóm thuật toán theo danh mục
  const categories = [...new Set(algorithms.map(algo => algo.category))];
  
  return (
    <div>
      <label htmlFor="encryption-algorithm" className="block text-sm font-medium text-gray-700 mb-1">
        Thuật toán mã hóa
      </label>
      <select
        id="encryption-algorithm"
        value={selectedAlgorithm}
        onChange={(e) => onChange(e.target.value)}
        className="w-full p-2 border rounded bg-white"
      >
        {categories.map(category => (
          <optgroup key={category} label={category}>
            {algorithms
              .filter(algo => algo.category === category)
              .map(algo => (
                <option key={algo.value} value={algo.value}>
                  {algo.label}
                </option>
              ))
            }
          </optgroup>
        ))}
      </select>
      
      <div className="mt-2 text-xs text-gray-500">
        {selectedAlgorithm.startsWith('RSA') && (
          <p>RSA là một thuật toán mã hóa bất đối xứng với độ bảo mật cao và được sử dụng rộng rãi.</p>
        )}
        {selectedAlgorithm.startsWith('ECC') && (
          <p>ECC (Mật mã đường cong Elliptic) cung cấp độ bảo mật tương tự RSA nhưng với khóa ngắn hơn.</p>
        )}
        {selectedAlgorithm.startsWith('DH') && (
          <p>DH (Diffie-Hellman) là một phương pháp trao đổi khóa an toàn qua kênh không an toàn.</p>
        )}
      </div>
    </div>
  );
};

export default EncryptionSelector;