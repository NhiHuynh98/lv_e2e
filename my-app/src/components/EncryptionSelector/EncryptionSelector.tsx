import React from 'react';

const EncryptionSelector = ({ selectedAlgorithm, onChange }) => {
  const algorithms = [
    { value: 'RSA-2048', label: 'RSA 2048-bit' },
    { value: 'RSA-3072', label: 'RSA 3072-bit' },
    { value: 'RSA-4096', label: 'RSA 4096-bit' },
    { value: 'ECC-256', label: 'ECC SECP256R1' },
    { value: 'ECC-384', label: 'ECC SECP384R1' },
    { value: 'ECC-521', label: 'ECC SECP521R1' },
    { value: 'DH-2048', label: 'Diffie-Hellman 2048-bit' },
    { value: 'DH-3072', label: 'Diffie-Hellman 3072-bit' },
    { value: 'DH-4096', label: 'Diffie-Hellman 4096-bit' },
  ];

  return (
    <div>
      <label htmlFor="encryption-algorithm" className="block text-sm font-medium text-gray-700 mb-1">
        Encryption Algorithm
      </label>
      <select
        id="encryption-algorithm"
        className="block w-full p-2 border border-gray-300 rounded-md bg-white shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
        value={selectedAlgorithm}
        onChange={(e) => onChange(e.target.value)}
      >
        {algorithms.map((algo) => (
          <option key={algo.value} value={algo.value}>
            {algo.label}
          </option>
        ))}
      </select>
      
      <div className="mt-2 text-xs text-gray-500">
        {selectedAlgorithm.startsWith('RSA') && (
          <p>RSA uses asymmetric encryption with large prime numbers. Best for key exchange and digital signatures.</p>
        )}
        {selectedAlgorithm.startsWith('ECC') && (
          <p>Elliptic Curve Cryptography offers strong security with smaller key sizes than RSA.</p>
        )}
        {selectedAlgorithm.startsWith('DH') && (
          <p>Diffie-Hellman allows secure key exchange over an insecure channel.</p>
        )}
      </div>
    </div>
  );
};

export default EncryptionSelector;