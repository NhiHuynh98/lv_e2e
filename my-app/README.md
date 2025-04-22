# End-to-End Encrypted Chat Application Research Project

This application is designed to compare different encryption algorithms (RSA, ECC, DH) in the context of an end-to-end encrypted chat system. It allows measurement of key generation time, encryption/decryption speed, and key length efficiency across different algorithms and security levels.

## Research Focus

- Comparing performance metrics of different cryptographic algorithms in a real-time chat context
- Testing resistance against eavesdropping attacks over wireless networks
- Analyzing tradeoffs between security level and performance
- Evaluating key exchange mechanisms in secure communication

## Features

- End-to-end encryption using various algorithms:
  - RSA (2048, 3072, 4096 bits)
  - Elliptic Curve Cryptography (256, 384, 521 bits)
  - Diffie-Hellman (2048, 3072, 4096 bits)
- Real-time messaging over WebSockets
- Benchmarking tools for performance comparison
- Authentication system
- React.js frontend with Python FastAPI backend

## Technical Architecture

### Frontend (React.js)
- User authentication interface
- Chat UI with encryption algorithm selection
- Real-time message display
- Performance metrics visualization
- Web Crypto API for client-side cryptographic operations

### Backend (Python FastAPI)
- WebSocket server for real-time communication
- RESTful API for authentication and key exchange
- Cryptographic operations using Python cryptography library
- Benchmarking services for algorithm comparison

## Setup and Installation

### Prerequisites
- Python 3.8+ 
- Node.js 14+ and npm
- Virtual environment (recommended)

### Backend Setup

```bash
# Clone the repository
git clone git@github.com:NhiHuynh98/lv_e2e.git
cd lv_e2e/BE

# Create and activate virtual environment
python3.8 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python api.py
```

The backend server will run on http://localhost:8000.

### Frontend Setup

```bash
# Navigate to frontend directory
cd my-app

# Install dependencies
yarn install

# Start development server
npm run dev or yarn dev
```

The frontend development server will run on http://localhost:5173.

## Usage

1. Register a new account or log in
2. Select the encryption algorithm you want to use
3. Add contacts by their username
4. Exchange messages securely
5. Run benchmarks to compare algorithm performance

## Benchmarking Metrics

The application collects and displays the following metrics:

- Key generation time
- Key size
- Encryption/decryption speed for various message sizes
- Network overhead
- CPU and memory usage

## Security Considerations

This application is designed for research purposes and educational use. While it implements proper cryptographic techniques, additional security measures would be needed for production use, including:

- Proper certificate validation
- Forward secrecy
- Message authentication codes
- Protection against side-channel attacks
- Secure key storage

## Future Work

- Implementing additional encryption algorithms (ChaCha20-Poly1305, AES-GCM, etc.)
- Adding group chat with secure multiparty encryption
- Integrating quantum-resistant encryption algorithms
- Implementing forward secrecy mechanisms
- Expanding analysis capabilities with more detailed metrics

## License

[MIT License](LICENSE)

## Contributors

- [Your Name] - Master's Degree Researcher