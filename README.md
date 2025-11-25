# Secure File Transfer System

This is a secure file transfer system that implements end-to-end encryption for file transfers between a server and clients. The system uses a combination of asymmetric (RSA) and symmetric (Fernet) encryption to ensure secure communication.

## Features

- Secure file transfer using RSA and Fernet encryption
- Support for multiple client connections
- Automatic file saving in a dedicated directory
- Thread-safe implementation
- Error handling and graceful disconnection

## Requirements

- Python 3.x
- Required Python packages:
  - cryptography
  - socket
  - threading
  - json
  - os
  - base64

## Installation

1. Clone the repository
2. Install required packages:
```bash
pip install cryptography
```

## Usage

### Server Side

```python
from file_transfer import SecureFileTransfer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate server keypair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Create server instance
server = SecureFileTransfer(host='localhost', port=5000)

# Start the server
server.start(private_key)
```

### Client Side

```python
from file_transfer import FileTransferClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate client keypair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Create client instance
client = FileTransferClient()

# Connect to server
client.connect('localhost', 5000, private_key)

# Send a file
client.send_file('path/to/your/file.txt')
```

## Security Features

1. **Asymmetric Encryption (RSA)**:
   - Used for initial key exchange
   - Server and client each have their own keypair
   - Public keys are exchanged for secure communication

2. **Symmetric Encryption (Fernet)**:
   - Used for actual file transfer
   - Generated for each client connection
   - Provides fast and secure file encryption

3. **Secure Key Exchange**:
   - Client sends public key to server
   - Server generates symmetric key
   - Symmetric key is encrypted with client's public key
   - Client decrypts symmetric key with private key

## File Transfer Process

1. Client connects to server
2. Client sends its public key
3. Server generates symmetric key
4. Server encrypts symmetric key with client's public key
5. Client decrypts symmetric key
6. File transfer begins using symmetric encryption
7. Files are saved in 'received_files' directory

## Error Handling

- Connection errors
- File transfer errors
- Encryption/decryption errors
- Graceful disconnection handling

## Directory Structure

```
project/
├── file_transfer.py
├── README.md
└── received_files/
    └── (transferred files will be saved here)
```

## Security Considerations

1. Always use strong key sizes (2048 bits or more)
2. Keep private keys secure
3. Use secure network connections
4. Implement proper authentication mechanisms
5. Regular security audits

## Limitations

1. No built-in authentication system
2. No file integrity verification
3. No progress tracking for large files
4. No automatic reconnection handling

## Future Improvements

1. Add user authentication
2. Implement file integrity checks
3. Add progress tracking
4. Implement automatic reconnection
5. Add compression support
6. Implement file transfer resume capability 