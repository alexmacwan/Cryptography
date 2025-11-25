import socket
import threading
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

class SecureFileTransfer:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.running = False
        self.server_keypair = None

    def start(self, server_keypair):
        """Start the file transfer server"""
        if self.running:
            return False
        
        self.server_keypair = server_keypair
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            # Start accepting connections in a separate thread
            threading.Thread(target=self._accept_connections, daemon=True).start()
            return True
        except Exception as e:
            print(f"Failed to start server: {e}")
            return False

    def stop(self):
        """Stop the file transfer server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.clients.clear()

    def _accept_connections(self):
        """Accept incoming connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                threading.Thread(target=self._handle_client, 
                              args=(client_socket, address),
                              daemon=True).start()
            except:
                if self.running:
                    continue
                break

    def _handle_client(self, client_socket, address):
        """Handle client connection and file transfers"""
        try:
            # Receive client's public key
            client_public_key_data = client_socket.recv(4096)
            client_public_key = serialization.load_pem_public_key(
                client_public_key_data,
                backend=default_backend()
            )
            
            # Generate and send symmetric key
            symmetric_key = Fernet.generate_key()
            encrypted_sym_key = client_public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client_socket.send(encrypted_sym_key)
            
            # Create Fernet instance for this client
            fernet = Fernet(symmetric_key)
            
            # Add client to connected clients
            client_id = str(address)
            self.clients[client_id] = {
                'socket': client_socket,
                'address': address,
                'fernet': fernet
            }
            
            # Handle incoming files
            while self.running:
                try:
                    # Receive encrypted file data
                    encrypted_data = client_socket.recv(4096)
                    if not encrypted_data:
                        break
                    
                    # Decrypt the file data
                    decrypted_data = fernet.decrypt(encrypted_data)
                    file_info = json.loads(decrypted_data.decode())
                    
                    # Create received_files directory if it doesn't exist
                    os.makedirs('received_files', exist_ok=True)
                    
                    # Save the file
                    filename = os.path.join('received_files', file_info['filename'])
                    with open(filename, 'wb') as f:
                        f.write(b64decode(file_info['data']))
                    
                except Exception as e:
                    print(f"Error handling file transfer: {e}")
                    break
                    
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            if str(address) in self.clients:
                del self.clients[str(address)]
            client_socket.close()

class FileTransferClient:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.fernet = None
        self.keypair = None
        self.server_public_key = None

    def connect(self, host, port, private_key=None):
        """Connect to the file transfer server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            
            # Send public key to server
            if private_key:
                public_key = private_key.public_key()
            elif self.keypair:
                public_key = self.keypair.public_key()
            else:
                raise ValueError("No keypair available for authentication")
                
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.socket.send(public_key_pem)
            
            # Receive encrypted symmetric key
            encrypted_sym_key = self.socket.recv(4096)
            if private_key:
                symmetric_key = private_key.decrypt(
                    encrypted_sym_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            elif self.keypair:
                symmetric_key = self.keypair.decrypt(
                    encrypted_sym_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            
            self.fernet = Fernet(symmetric_key)
            self.connected = True
            return True
            
        except Exception as e:
            print(f"Failed to connect: {e}")
            self.disconnect()
            return False

    def disconnect(self):
        """Disconnect from the server"""
        self.connected = False
        if self.socket:
            self.socket.close()
        self.socket = None
        self.fernet = None

    def send_file(self, filepath):
        """Send a file to the server"""
        if not self.connected or not self.fernet:
            return False
            
        try:
            # Read file data
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            # Prepare file info
            file_info = {
                'filename': os.path.basename(filepath),
                'data': b64encode(file_data).decode()
            }
            
            # Encrypt and send file data
            encrypted_data = self.fernet.encrypt(json.dumps(file_info).encode())
            self.socket.send(encrypted_data)
            return True
            
        except Exception as e:
            print(f"Failed to send file: {e}")
            return False

    def set_keypair(self, keypair):
        """Set the keypair for the client"""
        self.keypair = keypair