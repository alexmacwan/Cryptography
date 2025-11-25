import os
import json
import secrets
import string
import base64
import hashlib
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.exceptions import InvalidSignature
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
# Generate a strong secret key for the application
app.secret_key = secrets.token_hex(32)
# Enable CORS for API endpoints
CORS(app)

# Storage paths
STORAGE_DIR = 'storage'
SYMMETRIC_KEYS_FILE = os.path.join(STORAGE_DIR, 'symmetric_keys.json')
KEYPAIRS_FILE = os.path.join(STORAGE_DIR, 'keypairs.json')
PASSWORD_FILE = os.path.join(STORAGE_DIR, 'passwords.json')

# Ensure storage directory exists
os.makedirs(STORAGE_DIR, exist_ok=True)

# --- Authentication middleware ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions ---
def init_storage_files():
    """Initialize storage files if they don't exist"""
    if not os.path.exists(SYMMETRIC_KEYS_FILE):
        with open(SYMMETRIC_KEYS_FILE, 'w') as f:
            json.dump({}, f)
    
    if not os.path.exists(KEYPAIRS_FILE):
        with open(KEYPAIRS_FILE, 'w') as f:
            json.dump({}, f)
            
    if not os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'w') as f:
            json.dump({}, f)

def load_symmetric_keys():
    """Load symmetric keys from storage"""
    if os.path.exists(SYMMETRIC_KEYS_FILE):
        with open(SYMMETRIC_KEYS_FILE, 'r') as f:
            key_data = json.load(f)
            return {name: key.encode() if isinstance(key, str) else key for name, key in key_data.items()}
    return {}

def load_keypairs():
    """Load asymmetric keypairs from storage"""
    public_keys = {}
    private_keys = {}
    
    if os.path.exists(KEYPAIRS_FILE):
        with open(KEYPAIRS_FILE, 'r') as f:
            keypair_data = json.load(f)
            
            for name, pair in keypair_data.items():
                try:
                    # Load private key
                    private_key = serialization.load_pem_private_key(
                        pair["private"].encode() if isinstance(pair["private"], str) else pair["private"],
                        password=None
                    )
                    private_keys[name] = private_key
                    
                    # Load public key
                    public_key = serialization.load_pem_public_key(
                        pair["public"].encode() if isinstance(pair["public"], str) else pair["public"]
                    )
                    public_keys[name] = public_key
                except Exception as e:
                    print(f"Error loading keypair {name}: {str(e)}")
                    
    return public_keys, private_keys

def save_symmetric_keys(keys):
    """Save symmetric keys to file"""
    key_data = {name: key.decode() if isinstance(key, bytes) else key for name, key in keys.items()}
    with open(SYMMETRIC_KEYS_FILE, 'w') as f:
        json.dump(key_data, f)

def save_keypairs(public_keys, private_keys):
    """Save asymmetric keypairs to file"""
    keypair_data = {}
    for name in private_keys.keys():
        if name in public_keys:
            private_pem = private_keys[name].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = public_keys[name].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            keypair_data[name] = {
                "private": private_pem.decode(),
                "public": public_pem.decode()
            }
    
    with open(KEYPAIRS_FILE, 'w') as f:
        json.dump(keypair_data, f)

def load_passwords():
    """Load passwords from storage"""
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_passwords(passwords):
    """Save passwords to file"""
    with open(PASSWORD_FILE, 'w') as f:
        json.dump(passwords, f)

# Initialize storage
init_storage_files()

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'operational',
        'timestamp': datetime.now().isoformat()
    })

# --- Authentication endpoints ---
@app.route('/api/login', methods=['POST'])
def login():
    # Simple demonstration login - in production, use proper authentication
    data = request.get_json()
    if data and data.get('username') == 'admin' and data.get('password') == 'secure_password':
        session['user_id'] = 'admin'
        return jsonify({'success': True, 'message': 'Login successful'})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

# --- Symmetric encryption endpoints ---
@app.route('/api/symmetric/generate-key', methods=['POST'])
@login_required
def generate_symmetric_key():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Key name is required'}), 400
    
    key_name = data['name']
    keys = load_symmetric_keys()
    
    if key_name in keys:
        return jsonify({'error': 'Key with this name already exists'}), 409
    
    # Generate a new Fernet key
    key = Fernet.generate_key()
    keys[key_name] = key.decode()
    
    save_symmetric_keys(keys)
    
    return jsonify({
        'success': True,
        'message': f'Key "{key_name}" generated successfully',
        'key': key.decode()
    })

@app.route('/api/symmetric/encrypt', methods=['POST'])
@login_required
def symmetric_encrypt():
    data = request.get_json()
    if not data or 'key_name' not in data or 'plaintext' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    key_name = data['key_name']
    plaintext = data['plaintext']
    
    keys = load_symmetric_keys()
    if key_name not in keys:
        return jsonify({'error': f'Key "{key_name}" not found'}), 404
    
    try:
        key = keys[key_name]
        if isinstance(key, str):
            key = key.encode()
            
        f = Fernet(key)
        ciphertext = f.encrypt(plaintext.encode())
        
        return jsonify({
            'success': True,
            'ciphertext': ciphertext.decode(),
        })
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/symmetric/decrypt', methods=['POST'])
@login_required
def symmetric_decrypt():
    data = request.get_json()
    if not data or 'key_name' not in data or 'ciphertext' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    key_name = data['key_name']
    ciphertext = data['ciphertext']
    
    keys = load_symmetric_keys()
    if key_name not in keys:
        return jsonify({'error': f'Key "{key_name}" not found'}), 404
    
    try:
        key = keys[key_name]
        if isinstance(key, str):
            key = key.encode()
            
        f = Fernet(key)
        plaintext = f.decrypt(ciphertext.encode()).decode()
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
        })
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/symmetric/keys', methods=['GET'])
@login_required
def list_symmetric_keys():
    keys = load_symmetric_keys()
    return jsonify({
        'keys': list(keys.keys())
    })

# --- Asymmetric encryption endpoints ---
@app.route('/api/asymmetric/generate-keypair', methods=['POST'])
@login_required
def generate_keypair():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Key name is required'}), 400
    
    key_name = data['name']
    key_size = data.get('key_size', 2048)  # Default to 2048 bits
    
    public_keys, private_keys = load_keypairs()
    
    if key_name in public_keys or key_name in private_keys:
        return jsonify({'error': 'Key with this name already exists'}), 409
    
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        
        # Store keys
        private_keys[key_name] = private_key
        public_keys[key_name] = public_key
        
        # Save keys to file
        save_keypairs(public_keys, private_keys)
        
        # Format keys for display
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return jsonify({
            'success': True,
            'message': f'Keypair "{key_name}" generated successfully',
            'private_key': private_pem,
            'public_key': public_pem
        })
    except Exception as e:
        return jsonify({'error': f'Key generation failed: {str(e)}'}), 500

@app.route('/api/asymmetric/encrypt', methods=['POST'])
@login_required
def asymmetric_encrypt():
    data = request.get_json()
    if not data or 'key_name' not in data or 'plaintext' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    key_name = data['key_name']
    plaintext = data['plaintext']
    
    public_keys, _ = load_keypairs()
    if key_name not in public_keys:
        return jsonify({'error': f'Public key "{key_name}" not found'}), 404
    
    try:
        # Encrypt the plaintext
        ciphertext = public_keys[key_name].encrypt(
            plaintext.encode(),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return jsonify({
            'success': True,
            'ciphertext': base64.b64encode(ciphertext).decode(),
        })
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/asymmetric/decrypt', methods=['POST'])
@login_required
def asymmetric_decrypt():
    data = request.get_json()
    if not data or 'key_name' not in data or 'ciphertext' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    key_name = data['key_name']
    ciphertext = data['ciphertext']
    
    _, private_keys = load_keypairs()
    if key_name not in private_keys:
        return jsonify({'error': f'Private key "{key_name}" not found'}), 404
    
    try:
        # Decrypt the ciphertext
        plaintext = private_keys[key_name].decrypt(
            base64.b64decode(ciphertext),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        
        return jsonify({
            'success': True,
            'plaintext': plaintext,
        })
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/asymmetric/keys', methods=['GET'])
@login_required
def list_asymmetric_keys():
    public_keys, private_keys = load_keypairs()
    return jsonify({
        'public_keys': list(public_keys.keys()),
        'private_keys': list(private_keys.keys())
    })

# --- Hash endpoints ---
@app.route('/api/hash/compute', methods=['POST'])
def compute_hash():
    data = request.get_json()
    if not data or 'text' not in data or 'algorithm' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    text = data['text']
    algorithm = data['algorithm'].lower()
    
    available_algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s
    }
    
    if algorithm not in available_algorithms:
        return jsonify({'error': f'Algorithm "{algorithm}" not supported'}), 400
    
    try:
        hash_func = available_algorithms[algorithm]
        hash_value = hash_func(text.encode()).hexdigest()
        
        return jsonify({
            'success': True,
            'hash': hash_value,
            'algorithm': algorithm
        })
    except Exception as e:
        return jsonify({'error': f'Hash computation failed: {str(e)}'}), 500

# --- Digital signature endpoints ---
@app.route('/api/signature/sign', methods=['POST'])
@login_required
def sign_data():
    data = request.get_json()
    if not data or 'key_name' not in data or 'message' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    key_name = data['key_name']
    message = data['message']
    
    _, private_keys = load_keypairs()
    if key_name not in private_keys:
        return jsonify({'error': f'Private key "{key_name}" not found'}), 404
    
    try:
        # Sign the message
        signature = private_keys[key_name].sign(
            message.encode(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return jsonify({
            'success': True,
            'signature': base64.b64encode(signature).decode(),
            'message': message
        })
    except Exception as e:
        return jsonify({'error': f'Signing failed: {str(e)}'}), 500

@app.route('/api/signature/verify', methods=['POST'])
@login_required
def verify_signature():
    data = request.get_json()
    if not data or 'key_name' not in data or 'message' not in data or 'signature' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    key_name = data['key_name']
    message = data['message']
    signature = data['signature']
    
    public_keys, _ = load_keypairs()
    if key_name not in public_keys:
        return jsonify({'error': f'Public key "{key_name}" not found'}), 404
    
    try:
        # Verify the signature
        public_keys[key_name].verify(
            base64.b64decode(signature),
            message.encode(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return jsonify({
            'success': True,
            'verified': True,
            'message': 'Signature verification successful'
        })
    except InvalidSignature:
        return jsonify({
            'success': True,
            'verified': False,
            'message': 'Signature verification failed'
        })
    except Exception as e:
        return jsonify({'error': f'Verification failed: {str(e)}'}), 500

# --- Password management endpoints ---
@app.route('/api/password/generate', methods=['POST'])
def generate_password():
    data = request.get_json()
    length = data.get('length', 16) if data else 16
    use_uppercase = data.get('use_uppercase', True) if data else True
    use_lowercase = data.get('use_lowercase', True) if data else True
    use_digits = data.get('use_digits', True) if data else True
    use_special = data.get('use_special', True) if data else True
    
    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    if not characters:
        characters = string.ascii_letters + string.digits
    
    try:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        return jsonify({
            'success': True,
            'password': password,
            'length': length,
            'strength': 'strong' if length >= 12 else 'medium' if length >= 8 else 'weak'
        })
    except Exception as e:
        return jsonify({'error': f'Password generation failed: {str(e)}'}), 500

@app.route('/api/password/store', methods=['POST'])
@login_required
def store_password():
    data = request.get_json()
    if not data or 'name' not in data or 'password' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    name = data['name']
    password = data['password']
    description = data.get('description', '')
    
    passwords = load_passwords()
    
    # Simple encryption of the stored password
    key = app.secret_key[:32]
    f = Fernet(base64.urlsafe_b64encode(key.encode()))
    encrypted_password = f.encrypt(password.encode()).decode()
    
    passwords[name] = {
        'password': encrypted_password,
        'description': description,
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    save_passwords(passwords)
    
    return jsonify({
        'success': True,
        'message': f'Password "{name}" stored successfully'
    })

@app.route('/api/password/retrieve', methods=['POST'])
@login_required
def retrieve_password():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Password name is required'}), 400
    
    name = data['name']
    passwords = load_passwords()
    
    if name not in passwords:
        return jsonify({'error': f'Password "{name}" not found'}), 404
    
    try:
        # Decrypt the password
        key = app.secret_key[:32]
        f = Fernet(base64.urlsafe_b64encode(key.encode()))
        decrypted_password = f.decrypt(passwords[name]['password'].encode()).decode()
        
        return jsonify({
            'success': True,
            'name': name,
            'password': decrypted_password,
            'description': passwords[name]['description'],
            'created_at': passwords[name]['created_at'],
            'updated_at': passwords[name]['updated_at']
        })
    except Exception as e:
        return jsonify({'error': f'Password retrieval failed: {str(e)}'}), 500

@app.route('/api/password/list', methods=['GET'])
@login_required
def list_passwords():
    passwords = load_passwords()
    password_list = [{
        'name': name,
        'description': info['description'],
        'created_at': info['created_at'],
        'updated_at': info['updated_at']
    } for name, info in passwords.items()]
    
    return jsonify({
        'success': True,
        'passwords': password_list
    })

@app.route('/api/password/delete', methods=['POST'])
@login_required
def delete_password():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Password name is required'}), 400
    
    name = data['name']
    passwords = load_passwords()
    
    if name not in passwords:
        return jsonify({'error': f'Password "{name}" not found'}), 404
    
    del passwords[name]
    save_passwords(passwords)
    
    return jsonify({
        'success': True,
        'message': f'Password "{name}" deleted successfully'
    })

# Run the app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)