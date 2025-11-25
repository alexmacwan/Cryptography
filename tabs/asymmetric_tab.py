import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os
import datetime

# Define folder paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, 'keys', 'asymmetric')
ENCRYPTED_FILES_DIR = os.path.join(BASE_DIR, 'encrypted_files', 'asymmetric')

# Create directories if they don't exist
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_FILES_DIR, exist_ok=True)

class AsymmetricTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_private_key = None
        self.selected_public_key = None
        self.create_widgets()
        self.refresh_key_lists()
        
    def create_widgets(self):
        # Key generation section
        key_frame = ttk.LabelFrame(self, text="Key Management")
        key_frame.pack(pady=10, padx=10, fill="x")
        
        # Add key name input field
        name_frame = ttk.Frame(key_frame)
        name_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(name_frame, text="Key Pair Name:").pack(side="left", padx=(0, 5))
        self.key_name = ttk.Entry(name_frame)
        self.key_name.pack(side="left", fill="x", expand=True)
        
        generate_key_btn = ttk.Button(
            key_frame,
            text="Generate New Key Pair",
            command=self.generate_keys,
            style="Accent.TButton"
        )
        generate_key_btn.pack(pady=5, padx=5)
        
        # Key selection section
        key_select_frame = ttk.LabelFrame(self, text="Key Selection")
        key_select_frame.pack(pady=10, padx=10, fill="x")
        
        # My keys section
        my_keys_frame = ttk.LabelFrame(key_select_frame, text="My Keys")
        my_keys_frame.pack(fill="x", padx=5, pady=5)
        
        # My private key selection
        my_priv_frame = ttk.Frame(my_keys_frame)
        my_priv_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(my_priv_frame, text="My Private Key:").pack(side="left", padx=(0, 5))
        self.my_private_key = ttk.Combobox(my_priv_frame, state="readonly")
        self.my_private_key.pack(side="left", fill="x", expand=True)
        self.my_private_key.bind('<<ComboboxSelected>>', self.on_private_key_selected)
        
        # Other's keys section
        others_keys_frame = ttk.LabelFrame(key_select_frame, text="Recipient's Keys")
        others_keys_frame.pack(fill="x", padx=5, pady=5)
        
        # Other's public key selection
        other_pub_frame = ttk.Frame(others_keys_frame)
        other_pub_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(other_pub_frame, text="Recipient's Public Key:").pack(side="left", padx=(0, 5))
        self.recipient_public_key = ttk.Combobox(other_pub_frame, state="readonly")
        self.recipient_public_key.pack(side="left", fill="x", expand=True)
        self.recipient_public_key.bind('<<ComboboxSelected>>', self.on_public_key_selected)
        
        # Key management buttons frame
        key_mgmt_frame = ttk.Frame(key_select_frame)
        key_mgmt_frame.pack(pady=5, padx=5)
        
        # Export public key button
        export_btn = ttk.Button(
            key_mgmt_frame,
            text="Export My Public Key",
            command=self.export_public_key
        )
        export_btn.pack(side="left", padx=5)
        
        # Import public key button
        import_btn = ttk.Button(
            key_mgmt_frame,
            text="Import Public Key",
            command=self.import_public_key
        )
        import_btn.pack(side="left", padx=5)
        
        # Refresh key lists button
        refresh_btn = ttk.Button(
            key_mgmt_frame,
            text="Refresh Key Lists",
            command=self.refresh_key_lists
        )
        refresh_btn.pack(side="left", padx=5)
        
        # Encryption section
        encrypt_frame = ttk.LabelFrame(self, text="Encryption (Using Public Key)")
        encrypt_frame.pack(pady=10, padx=10, fill="x")
        
        # Plaintext input with browse button
        plaintext_frame = ttk.Frame(encrypt_frame)
        plaintext_frame.pack(fill="x", padx=5, pady=5)
        
        self.plaintext = tk.Text(plaintext_frame, height=5)
        self.plaintext.pack(side="left", fill="x", expand=True)
        
        browse_plaintext_btn = ttk.Button(
            plaintext_frame,
            text="Browse",
            command=lambda: self.load_file(self.plaintext)
        )
        browse_plaintext_btn.pack(side="right", padx=(5, 0))
        
        encrypt_btn_frame = ttk.Frame(encrypt_frame)
        encrypt_btn_frame.pack(pady=5)
        
        encrypt_btn = ttk.Button(
            encrypt_btn_frame,
            text="Encrypt",
            command=self.encrypt_text
        )
        encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        save_encrypt_btn = ttk.Button(
            encrypt_btn_frame,
            text="Save Encrypted Text",
            command=lambda: self.save_text(self.ciphertext)
        )
        save_encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        # Decryption section
        decrypt_frame = ttk.LabelFrame(self, text="Decryption (Using Private Key)")
        decrypt_frame.pack(pady=10, padx=10, fill="x")
        
        # Ciphertext input with browse button
        ciphertext_frame = ttk.Frame(decrypt_frame)
        ciphertext_frame.pack(fill="x", padx=5, pady=5)
        
        self.ciphertext = tk.Text(ciphertext_frame, height=5)
        self.ciphertext.pack(side="left", fill="x", expand=True)
        
        browse_ciphertext_btn = ttk.Button(
            ciphertext_frame,
            text="Browse",
            command=lambda: self.load_file(self.ciphertext)
        )
        browse_ciphertext_btn.pack(side="right", padx=(5, 0))
        
        decrypt_btn_frame = ttk.Frame(decrypt_frame)
        decrypt_btn_frame.pack(pady=5)
        
        decrypt_btn = ttk.Button(
            decrypt_btn_frame,
            text="Decrypt",
            command=self.decrypt_text
        )
        decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        save_decrypt_btn = ttk.Button(
            decrypt_btn_frame,
            text="Save Decrypted Text",
            command=lambda: self.save_text(self.plaintext)
        )
        save_decrypt_btn.pack(side=tk.LEFT, padx=5)
        
    def generate_keys(self):
        """Generate RSA key pair"""
        key_name = self.key_name.get().strip()
        if not key_name:
            messagebox.showerror(
                "Error",
                "Please enter a name for the key pair!"
            )
            return
            
        # Check if key name already exists
        if key_name in self.controller.private_keys or key_name in self.controller.public_keys:
            response = messagebox.askyesno(
                "Key Exists",
                f"A key pair with name '{key_name}' already exists! Do you want to replace it?"
            )
            if not response:
                return
            
        try:
            # Generate new RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            # Store the keys in the controller's key dictionaries
            self.controller.private_keys[key_name] = private_key
            self.controller.public_keys[key_name] = public_key
            
            messagebox.showinfo(
                "Success",
                f"New RSA key pair '{key_name}' generated!"
            )
            # Clear the input field and refresh key lists
            self.key_name.delete(0, tk.END)
            self.refresh_key_lists()
            
            # Select the newly generated key
            self.my_private_key.set(key_name)
            self.recipient_public_key.set(key_name)
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to generate key pair: {str(e)}"
            )
        
    def encrypt_text(self):
        """Encrypt text using recipient's public key"""
        recipient_key_name = self.recipient_public_key.get()
        if not recipient_key_name:
            messagebox.showerror(
                "Error",
                "Please select a recipient's public key!"
            )
            return
            
        plaintext = self.plaintext.get("1.0", "end-1c")
        if not plaintext:
            messagebox.showerror(
                "Error",
                "Please enter text to encrypt!"
            )
            return
            
        try:
            public_key = self.controller.public_keys[recipient_key_name]
            ciphertext = public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.ciphertext.delete("1.0", "end")
            self.ciphertext.insert("1.0", ciphertext.hex())
            messagebox.showinfo(
                "Success",
                "Message encrypted successfully!"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Encryption failed: {str(e)}"
            )
            
    def decrypt_text(self):
        """Decrypt text using my private key"""
        my_key_name = self.my_private_key.get()
        if not my_key_name:
            messagebox.showerror(
                "Error",
                "Please select your private key!"
            )
            return
            
        ciphertext = self.ciphertext.get("1.0", "end-1c")
        if not ciphertext:
            messagebox.showerror(
                "Error",
                "Please enter text to decrypt!"
            )
            return
            
        try:
            private_key = self.controller.private_keys[my_key_name]
            plaintext = private_key.decrypt(
                bytes.fromhex(ciphertext),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.plaintext.delete("1.0", "end")
            self.plaintext.insert("1.0", plaintext.decode())
            messagebox.showinfo(
                "Success",
                "Message decrypted successfully!"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Decryption failed: {str(e)}"
            )
            
    def refresh_key_lists(self):
        """Update the key selection dropdowns"""
        # Get list of available keys
        all_keys = list(self.controller.private_keys.keys())
        
        # Update private key dropdown (exclude selected public key)
        private_keys = [k for k in all_keys if k != self.selected_public_key]
        self.my_private_key['values'] = private_keys
        
        # Update public key dropdown (exclude selected private key)
        public_keys = [k for k in all_keys if k != self.selected_private_key]
        self.recipient_public_key['values'] = public_keys
        
        # Maintain selections if they're still valid
        if self.selected_private_key in private_keys:
            self.my_private_key.set(self.selected_private_key)
        if self.selected_public_key in public_keys:
            self.recipient_public_key.set(self.selected_public_key)
            
    def on_private_key_selected(self, event):
        """Handle private key selection"""
        self.selected_private_key = self.my_private_key.get()
        self.refresh_key_lists()
        
    def on_public_key_selected(self, event):
        """Handle public key selection"""
        self.selected_public_key = self.recipient_public_key.get()
        self.refresh_key_lists()
            
        # Enable/disable encryption/decryption based on key selection
        has_keys = len(key_names) > 0
    
    def export_public_key(self):
        """Export the selected public key to a file"""
        key_name = self.my_private_key.get()
        if not key_name:
            messagebox.showerror(
                "Error",
                "Please select a key pair first!"
            )
            return
            
        try:
            # Get the public key
            public_key = self.controller.public_keys[key_name]
            
            # Serialize the public key
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save to keys directory with default name
            file_path = os.path.join(KEYS_DIR, f"{key_name}.pub")
            
            # Ask for confirmation if file exists
            if os.path.exists(file_path):
                if not messagebox.askyesno(
                    "File Exists",
                    f"Public key file '{key_name}.pub' already exists. Do you want to replace it?"
                ):
                    return
            
            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(pem)
                messagebox.showinfo(
                    "Success",
                    f"Public key exported to {file_path}"
                )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to export public key: {str(e)}"
            )
    
    def import_public_key(self):
        """Import a public key from a file"""
        file_path = filedialog.askopenfilename(
            title="Select Public Key",
            initialdir=KEYS_DIR,
            filetypes=[("Public Key", "*.pub")])
        
        if file_path:
            try:
                # Get the key name from file name
                key_name = os.path.splitext(os.path.basename(file_path))[0]
                
                # Check if key already exists
                if key_name in self.controller.public_keys:
                    response = messagebox.askyesno(
                        "Key Exists",
                        f"A public key with name '{key_name}' already exists! Do you want to replace it?"
                    )
                    if not response:
                        return
                
                # Read and load the public key
                with open(file_path, 'rb') as f:
                    public_key = serialization.load_pem_public_key(f.read())
                
                # Store the public key
                self.controller.public_keys[key_name] = public_key
                
                messagebox.showinfo(
                    "Success",
                    f"Public key '{key_name}' imported successfully!"
                )
                
                # Refresh the key lists
                self.refresh_key_lists()
                
                # Select the imported key as recipient
                self.recipient_public_key.set(key_name)
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to import public key: {str(e)}"
                )
    
    def load_file(self, text_widget):
        """Load text from a file into the given text widget"""
        # Determine if we're loading encrypted or plaintext content
        is_encrypted = text_widget == self.ciphertext
        
        file_path = filedialog.askopenfilename(
            title="Select Encrypted File" if is_encrypted else "Select Text File",
            initialdir=ENCRYPTED_FILES_DIR if is_encrypted else None,
            filetypes=[
                ("Encrypted files", "*.enc") if is_encrypted else ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                # Read file based on type
                mode = 'rb' if is_encrypted else 'r'
                with open(file_path, mode) as file:
                    if is_encrypted:
                        # Convert bytes to hex string for encrypted content
                        content = file.read().hex()
                    else:
                        content = file.read()
                    
                    text_widget.delete("1.0", "end")
                    text_widget.insert("1.0", content)
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to load file: {str(e)}"
                )
    def save_text(self, text_widget):
        """Save text from the given text widget to a file"""
        content = text_widget.get("1.0", "end-1c")
        if not content:
            messagebox.showerror(
                "Error",
                "No content to save!"
            )
            return
        
        # Determine if we're saving encrypted or decrypted content
        is_encrypted = text_widget == self.ciphertext
        
        # Set initial directory and filename
        if is_encrypted:
            initial_dir = ENCRYPTED_FILES_DIR
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            initial_file = f"encrypted_{timestamp}.enc"
        else:
            initial_dir = None
            initial_file = "decrypted.txt"
        
        file_path = filedialog.asksaveasfilename(
            title="Save Encrypted File" if is_encrypted else "Save Decrypted File",
            initialdir=initial_dir,
            initialfile=initial_file,
            defaultextension=".enc" if is_encrypted else ".txt",
            filetypes=[
                ("Encrypted files", "*.enc") if is_encrypted else ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                # Ensure .enc extension for encrypted files
                if is_encrypted and not file_path.lower().endswith('.enc'):
                    file_path += '.enc'
                
                # Save the file
                mode = 'wb' if is_encrypted else 'w'
                with open(file_path, mode) as f:
                    if is_encrypted:
                        # Convert hex string to bytes for encrypted content
                        f.write(bytes.fromhex(content))
                    else:
                        f.write(content)
                
                messagebox.showinfo(
                    "Success",
                    f"{'Encrypted' if is_encrypted else 'Decrypted'} file saved successfully!"
                )
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to save file: {str(e)}"
                )
