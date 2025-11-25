import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class KeyManagementTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.keys_dir = os.path.join(os.path.dirname(__file__), "..", "keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        self.create_widgets()
        
    def create_widgets(self):
        # Symmetric key section
        sym_frame = ttk.LabelFrame(self, text="Symmetric Keys")
        sym_frame.pack(pady=10, padx=10, fill="x")
        
        # Add key name input field for symmetric keys
        sym_name_frame = ttk.Frame(sym_frame)
        sym_name_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(sym_name_frame, text="Key Name:").pack(side="left", padx=(0, 5))
        self.sym_key_name = ttk.Entry(sym_name_frame)
        self.sym_key_name.pack(side="left", fill="x", expand=True)
        
        generate_sym_btn = ttk.Button(
            sym_frame,
            text="Generate New Key",
            command=self.generate_symmetric_key
        )
        generate_sym_btn.pack(pady=5, padx=5)
        
        save_sym_btn = ttk.Button(
            sym_frame,
            text="Save Key",
            command=self.save_symmetric_key
        )
        save_sym_btn.pack(pady=5, padx=5)
        
        load_sym_btn = ttk.Button(
            sym_frame,
            text="Load Key",
            command=self.load_symmetric_key
        )
        load_sym_btn.pack(pady=5, padx=5)
        
        # Asymmetric key section
        asym_frame = ttk.LabelFrame(self, text="Asymmetric Keys")
        asym_frame.pack(pady=10, padx=10, fill="x")
        
        # Add key name input field for asymmetric keys
        asym_name_frame = ttk.Frame(asym_frame)
        asym_name_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(asym_name_frame, text="Key Pair Name:").pack(side="left", padx=(0, 5))
        self.asym_key_name = ttk.Entry(asym_name_frame)
        self.asym_key_name.pack(side="left", fill="x", expand=True)
        
        generate_asym_btn = ttk.Button(
            asym_frame,
            text="Generate Key Pair",
            command=self.generate_asymmetric_keys
        )
        generate_asym_btn.pack(pady=5, padx=5)
        
        save_priv_btn = ttk.Button(
            asym_frame,
            text="Save Private Key",
            command=self.save_private_key
        )
        save_priv_btn.pack(pady=5, padx=5)
        
        save_pub_btn = ttk.Button(
            asym_frame,
            text="Save Public Key",
            command=self.save_public_key
        )
        save_pub_btn.pack(pady=5, padx=5)
        
        load_priv_btn = ttk.Button(
            asym_frame,
            text="Load Private Key",
            command=self.load_private_key
        )
        load_priv_btn.pack(pady=5, padx=5)
        
        load_pub_btn = ttk.Button(
            asym_frame,
            text="Load Public Key",
            command=self.load_public_key
        )
        load_pub_btn.pack(pady=5, padx=5)
        
    def generate_symmetric_key(self):
        """Generate a new Fernet key"""
        key_name = self.sym_key_name.get().strip()
        if not key_name:
            messagebox.showerror(
                "Error",
                "Please enter a name for the key!"
            )
            return
            
        self.symmetric_key = Fernet.generate_key()
        # Store the key in the app's symmetric keys dictionary
        self.app.symmetric_keys[key_name] = self.symmetric_key
        messagebox.showinfo(
            "Success",
            f"New symmetric key '{key_name}' generated!"
        )
        # Clear the input field
        self.sym_key_name.delete(0, tk.END)
        
    def save_symmetric_key(self):
        """Save symmetric key to file"""
        if not hasattr(self, 'symmetric_key'):
            messagebox.showerror(
                "Error",
                "No key to save! Generate one first."
            )
            return
            
        filename = filedialog.asksaveasfilename(
            initialdir=self.keys_dir,
            title="Save Symmetric Key",
            filetypes=[("Key files", "*.key")]
        )
        
        if filename:
            with open(filename, 'wb') as f:
                f.write(self.symmetric_key)
                
    def load_symmetric_key(self):
        """Load symmetric key from file"""
        filename = filedialog.askopenfilename(
            initialdir=self.keys_dir,
            title="Load Symmetric Key",
            filetypes=[("Key files", "*.key")]
        )
        
        if filename:
            with open(filename, 'rb') as f:
                self.symmetric_key = f.read()
                messagebox.showinfo(
                    "Success",
                    "Key loaded successfully!"
                )
                
    def generate_asymmetric_keys(self):
        """Generate new RSA key pair"""
        key_name = self.asym_key_name.get().strip()
        if not key_name:
            messagebox.showerror(
                "Error",
                "Please enter a name for the key pair!"
            )
            return
            
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        self.private_key = private_key
        self.public_key = public_key
        
        # Store the keys in the app's key dictionaries
        self.app.private_keys[key_name] = private_key
        self.app.public_keys[key_name] = public_key
        
        messagebox.showinfo(
            "Success",
            f"New key pair '{key_name}' generated!"
        )
        # Clear the input field
        self.asym_key_name.delete(0, tk.END)
        
    def save_private_key(self):
        """Save private key to file"""
        if not hasattr(self, 'private_key'):
            messagebox.showerror(
                "Error",
                "No private key to save! Generate one first."
            )
            return
            
        filename = filedialog.asksaveasfilename(
            initialdir=self.keys_dir,
            title="Save Private Key",
            filetypes=[("PEM files", "*.pem")]
        )
        
        if filename:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(filename, 'wb') as f:
                f.write(pem)
                
    def save_public_key(self):
        """Save public key to file"""
        if not hasattr(self, 'public_key'):
            messagebox.showerror(
                "Error",
                "No public key to save! Generate one first."
            )
            return
            
        filename = filedialog.asksaveasfilename(
            initialdir=self.keys_dir,
            title="Save Public Key",
            filetypes=[("PEM files", "*.pem")]
        )
        
        if filename:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(filename, 'wb') as f:
                f.write(pem)
                
    def load_private_key(self):
        """Load private key from file"""
        filename = filedialog.askopenfilename(
            initialdir=self.keys_dir,
            title="Load Private Key",
            filetypes=[("PEM files", "*.pem")]
        )
        
        if filename:
            with open(filename, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
                self.public_key = self.private_key.public_key()
                messagebox.showinfo(
                    "Success",
                    "Private key loaded successfully!"
                )
                
    def load_public_key(self):
        """Load public key from file"""
        filename = filedialog.askopenfilename(
            initialdir=self.keys_dir,
            title="Load Public Key",
            filetypes=[("PEM files", "*.pem")]
        )
        
        if filename:
            with open(filename, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read()
                )
                messagebox.showinfo(
                    "Success",
                    "Public key loaded successfully!"
                )
