import tkinter as tk
from tkinter import ttk, messagebox
import os
import json
from cryptography.fernet import Fernet
from tabs import (
    HomeTab,
    SymmetricTab,
    AsymmetricTab,
    HashTab,
    KeyManagementTab,
    DigitalSignatureTab,
    PasswordManagementTab,
    FileTransferTab
)
from cryptography.hazmat.primitives import serialization

class CryptoTool:
    def __init__(self, root):
        """Initialize the main application window."""
        self.root = root
        self.root.title("Secure Encryption Tool")
        self.root.geometry("800x600")
            
        # Initialize variables
        self.initialize_variables()
        
        # Configure styles
        self.configure_styles()
        
        # Load saved keys
        self.load_keys()
                
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)
        
        # Create tabs
        self.create_tabs()
        
        # Create status bar
        self.create_status_bar()
        
        # Set up window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def initialize_variables(self):
        """Initialize tkinter variables."""
        self.current_key_name = tk.StringVar(value="No key selected")
        self.current_public_key_name = tk.StringVar(value="No key selected")
        self.current_private_key_name = tk.StringVar(value="No key selected")
        self.server_host = tk.StringVar(value="localhost")
        self.server_port = tk.StringVar(value="5000")
        self.transfer_file_var = tk.StringVar()
        
        # Initialize key storage
        self.symmetric_keys = {}
        self.public_keys = {}
        self.private_keys = {}

    def configure_styles(self):
        """Configure ttk styles for the application"""
        style = ttk.Style()
        
        # Configure Notebook style
        style.configure("TNotebook", background='#f0f0f0', borderwidth=0)
        style.configure("TNotebook.Tab", padding=[15, 5], font=('Helvetica', 10))
        style.map("TNotebook.Tab",
                 background=[("selected", "#4a90e2"), ("!selected", "#f0f0f0")],
                 foreground=[("selected", "#ffffff"), ("!selected", "#333333")])
        
        # Configure Frame styles
        style.configure("Main.TFrame", background='#ffffff')
        style.configure("Card.TFrame", background='#ffffff', relief='solid', borderwidth=1)
        
        # Configure Label styles
        style.configure("Header.TLabel", font=('Helvetica', 16, 'bold'), background='#ffffff')
        style.configure("Subheader.TLabel", font=('Helvetica', 12), background='#ffffff')
        style.configure("Status.TLabel", font=('Helvetica', 10), background='#f0f0f0')
        
        # Configure Button styles
        style.configure("Primary.TButton", padding=[20, 10], font=('Helvetica', 10))
        style.configure("Secondary.TButton", padding=[15, 8], font=('Helvetica', 10))
        
        # Configure Entry style
        style.configure("TEntry", padding=[5, 5])
        
        # Configure Labelframe style
        style.configure("Card.TLabelframe", background='#ffffff', relief='solid', borderwidth=1)
        style.configure("Card.TLabelframe.Label",
                      font=('Helvetica', 11, 'bold'),
                      background='#ffffff',
                      foreground='#333333')

    def create_tabs(self):
        """Create all application tabs"""
        self.tabs = {
            'home': HomeTab(self.notebook, self),
            'symmetric': SymmetricTab(self.notebook, self),
            'asymmetric': AsymmetricTab(self.notebook, self),
            'hash': HashTab(self.notebook, self),
            'key_management': KeyManagementTab(self.notebook, self),
            'digital_signature': DigitalSignatureTab(self.notebook, self),
            'password_management': PasswordManagementTab(self.notebook, self),
            'file_transfer': FileTransferTab(self.notebook, self)
        }

    def create_status_bar(self):
        """Create the status bar"""
        status_frame = ttk.Frame(self.root, style="Main.TFrame")
        status_frame.pack(side="bottom", fill="x")
        status_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="Status:", style="Status.TLabel").grid(row=0, column=0, padx=(0, 5))
        ttk.Label(status_frame, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=1, sticky="w")
            
    def update_status(self, message):
        """Update the status bar message"""
        self.status_var.set(message)

    def on_closing(self):
        """Handle window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.save_keys()
            self.root.destroy()

    def load_keys(self):
        """Load saved keys from files."""
        try:
            # Load symmetric keys
            if os.path.exists("symmetric_keys.json"):
                with open("symmetric_keys.json", "r") as f:
                    key_data = json.loads(f.read())
                    self.symmetric_keys = {name: key.encode() for name, key in key_data.items()}

            # Load asymmetric keys
            if os.path.exists("keypairs.json"):
                with open("keypairs.json", "r") as f:
                    keypair_data = json.loads(f.read())
                    for name, pair in keypair_data.items():
                        # Load private key
                        private_key = serialization.load_pem_private_key(
                            pair["private"].encode(),
                            password=None
                        )
                        self.private_keys[name] = private_key

                        # Load public key
                        public_key = serialization.load_pem_public_key(
                            pair["public"].encode()
                        )
                        self.public_keys[name] = public_key

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {str(e)}")
            # Initialize empty if loading fails
            self.symmetric_keys = {}
            self.public_keys = {}
            self.private_keys = {}

    def save_keys(self):
        """Save keys to files."""
        try:
            # Save symmetric keys
            symmetric_data = {name: key.decode() for name, key in self.symmetric_keys.items()}
            with open("symmetric_keys.json", "w") as f:
                json.dump(symmetric_data, f)

            # Save asymmetric keys
            keypair_data = {}
            for name in self.private_keys.keys():
                private_pem = self.private_keys[name].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
            )
                public_pem = self.public_keys[name].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
                keypair_data[name] = {
                    "private": private_pem.decode(),
                    "public": public_pem.decode()
                }
            with open("keypairs.json", "w") as f:
                json.dump(keypair_data, f)

    except Exception as e:
            messagebox.showerror("Error", f"Failed to save keys: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoTool(root)
    root.mainloop()