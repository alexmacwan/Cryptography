import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.fernet import Fernet
import base64
import os
import datetime

# Define folder paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, 'keys', 'symmetric')
ENCRYPTED_FILES_DIR = os.path.join(BASE_DIR, 'encrypted_files', 'symmetric')

# Create directories if they don't exist
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_FILES_DIR, exist_ok=True)

class SymmetricTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.key = None
        self.create_widgets()
        
    def create_widgets(self):
        # Key management
        key_frame = ttk.LabelFrame(self, text="Key Management")
        key_frame.pack(pady=10, padx=10, fill="x")
        
        # Add key name input field
        name_frame = ttk.Frame(key_frame)
        name_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(name_frame, text="Key Name:").pack(side="left", padx=(0, 5))
        self.key_name = ttk.Entry(name_frame)
        self.key_name.pack(side="left", fill="x", expand=True)
        
        generate_key_btn = ttk.Button(
            key_frame,
            text="Generate New Key",
            command=self.generate_key
        )
        generate_key_btn.pack(pady=5, padx=5)
        
        # Encryption section
        encrypt_frame = ttk.LabelFrame(self, text="Encryption")
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
        decrypt_frame = ttk.LabelFrame(self, text="Decryption")
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
        
    def generate_key(self):
        """Generate a new Fernet key"""
        key_name = self.key_name.get().strip()
        if not key_name:
            messagebox.showerror(
                "Error",
                "Please enter a name for the key!"
            )
            return
            
        if not key_name.endswith('.key'):
            key_name += '.key'
            
        # Check if key already exists
        key_path = os.path.join(KEYS_DIR, key_name)
        if os.path.exists(key_path):
            if not messagebox.askyesno(
                "Key Exists",
                f"A key with name '{key_name}' already exists! Do you want to replace it?"
            ):
                return
                
        try:
            # Generate new key
            self.key = Fernet.generate_key()
            
            # Save key to file
            with open(key_path, 'wb') as f:
                f.write(self.key)
            
            # Store the key in the controller's symmetric keys dictionary
            self.controller.symmetric_keys[key_name] = self.key
            
            messagebox.showinfo(
                "Success",
                f"New key '{key_name}' generated and saved to {key_path}"
            )
            # Clear the input field
            self.key_name.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to generate key: {str(e)}"
            )
        
    def encrypt_text(self):
        """Encrypt the plaintext"""
        if not self.key:
            messagebox.showerror(
                "Error",
                "Please generate a key first!"
            )
            return
            
        plaintext = self.plaintext.get("1.0", "end-1c")
        if not plaintext:
            messagebox.showerror(
                "Error",
                "Please enter text to encrypt!"
            )
            return
            
        f = Fernet(self.key)
        ciphertext = f.encrypt(plaintext.encode())
        self.ciphertext.delete("1.0", "end")
        self.ciphertext.insert("1.0", ciphertext.decode())
        
    def decrypt_text(self):
        """Decrypt the ciphertext"""
        if not self.key:
            messagebox.showerror(
                "Error",
                "Please generate a key first!"
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
            f = Fernet(self.key)
            plaintext = f.decrypt(ciphertext.encode())
            self.plaintext.delete("1.0", "end")
            self.plaintext.insert("1.0", plaintext.decode())
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Decryption failed: {str(e)}"
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
                        # For encrypted files, read as bytes and decode to string
                        content = file.read().decode()
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
                        f.write(content.encode())
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
