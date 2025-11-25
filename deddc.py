# tabs/asymmetric_tab.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class AsymmetricTab:
    def __init__(self, notebook, parent):
        self.parent = parent
        self.frame = ttk.Frame(notebook, style='Card.TFrame')
        
        # Add tab to notebook
        notebook.add(self.frame, text="🔐 Asymmetric Encryption")
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create asymmetric encryption widgets"""
        main_frame = ttk.Frame(self.frame, style='Card.TFrame')
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Asymmetric Encryption (RSA)",
            style='Section.TLabel'
        )
        title_label.pack(anchor="w", pady=(0, 20))
        
        # Create notebook for encryption/decryption
        operation_notebook = ttk.Notebook(main_frame)
        operation_notebook.pack(expand=True, fill="both")
        
        # Encryption tab
        self.create_encryption_tab(operation_notebook)
        
        # Decryption tab
        self.create_decryption_tab(operation_notebook)
        
        # Key exchange explanation
        self.create_key_exchange_explanation(main_frame)
    
    def create_encryption_tab(self, notebook):
        """Create encryption interface"""
        encrypt_frame = ttk.Frame(notebook, style='Card.TFrame')
        notebook.add(encrypt_frame, text="🔒 Encrypt")
        
        # Key selection section
        key_section = ttk.LabelFrame(encrypt_frame, text="Select Recipient's Public Key", padding=15)
        key_section.pack(fill="x", pady=(0, 20))
        
        key_frame = ttk.Frame(key_section)
        key_frame.pack(fill="x")
        
        ttk.Label(key_frame, text="Public Key:").pack(side="left", padx=(0, 10))
        
        self.encrypt_key_var = tk.StringVar(value="No key selected")
        key_combo = ttk.Combobox(
            key_frame,
            textvariable=self.encrypt_key_var,
            values=list(self.parent.public_keys.keys()),
            state="readonly",
            width=30
        )
        key_combo.pack(side="left", padx=(0, 10))
        
        refresh_btn = ttk.Button(
            key_frame,
            text="🔄",
            command=self.refresh_public_keys,
            width=3
        )
        refresh_btn.pack(side="left")
        
        # Import key button
        import_btn = ttk.Button(
            key_frame,
            text="Import Public Key",
            command=self.import_public_key,
            style="Secondary.TButton"
        )
        import_btn.pack(side="right")
        
        # Input section
        input_section = ttk.LabelFrame(encrypt_frame, text="Message to Encrypt", padding=15)
        input_section.pack(fill="both", expand=True, pady=(0, 20))
        
        self.encrypt_input = tk.Text(
            input_section,
            height=8,
            wrap=tk.WORD,
            font=('Consolas', 11)
        )
        self.encrypt_input.pack(fill="both", expand=True)
        
        # Control buttons
        control_frame = ttk.Frame(encrypt_frame)
        control_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Button(
            control_frame,
            text="📁 Load from File",
            command=self.load_encrypt_file,
            style="Secondary.TButton"
        ).pack(side="left", padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="🔒 Encrypt Message",
            command=self.encrypt_message,
            style="Primary.TButton"
        ).pack(side="right")
        
        # Output section
        output_section = ttk.LabelFrame(encrypt_frame, text="Encrypted Output", padding=15)
        output_section.pack(fill="both", expand=True)
        
        self.encrypt_output = tk.Text(
            output_section,
            height=8,
            wrap=tk.WORD,
            font=('Consolas', 11),
            state=tk.DISABLED
        )
        self.encrypt_output.pack(fill="both", expand=True, pady=(0, 10))
        
        # Output controls
        output_control_frame = ttk.Frame(output_section)
        output_control_frame.pack(fill="x")
        
        ttk.Button(
            output_control_frame,
            text="📋 Copy",
            command=self.copy_encrypted,
            style="Secondary.TButton"
        ).pack(side="left", padx=(0, 10))
        
        ttk.Button(
            output_control_frame,
            text="💾 Save to File",
            command=self.save_encrypted_file,
            style="Secondary.TButton"
        ).pack(side="right")
    
    def create_decryption_tab(self, notebook):
        """Create decryption interface"""
        decrypt_frame = ttk.Frame(notebook, style='Card.TFrame')
        notebook.add(decrypt_frame, text="🔓 Decrypt")
        
        # Key selection section
        key_section = ttk.LabelFrame(decrypt_frame, text="Select Your Private Key", padding=15)
        key_section.pack(fill="x", pady=(0, 20))
        
        key_frame = ttk.Frame(key_section)
        key_frame.pack(fill="x")
        
        ttk.Label(key_frame, text="Private Key:").pack(side="left", padx=(0, 10))
        
        self.decrypt_key_var = tk.StringVar(value="No key selected")
        key_combo = ttk.Combobox(
            key_frame,
            textvariable=self.decrypt_key_var,
            values=list(self.parent.private_keys.keys()),
            state="readonly",
            width=30
        )
        key_combo.pack(side="left", padx=(0, 10))
        
        refresh_btn = ttk.Button(
            key_frame,
            text="🔄",
            command=self.refresh_private_keys,
            width=3
        )
        refresh_btn.pack(side="left")
        
        # Import key button
        import_btn = ttk.Button(
            key_frame,
            text="Import Private Key",
            command=self.import_private_key,
            style="Secondary.TButton"
        )
        import_btn.pack(side="right")
        
        # Input section
        input_section = ttk.LabelFrame(decrypt_frame, text="Encrypted Message", padding=15)
        input_section.pack(fill="both", expand=True, pady=(0, 20))
        
        self.decrypt_input = tk.Text(
            input_section,
            height=8,
            wrap=tk.WORD,
            font=('Consolas', 11)
        )
        self.decrypt_input.pack(fill="both", expand=True)
        
        # Control buttons
        control_frame = ttk.Frame(decrypt_frame)
        control_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Button(
            control_frame,
            text="📁 Load from File",
            command=self.load_decrypt_file,
            style="Secondary.TButton"
        ).pack(side="left", padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="🔓 Decrypt Message",
            command=self.decrypt_message,
            style="Primary.TButton"
        ).pack(side="right")
        
        # Output section
        output_section = ttk.LabelFrame(decrypt_frame, text="Decrypted Output", padding=15)
        output_section.pack(fill="both", expand=True)
        
        self.decrypt_output = tk.Text(
            output_section,
            height=8,
            wrap=tk.WORD,
            font=('Consolas', 11),
            state=tk.DISABLED
        )
        self.decrypt_output.pack(fill="both", expand=True, pady=(0, 10))
        
        # Output controls
        output_control_frame = ttk.Frame(output_section)
        output_control_frame.pack(fill="x")
        
        ttk.Button(
            output_control_frame,
            text="📋 Copy",
            command=self.copy_decrypted,
            style="Secondary.TButton"
        ).pack(side="left", padx=(0, 10))
        
        ttk.Button(
            output_control_frame,
            text="💾 Save to File",
            command=self.save_decrypted_file,
            style="Secondary.TButton"
        ).pack(side="right")
    
    def create_key_exchange_explanation(self, parent):
        """Create explanation of key exchange process"""
        explanation_frame = ttk.LabelFrame(parent, text="How Asymmetric Encryption Works", padding=15)
        explanation_frame.pack(fill="x", pady=(20, 0))
        
        explanation_text = """
🔑 Key Exchange Process:

1. Each person generates a key pair (public key + private key)
2. Public keys are shared openly, private keys are kept secret
3. To send encrypted message: Use recipient's PUBLIC key to encrypt
4. To read encrypted message: Use your own PRIVATE key to decrypt

Example:
• Alice wants to send a message to Bob
• Alice encrypts using Bob's public key
• Bob decrypts using Bob's private key
• Only Bob can read the message (only he has his private key)

⚠️ Important: You can only decrypt messages that were encrypted with YOUR public key!
        """.strip()
        
        explanation_label = ttk.Label(
            explanation_frame,
            text=explanation_text,
            justify="left",
            font=('Segoe UI', 10)
        )
        explanation_label.pack(anchor="w")
    
    def refresh_public_keys(self):
        """Refresh public key dropdown"""
        key_values = list(self.parent.public_keys.keys())
        # Find the combobox and update its values
        for widget in self.frame.winfo_children():
            if isinstance(widget, ttk.Frame):
                self._update_combobox_values(widget, "encrypt_key_var", key_values)
    
    def refresh_private_keys(self):
        """Refresh private key dropdown"""
        key_values = list(self.parent.private_keys.keys())
        # Find the combobox and update its values
        for widget in self.frame.winfo_children():
            if isinstance(widget, ttk.Frame):
                self._update_combobox_values(widget, "decrypt_key_var", key_values)
    
    def _update_combobox_values(self, parent, var_name, values):
        """Helper method to update combobox values recursively"""
        for widget in parent.winfo_children():
            if isinstance(widget, ttk.Combobox):
                if hasattr(self, var_name) and widget['textvariable'] == str(getattr(self, var_name)):
                    widget['values'] = values
            elif hasattr(widget, 'winfo_children'):
                self._update_combobox_values(widget, var_name, values)
    
    def import_public_key(self):
        """Import a public key from file"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select Public Key File",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'rb') as f:
                    key_data = f.read()
                
                # Load the public key
                public_key = serialization.load_pem_public_key(key_data)
                
                # Ask for key name
                key_name = tk.simpledialog.askstring("Key Name", "Enter a name for this public key:")
                if key_name:
                    self.parent.public_keys[key_name] = public_key
                    self.refresh_public_keys()
                    self.parent.update_status(f"Public key '{key_name}' imported successfully")
                    messagebox.showinfo("Success", f"Public key '{key_name}' imported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import public key: {str(e)}")
    
    def import_private_key(self):
        """Import a private key from file"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select Private Key File",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'rb') as f:
                    key_data = f.read()
                
                # Load the private key
                private_key = serialization.load_pem_private_key(key_data, password=None)
                
                # Ask for key name
                key_name = tk.simpledialog.askstring("Key Name", "Enter a name for this private key:")
                if key_name:
                    self.parent.private_keys[key_name] = private_key
                    self.refresh_private_keys()
                    self.parent.update_status(f"Private key '{key_name}' imported successfully")
                    messagebox.showinfo("Success", f"Private key '{key_name}' imported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import private key: {str(e)}")
    
    def encrypt_message(self):
        """Encrypt message using selected public key"""
        try:
            # Get selected key
            key_name = self.encrypt_key_var.get()
            if key_name == "No key selected" or key_name not in self.parent.public_keys:
                messagebox.showerror("Error", "Please select a valid public key")
                return
            
            # Get message
            message = self.encrypt_input.get("1.0", tk.END).strip()
            if not message:
                messagebox.showerror("Error", "Please enter a message to encrypt")
                return
            
            # Get public key
            public_key = self.parent.public_keys[key_name]
            
            # Encrypt message
            encrypted_data = public_key.encrypt(
                message.encode('utf-8'),
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encode to base64 for display
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Display result
            self.encrypt_output.config(state=tk.NORMAL)
            self.encrypt_output.delete("1.0", tk.END)
            self.encrypt_output.insert("1.0", encrypted_b64)
            self.encrypt_output.config(state=tk.DISABLED)
            
            self.parent.update_status(f"Message encrypted successfully using key '{key_name}'")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_message(self):
        """Decrypt message using selected private key"""
        try:
            # Get selected key
            key_name = self.decrypt_key_var.get()
            if key_name == "No key selected" or key_name not in self.parent.private_keys:
                messagebox.showerror("Error", "Please select a valid private key")
                return
            
            # Get encrypted message
            encrypted_b64 = self.decrypt_input.get("1.0", tk.END).strip()
            if not encrypted_b64:
                messagebox.showerror("Error", "Please enter an encrypted message to decrypt")
                return
            
            # Get private key
            private_key = self.parent.private_keys[key_name]
            
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_b64)
            
            # Decrypt message
            decrypted_data = private_key.decrypt(
                encrypted_data,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decode to string
            decrypted_message = decrypted_data.decode('utf-8')
            
            # Display result
            self.decrypt_output.config(state=tk.NORMAL)
            self.decrypt_output.delete("1.0", tk.END)
            self.decrypt_output.insert("1.0", decrypted_message)
            self.decrypt_output.config(state=tk.DISABLED)
            
            self.parent.update_status(f"Message decrypted successfully using key '{key_name}'")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def load_encrypt_file(self):
        """Load text from file for encryption"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select file to encrypt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.encrypt_input.delete("1.0", tk.END)
                self.encrypt_input.insert("1.0", content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def load_decrypt_file(self):
        """Load encrypted text from file for decryption"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select encrypted file",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.decrypt_input.delete("1.0", tk.END)
                self.decrypt_input.insert("1.0", content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def copy_encrypted(self):
        """Copy encrypted text to clipboard"""
        try:
            encrypted_text = self.encrypt_output.get("1.0", tk.END).strip()
            if encrypted_text:
                self.parent.root.clipboard_clear()
                self.parent.root.clipboard_append(encrypted_text)
                self.parent.update_status("Encrypted text copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")
    
    def copy_decrypted(self):
        """Copy decrypted text to clipboard"""
        try:
            decrypted_text = self.decrypt_output.get("1.0", tk.END).strip()
            if decrypted_text:
                self.parent.root.clipboard_clear()
                self.parent.root.clipboard_append(decrypted_text)
                self.parent.update_status("Decrypted text copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")
    
    def save_encrypted_file(self):
        """Save encrypted text to file"""
        try:
            encrypted_text = self.encrypt_output.get("1.0", tk.END).strip()
            if not encrypted_text:
                messagebox.showerror("Error", "No encrypted text to save")
                return
            
            file_path = filedialog.asksaveasfilename(
                title="Save encrypted file",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(encrypted_text)
                self.parent.update_status(f"Encrypted text saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def save_decrypted_file(self):
        """Save decrypted text to file"""
        try:
            decrypted_text = self.decrypt_output.get("1.0", tk.END).strip()
            if not decrypted_text:
                messagebox.showerror("Error", "No decrypted text to save")
                return
            
            file_path = filedialog.asksaveasfilename(
                title="Save decrypted file",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(decrypted_text)
                self.parent.update_status(f"Decrypted text saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")