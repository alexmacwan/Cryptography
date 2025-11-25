import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import json
import base64
import threading
from cryptography.fernet import Fernet
import paramiko
import requests
import pyotp
import qrcode
from PIL import Image, ImageTk
import tweepy
from facebook import GraphAPI
from telegram import Bot
import asyncio

class FileTransferTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.key = None
        self.sftp_client = None
        self.ssh_client = None
        self.mfa_secret = None
        
        # Load social media credentials from config file
        self.social_credentials = self.load_social_credentials()
        self.create_widgets()
        
    def create_widgets(self):
        # Social Media Frame
        social_frame = ttk.LabelFrame(self, text="Social Media Sharing")
        social_frame.pack(pady=10, padx=10, fill="x")
        
        # Social media platform selection
        ttk.Label(social_frame, text="Platform:").pack(side="left", padx=5)
        self.platform_var = tk.StringVar(value="twitter")
        platform_combo = ttk.Combobox(social_frame, textvariable=self.platform_var,
                                    values=["Twitter", "Facebook", "Telegram"])
        platform_combo.pack(side="left", padx=5)
        
        # Recipient/Channel input
        ttk.Label(social_frame, text="Recipient:").pack(side="left", padx=5)
        self.recipient_entry = ttk.Entry(social_frame)
        self.recipient_entry.pack(side="left", padx=5)
        
        # Share button
        self.share_btn = ttk.Button(social_frame, text="Share File",
                                  command=self.share_on_social)
        self.share_btn.pack(side="left", padx=5)
        
        # Server Connection Frame
        server_frame = ttk.LabelFrame(self, text="Server Connection")
        server_frame.pack(pady=10, padx=10, fill="x")
        
        # Server details
        ttk.Label(server_frame, text="Host:").pack(side="left", padx=5)
        self.host_entry = ttk.Entry(server_frame)
        self.host_entry.pack(side="left", padx=5)
        
        ttk.Label(server_frame, text="Port:").pack(side="left", padx=5)
        self.port_entry = ttk.Entry(server_frame, width=6)
        self.port_entry.insert(0, "22")
        self.port_entry.pack(side="left", padx=5)
        
        ttk.Label(server_frame, text="Username:").pack(side="left", padx=5)
        self.username_entry = ttk.Entry(server_frame)
        self.username_entry.pack(side="left", padx=5)
        
        self.password_var = tk.StringVar()
        ttk.Label(server_frame, text="Password:").pack(side="left", padx=5)
        self.password_entry = ttk.Entry(server_frame, show="*")
        self.password_entry.pack(side="left", padx=5)
        
        # Protocol selection
        protocol_frame = ttk.Frame(server_frame)
        protocol_frame.pack(pady=5, fill="x")
        
        self.protocol_var = tk.StringVar(value="sftp")
        ttk.Radiobutton(protocol_frame, text="SFTP", variable=self.protocol_var, 
                       value="sftp").pack(side="left", padx=5)
        ttk.Radiobutton(protocol_frame, text="HTTPS", variable=self.protocol_var, 
                       value="https").pack(side="left", padx=5)
        
        # MFA Frame
        mfa_frame = ttk.LabelFrame(self, text="Multi-Factor Authentication")
        mfa_frame.pack(pady=10, padx=10, fill="x")
        
        self.setup_mfa_btn = ttk.Button(mfa_frame, text="Setup MFA", 
                                       command=self.setup_mfa)
        self.setup_mfa_btn.pack(pady=5, padx=5, side=tk.LEFT)
        
        ttk.Label(mfa_frame, text="MFA Code:").pack(side="left", padx=5)
        self.mfa_entry = ttk.Entry(mfa_frame, width=6)
        self.mfa_entry.pack(side="left", padx=5)
        
        # Connect button
        self.connect_btn = ttk.Button(server_frame, text="Connect", 
                                    command=self.connect_to_server)
        self.connect_btn.pack(pady=5)
        
        # Key management
        key_frame = ttk.LabelFrame(self, text="Encryption Key")
        key_frame.pack(pady=10, padx=10, fill="x")
        
        # Add key name input field
        name_frame = ttk.Frame(key_frame)
        name_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(name_frame, text="Key Name:").pack(side="left", padx=(0, 5))
        self.key_name = ttk.Entry(name_frame)
        self.key_name.pack(side="left", fill="x", expand=True)
        
        button_frame = ttk.Frame(key_frame)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        generate_key_btn = ttk.Button(
            button_frame,
            text="Generate New Key",
            command=self.generate_key
        )
        generate_key_btn.pack(pady=5, padx=5, side=tk.LEFT)
        
        save_key_btn = ttk.Button(
            key_frame,
            text="Save Key",
            command=self.save_key
        )
        save_key_btn.pack(pady=5, padx=5, side=tk.LEFT)
        
        load_key_btn = ttk.Button(
            key_frame,
            text="Load Key",
            command=self.load_key
        )
        load_key_btn.pack(pady=5, padx=5, side=tk.LEFT)
        
        # File encryption
        encrypt_frame = ttk.LabelFrame(self, text="File Encryption")
        encrypt_frame.pack(pady=10, padx=10, fill="x")
        
        self.encrypt_path = ttk.Entry(encrypt_frame)
        self.encrypt_path.pack(pady=5, padx=5, fill="x", side=tk.LEFT, expand=True)
        
        browse_encrypt_btn = ttk.Button(
            encrypt_frame,
            text="Browse",
            command=lambda: self.browse_file(self.encrypt_path)
        )
        browse_encrypt_btn.pack(pady=5, padx=5, side=tk.LEFT)
        
        encrypt_btn = ttk.Button(
            encrypt_frame,
            text="Encrypt File",
            command=self.encrypt_file
        )
        encrypt_btn.pack(pady=5, padx=5)
        
        # File decryption
        decrypt_frame = ttk.LabelFrame(self, text="File Decryption")
        decrypt_frame.pack(pady=10, padx=10, fill="x")
        
        self.decrypt_path = ttk.Entry(decrypt_frame)
        self.decrypt_path.pack(pady=5, padx=5, fill="x", side=tk.LEFT, expand=True)
        
        browse_decrypt_btn = ttk.Button(
            decrypt_frame,
            text="Browse",
            command=lambda: self.browse_file(self.decrypt_path)
        )
        browse_decrypt_btn.pack(pady=5, padx=5, side=tk.LEFT)
        
        decrypt_btn = ttk.Button(
            decrypt_frame,
            text="Decrypt File",
            command=self.decrypt_file
        )
        decrypt_btn.pack(pady=5, padx=5)
        
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
            
        # Create keys directory if it doesn't exist
        keys_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
        os.makedirs(keys_dir, exist_ok=True)
            
        key_path = os.path.join(keys_dir, key_name)
        
        # Check if key already exists
        if os.path.exists(key_path):
            if not messagebox.askyesno(
                "Warning",
                f"Key '{key_name}' already exists. Do you want to overwrite it?"
            ):
                return
            
        self.key = Fernet.generate_key()
        # Store the key in the app's symmetric keys dictionary
        self.app.symmetric_keys[key_name] = self.key
        
        # Save key to file
        try:
            with open(key_path, 'wb') as f:
                f.write(self.key)
            messagebox.showinfo(
                "Success",
                f"New encryption key '{key_name}' generated and saved to:\n{key_path}"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to save key: {str(e)}"
            )
            return
            
        # Clear the input field
        self.key_name.delete(0, tk.END)
        
    def save_key(self):
        """Save the current key to a file"""
        if not self.key:
            messagebox.showerror(
                "Error",
                "No key to save! Generate one first."
            )
            return
            
        key_name = self.key_name.get().strip()
        if not key_name:
            messagebox.showerror(
                "Error",
                "Please enter a name for the key!"
            )
            return
            
        if not key_name.endswith('.key'):
            key_name += '.key'
            
        # Create keys directory if it doesn't exist
        keys_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
        os.makedirs(keys_dir, exist_ok=True)
        
        key_path = os.path.join(keys_dir, key_name)
        
        # Check if key already exists
        if os.path.exists(key_path):
            if not messagebox.askyesno(
                "Warning",
                f"Key '{key_name}' already exists. Do you want to overwrite it?"
            ):
                return
                
        try:
            with open(key_path, 'wb') as f:
                f.write(self.key)
            messagebox.showinfo(
                "Success",
                f"Key saved successfully to:\n{key_path}"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to save key: {str(e)}"
            )
                
    def load_key(self):
        """Load a key from file"""
        keys_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'keys')
        
        # Create keys directory if it doesn't exist
        os.makedirs(keys_dir, exist_ok=True)
        
        filename = filedialog.askopenfilename(
            title="Load Encryption Key",
            initialdir=keys_dir,
            filetypes=[("Key files", "*.key")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    self.key = f.read()
                key_name = os.path.basename(filename)
                self.app.symmetric_keys[key_name] = self.key
                self.key_name.delete(0, tk.END)
                self.key_name.insert(0, key_name)
                messagebox.showinfo(
                    "Success",
                    f"Key '{key_name}' loaded successfully!"
                )
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to load key: {str(e)}"
                )
                
    def browse_file(self, entry):
        """Open file browser and update entry"""
        filename = filedialog.askopenfilename(title="Select File")
        if filename:
            entry.delete(0, tk.END)
            entry.insert(0, filename)
            
    def setup_mfa(self):
        """Setup Multi-Factor Authentication"""
        self.mfa_secret = pyotp.random_base32()
        totp = pyotp.TOTP(self.mfa_secret)
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp.provisioning_uri("CryptoTool", issuer_name="SecureFileTransfer"))
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Show QR code in a new window
        qr_window = tk.Toplevel(self)
        qr_window.title("MFA Setup")
        
        # Convert PIL image to PhotoImage
        photo = ImageTk.PhotoImage(qr_image)
        label = ttk.Label(qr_window, image=photo)
        label.image = photo
        label.pack(padx=10, pady=10)
        
        ttk.Label(qr_window, text="Scan this QR code with your authenticator app").pack(pady=5)
        ttk.Label(qr_window, text=f"Secret key: {self.mfa_secret}").pack(pady=5)
        
    def verify_mfa(self):
        """Verify MFA code"""
        if not self.mfa_secret:
            messagebox.showerror("Error", "MFA not set up! Please set up MFA first.")
            return False
            
        mfa_code = self.mfa_entry.get().strip()
        if not mfa_code:
            messagebox.showerror("Error", "Please enter MFA code!")
            return False
            
        totp = pyotp.TOTP(self.mfa_secret)
        if totp.verify(mfa_code):
            return True
        else:
            messagebox.showerror("Error", "Invalid MFA code!")
            return False
            
    def connect_to_server(self):
        """Connect to server using selected protocol"""
        if not self.verify_mfa():
            return
            
        host = self.host_entry.get().strip()
        port = int(self.port_entry.get().strip())
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not all([host, username, password]):
            messagebox.showerror("Error", "Please fill in all connection details!")
            return
            
        protocol = self.protocol_var.get()
        
        try:
            if protocol == "sftp":
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_client.connect(host, port, username, password)
                self.sftp_client = self.ssh_client.open_sftp()
                messagebox.showinfo("Success", "Connected to SFTP server!")
            else:  # HTTPS
                # Test HTTPS connection
                response = requests.get(f"https://{host}:{port}/test",
                                      auth=(username, password),
                                      verify=True)
                response.raise_for_status()
                messagebox.showinfo("Success", "Connected to HTTPS server!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            self.disconnect()
            
    def disconnect(self):
        """Disconnect from server"""
        if self.sftp_client:
            self.sftp_client.close()
            self.sftp_client = None
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            
    def encrypt_file(self):
        """Encrypt a file"""
        if not self.key:
            messagebox.showerror(
                "Error",
                "No encryption key! Generate or load one first."
            )
            return
            
        input_path = self.encrypt_path.get()
        if not input_path or not os.path.exists(input_path):
            messagebox.showerror(
                "Error",
                "Please select a valid file to encrypt!"
            )
            return
            
        output_path = input_path + '.encrypted'
        
        try:
            f = Fernet(self.key)
            with open(input_path, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = f.encrypt(file_data)
            
            with open(output_path, 'wb') as file:
                file.write(encrypted_data)
                
            # If connected to server, upload the encrypted file
            if self.sftp_client:
                remote_path = os.path.basename(output_path)
                self.sftp_client.put(output_path, remote_path)
                messagebox.showinfo(
                    "Success",
                    f"File encrypted and uploaded to server!\nRemote path: {remote_path}"
                )
            else:
                messagebox.showinfo(
                    "Success",
                    f"File encrypted successfully!\nSaved as: {output_path}"
                )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to encrypt/upload file: {str(e)}"
            )
            
    def download_and_decrypt(self, remote_filename):
        """Download and decrypt a file from the server"""
        try:
            # Create a temporary file to store the downloaded encrypted data
            temp_path = os.path.join(os.path.dirname(self.decrypt_path.get()), remote_filename)
            self.sftp_client.get(remote_filename, temp_path)
            
            # Decrypt the downloaded file
            output_path = temp_path.replace('.encrypted', '_decrypted')
            
            f = Fernet(self.key)
            with open(temp_path, 'rb') as file:
                encrypted_data = file.read()
                
            decrypted_data = f.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
                
            # Clean up temporary file
            os.remove(temp_path)
            
            messagebox.showinfo(
                "Success",
                f"File downloaded and decrypted successfully!\nSaved as: {output_path}"
            )
            
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to download/decrypt file: {str(e)}"
            )
            
    def decrypt_file(self):
        """Decrypt a file"""
        if not self.key:
            messagebox.showerror(
                "Error",
                "No encryption key! Generate or load one first."
            )
            return

        # If connected to server, show remote file selection dialog
        if self.sftp_client:
            try:
                remote_files = self.sftp_client.listdir()
                encrypted_files = [f for f in remote_files if f.endswith('.encrypted')]
                
                if not encrypted_files:
                    messagebox.showerror(
                        "Error",
                        "No encrypted files found on server!"
                    )
                    return
                    
                # Create file selection dialog
                dialog = tk.Toplevel(self)
                dialog.title("Select Remote File")
                dialog.geometry("300x200")
                
                listbox = tk.Listbox(dialog)
                listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                for file in encrypted_files:
                    listbox.insert(tk.END, file)
                    
                def on_select():
                    selection = listbox.get(listbox.curselection())
                    dialog.destroy()
                    self.download_and_decrypt(selection)
                    
                ttk.Button(dialog, text="Select", command=on_select).pack(pady=5)
                
                return
                
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to list remote files: {str(e)}"
                )
                return
                
        # Local file decryption
        input_path = self.decrypt_path.get()
        if not input_path or not os.path.exists(input_path):
            messagebox.showerror(
                "Error",
                "Please select a valid file to decrypt!"
            )
            return
            
        output_path = input_path.replace('.encrypted', '.decrypted')
        
        try:
            f = Fernet(self.key)
            with open(input_path, 'rb') as file:
                encrypted_data = file.read()
                
            decrypted_data = f.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
                
            messagebox.showinfo(
                "Success",
                f"File decrypted successfully!\nSaved as: {output_path}"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to decrypt file: {str(e)}"
            )
            
    def share_on_social(self):
        """Share encrypted file on selected social media platform"""
        if not self.key:
            messagebox.showerror("Error", "Generate or load an encryption key first!")
            return
            
        # Get the file to share
        file_path = filedialog.askopenfilename(title="Select File to Share",
                                             filetypes=[("Encrypted files", "*.encrypted")])
        if not file_path:
            return
            
        platform = self.platform_var.get().lower()
        recipient = self.recipient_entry.get().strip()
        
        if not recipient:
            messagebox.showerror("Error", "Please enter a recipient!")
            return
            
        try:
            # First encrypt the file if it's not already encrypted
            if not file_path.endswith('.encrypted'):
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = Fernet(self.key).encrypt(data)
                file_path = file_path + '.encrypted'
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
            
            # Share based on selected platform
            if platform == 'twitter':
                self.share_on_twitter(file_path, recipient)
            elif platform == 'facebook':
                self.share_on_facebook(file_path, recipient)
            elif platform == 'telegram':
                asyncio.run(self.share_on_telegram(file_path, recipient))
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to share file: {str(e)}")
            
    def share_on_twitter(self, file_path, recipient):
        """Share file on Twitter"""
        auth = tweepy.OAuthHandler(
            self.social_credentials['twitter']['api_key'],
            self.social_credentials['twitter']['api_secret']
        )
        auth.set_access_token(
            self.social_credentials['twitter']['access_token'],
            self.social_credentials['twitter']['access_token_secret']
        )
        api = tweepy.API(auth)
        
        # Upload file
        media = api.media_upload(file_path)
        # Send direct message with file
        api.send_direct_message(recipient, attachment_type='media',
                              attachment_media_id=media.media_id)
        messagebox.showinfo("Success", "File shared on Twitter!")
        
    def share_on_facebook(self, file_path, recipient):
        """Share file on Facebook"""
        graph = GraphAPI(self.social_credentials['facebook']['access_token'])
        
        # Upload file to Facebook
        with open(file_path, 'rb') as f:
            graph.put_photo(f, album_path=f"{recipient}/photos")
        messagebox.showinfo("Success", "File shared on Facebook!")
        
    async def share_on_telegram(self, file_path, recipient):
        """Share file on Telegram"""
        bot = Bot(token=self.social_credentials['telegram']['bot_token'])
        
        with open(file_path, 'rb') as f:
            await bot.send_document(chat_id=recipient, document=f)
        messagebox.showinfo("Success", "File shared on Telegram!")
        
    def load_social_credentials(self):
        """Load social media credentials from config file"""
        try:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                      'config', 'social_media_config.json')
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to load social media credentials: {str(e)}\n"
                "Please configure your credentials in config/social_media_config.json"
            )
            return {
                'twitter': {'api_key': '', 'api_secret': '', 'access_token': '', 'access_token_secret': ''},
                'facebook': {'access_token': ''},
                'telegram': {'bot_token': ''}
            }
            
    def __del__(self):
        """Clean up resources when the tab is destroyed"""
        self.disconnect()
