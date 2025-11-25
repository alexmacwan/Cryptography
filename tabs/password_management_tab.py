import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from cryptography.fernet import Fernet
import base64
import secrets
import string

class PasswordManagementTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.passwords_file = os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "passwords.enc"
        )
        self.key_file = os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "master.key"
        )
        os.makedirs(os.path.dirname(self.passwords_file), exist_ok=True)
        self.load_or_create_key()
        self.create_widgets()
        self.load_passwords()
        
    def create_widgets(self):
        # Password list
        list_frame = ttk.LabelFrame(self, text="Stored Passwords")
        list_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.password_tree = ttk.Treeview(
            list_frame,
            columns=("Service", "Username"),
            show="headings"
        )
        self.password_tree.heading("Service", text="Service")
        self.password_tree.heading("Username", text="Username")
        self.password_tree.pack(pady=5, padx=5, fill="both", expand=True)
        
        # Add password section
        add_frame = ttk.LabelFrame(self, text="Add Password")
        add_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(add_frame, text="Service:").grid(row=0, column=0, padx=5, pady=5)
        self.service_entry = ttk.Entry(add_frame)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(add_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(add_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(add_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(add_frame, show="•")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        
        btn_frame = ttk.Frame(add_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        generate_btn = ttk.Button(
            btn_frame,
            text="Generate Password",
            command=self.generate_password
        )
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        add_btn = ttk.Button(
            btn_frame,
            text="Add Password",
            command=self.add_password
        )
        add_btn.pack(side=tk.LEFT, padx=5)
        
        # View password button
        view_btn = ttk.Button(
            self,
            text="View Password",
            command=self.view_password
        )
        view_btn.pack(pady=10)
        
        # Delete password button
        delete_btn = ttk.Button(
            self,
            text="Delete Password",
            command=self.delete_password
        )
        delete_btn.pack(pady=5)
        
    def load_or_create_key(self):
        """Load existing key or create a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
                
    def load_passwords(self):
        """Load encrypted passwords from file"""
        if os.path.exists(self.passwords_file):
            try:
                with open(self.passwords_file, 'rb') as f:
                    encrypted_data = f.read()
                    f = Fernet(self.key)
                    decrypted_data = f.decrypt(encrypted_data)
                    self.passwords = json.loads(decrypted_data)
            except Exception:
                self.passwords = {}
        else:
            self.passwords = {}
            
        # Update treeview
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
            
        for service, data in self.passwords.items():
            self.password_tree.insert(
                "",
                "end",
                values=(service, data['username'])
            )
            
    def save_passwords(self):
        """Save encrypted passwords to file"""
        f = Fernet(self.key)
        encrypted_data = f.encrypt(json.dumps(self.passwords).encode())
        with open(self.passwords_file, 'wb') as f:
            f.write(encrypted_data)
            
    def generate_password(self):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
    def add_password(self):
        """Add a new password"""
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not service or not username or not password:
            messagebox.showerror(
                "Error",
                "Please fill in all fields!"
            )
            return
            
        self.passwords[service] = {
            'username': username,
            'password': password
        }
        
        self.save_passwords()
        self.load_passwords()
        
        # Clear entries
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        
    def view_password(self):
        """View selected password"""
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showerror(
                "Error",
                "Please select a password to view!"
            )
            return
            
        service = self.password_tree.item(selection[0])['values'][0]
        if service in self.passwords:
            password = self.passwords[service]['password']
            messagebox.showinfo(
                "Password",
                f"Password for {service}:\n{password}"
            )
            
    def delete_password(self):
        """Delete selected password"""
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showerror(
                "Error",
                "Please select a password to delete!"
            )
            return
            
        service = self.password_tree.item(selection[0])['values'][0]
        if service in self.passwords:
            del self.passwords[service]
            self.save_passwords()
            self.load_passwords()
