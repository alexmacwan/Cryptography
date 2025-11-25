import tkinter as tk
from tkinter import ttk, messagebox
import hmac
import hashlib
import base64
import secrets

class DigitalSignatureTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.secret_key = None
        self.create_widgets()
        
    def create_widgets(self):
        # Message input
        input_frame = ttk.LabelFrame(self, text="Message")
        input_frame.pack(pady=10, padx=10, fill="x")
        
        self.message_text = tk.Text(input_frame, height=5)
        self.message_text.pack(pady=5, padx=5, fill="x")
        
        # Add copy button for message
        copy_msg_btn = ttk.Button(
            input_frame,
            text="Copy Message",
            command=lambda: self.copy_to_clipboard(self.message_text.get("1.0", "end-1c"))
        )
        copy_msg_btn.pack(pady=5)
        
        # Signature section
        sig_frame = ttk.LabelFrame(self, text="Digital Signature")
        sig_frame.pack(pady=10, padx=10, fill="x")
        
        # Generate new signature key button
        gen_key_btn = ttk.Button(
            sig_frame,
            text="Generate New Signature Key",
            command=self.generate_key
        )
        gen_key_btn.pack(pady=5)
        
        sign_btn = ttk.Button(
            sig_frame,
            text="Sign Message",
            command=self.sign_message
        )
        sign_btn.pack(pady=5)
        
        self.signature_text = tk.Text(sig_frame, height=5)
        self.signature_text.pack(pady=5, padx=5, fill="x")
        
        # Add copy/paste buttons for signature
        sig_btn_frame = ttk.Frame(sig_frame)
        sig_btn_frame.pack(pady=5)
        
        copy_sig_btn = ttk.Button(
            sig_btn_frame,
            text="Copy Signature",
            command=lambda: self.copy_to_clipboard(self.signature_text.get("1.0", "end-1c"))
        )
        copy_sig_btn.pack(side="left", padx=5)
        
        paste_sig_btn = ttk.Button(
            sig_btn_frame,
            text="Paste Signature",
            command=lambda: self.signature_text.insert("1.0", self.app.clipboard_get())
        )
        paste_sig_btn.pack(side="left", padx=5)
        
        # Verification section
        verify_frame = ttk.LabelFrame(self, text="Signature Verification")
        verify_frame.pack(pady=10, padx=10, fill="x")
        
        verify_btn = ttk.Button(
            verify_frame,
            text="Verify Signature",
            command=self.verify_signature
        )
        verify_btn.pack(pady=5)
        
        self.verify_result = ttk.Label(
            verify_frame,
            text="Not verified",
            font=("Helvetica", 10)
        )
        self.verify_result.pack(pady=5)
        
    def generate_key(self):
        """Generate a new signature key"""
        self.secret_key = secrets.token_bytes(32)
        messagebox.showinfo(
            "Success",
            "New signature key generated!"
        )
        
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.app.clipboard_clear()
        self.app.clipboard_append(text)
        self.app.update()
        
    def sign_message(self):
        """Sign a message using HMAC"""
        if not self.secret_key:
            messagebox.showerror(
                "Error",
                "No signature key available! Generate one first."
            )
            return
            
        message = self.message_text.get("1.0", "end-1c")
        if not message:
            messagebox.showerror(
                "Error",
                "Please enter a message to sign!"
            )
            return
            
        try:
            # Create HMAC signature
            h = hmac.new(self.secret_key, message.encode(), hashlib.sha256)
            signature = base64.b64encode(h.digest()).decode()
            
            # Format as message|signature
            signed_message = f"Message: {message}\nSignature: {signature}"
            
            self.signature_text.delete("1.0", "end")
            self.signature_text.insert("1.0", signed_message)
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to sign message: {str(e)}"
            )
            
    def verify_signature(self):
        """Verify a signature using HMAC"""
        if not self.secret_key:
            messagebox.showerror(
                "Error",
                "No signature key available! Generate one first."
            )
            return
            
        signed_data = self.signature_text.get("1.0", "end-1c")
        
        try:
            # Extract message and signature from formatted text
            lines = signed_data.strip().split('\n')
            if len(lines) != 2 or not lines[0].startswith('Message: ') or not lines[1].startswith('Signature: '):
                messagebox.showerror(
                    "Error",
                    "Invalid signature format! Expected:\nMessage: <message>\nSignature: <signature>"
                )
                return
                
            message = lines[0][len('Message: '):]
            signature = lines[1][len('Signature: '):]
            
            # Verify HMAC
            h = hmac.new(self.secret_key, message.encode(), hashlib.sha256)
            expected_signature = base64.b64encode(h.digest()).decode()
            
            if hmac.compare_digest(signature, expected_signature):
                self.verify_result.config(
                    text="✓ Signature Valid",
                    foreground="green"
                )
                # Update message text with original message
                self.message_text.delete("1.0", "end")
                self.message_text.insert("1.0", message)
            else:
                self.verify_result.config(
                    text="✗ Invalid Signature",
                    foreground="red"
                )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Verification failed: {str(e)}"
            )
