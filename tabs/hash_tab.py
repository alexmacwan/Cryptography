import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives import hashes

class HashTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()
        
    def create_widgets(self):
        # Hash input
        input_frame = ttk.LabelFrame(self, text="Input")
        input_frame.pack(pady=10, padx=10, fill="x")
        
        self.input_text = tk.Text(input_frame, height=5)
        self.input_text.pack(pady=5, padx=5, fill="x")
        
        # Hash algorithm selection
        algo_frame = ttk.LabelFrame(self, text="Hash Algorithm")
        algo_frame.pack(pady=10, padx=10, fill="x")
        
        self.algorithm = tk.StringVar(value="SHA256")
        algorithms = ["MD5", "SHA1", "SHA256", "SHA512"]
        
        for algo in algorithms:
            ttk.Radiobutton(
                algo_frame,
                text=algo,
                value=algo,
                variable=self.algorithm
            ).pack(side=tk.LEFT, padx=10)
            
        # Hash button
        hash_btn = ttk.Button(
            self,
            text="Generate Hash",
            command=self.generate_hash
        )
        hash_btn.pack(pady=10)
        
        # Hash output
        output_frame = ttk.LabelFrame(self, text="Hash Output")
        output_frame.pack(pady=10, padx=10, fill="x")
        
        self.output_text = tk.Text(output_frame, height=3)
        self.output_text.pack(pady=5, padx=5, fill="x")
        
    def generate_hash(self):
        """Generate hash of input text"""
        input_text = self.input_text.get("1.0", "end-1c")
        if not input_text:
            messagebox.showerror(
                "Error",
                "Please enter text to hash!"
            )
            return
            
        # Select hash algorithm
        algorithm = self.algorithm.get()
        hash_algo = {
            "MD5": hashes.MD5(),
            "SHA1": hashes.SHA1(),
            "SHA256": hashes.SHA256(),
            "SHA512": hashes.SHA512()
        }.get(algorithm)
        
        if not hash_algo:
            messagebox.showerror(
                "Error",
                "Invalid hash algorithm selected!"
            )
            return
            
        # Generate hash
        digest = hashes.Hash(hash_algo)
        digest.update(input_text.encode())
        hash_value = digest.finalize()
        
        # Display hash
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", hash_value.hex())
