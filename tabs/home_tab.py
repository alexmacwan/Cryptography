import tkinter as tk
from tkinter import ttk

class HomeTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()
        
    def create_widgets(self):
        # Welcome message
        welcome_label = ttk.Label(
            self,
            text="Welcome to Crypto Tool",
            font=("Helvetica", 24, "bold")
        )
        welcome_label.pack(pady=20)
        
        # Description
        description = ttk.Label(
            self,
            text="Select a tool from the tabs above to get started",
            font=("Helvetica", 12)
        )
        description.pack(pady=10)
        
        # Feature list
        features_frame = ttk.LabelFrame(self, text="Available Features")
        features_frame.pack(pady=20, padx=20, fill="x")
        
        features = [
            "✓ Symmetric Encryption",
            "✓ Asymmetric Encryption",
            "✓ Hash Functions",
            "✓ Key Management",
            "✓ Digital Signatures",
            "✓ Password Management",
            "✓ Secure File Transfer"
        ]
        
        for feature in features:
            feature_label = ttk.Label(
                features_frame,
                text=feature,
                font=("Helvetica", 10)
            )
            feature_label.pack(pady=5, padx=10, anchor="w")
