import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import json
import socket
import threading
import secrets
import string
import base64
import hashlib
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.exceptions import InvalidSignature

# Import all tab classes
from tabs.home_tab import HomeTab
from tabs.symmetric_tab import SymmetricTab
from tabs.asymmetric_tab import AsymmetricTab
from tabs.hash_tab import HashTab
from tabs.key_management_tab import KeyManagementTab
from tabs.digital_signature_tab import DigitalSignatureTab
from tabs.password_management_tab import PasswordManagementTab
from tabs.file_transfer_tab import FileTransferTab

class CryptoTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Encryption Tool")
        self.geometry("1280x800")
        self.minsize(1080, 700)
        
        # Define colors first
        self.colors = {
            'primary': '#2196F3',
            'primary_light': '#42A5F5',
            'primary_dark': '#1976D2',
            'secondary': '#546E7A',
            'secondary_light': '#78909C',
            'success': '#4CAF50',
            'success_light': '#66BB6A',
            'warning': '#FF9800',
            'warning_light': '#FFA726',
            'error': '#F44336',
            'error_light': '#EF5350',
            'surface': '#FFFFFF',
            'background': '#FAFAFA',
            'text': '#212121',
            'text_secondary': '#757575',
            'border': '#E0E0E0',
            'highlight': '#E3F2FD',
            'disabled': '#BDBDBD'
        }
        
        # Set font only once
        self.default_font = ('Segoe UI', 11)
        self.option_add('*Font', self.default_font)
        
        # Configure root window background
        self.configure(bg=self.colors['background'])
        
        # Initialize variables
        self.initialize_variables()
        
        # Configure styles
        self.configure_styles()
        
        # Create main container with scrolling
        self.main_container = ttk.Frame(self, style='Main.TFrame')
        self.main_container.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Create background canvas for animation
        self.bg_canvas = tk.Canvas(self.main_container, highlightthickness=0)
        self.bg_canvas.place(relwidth=1, relheight=1)
        
        # Variables for tab animation
        self.current_tab = None
        self.animation_items = []
        
        # Start animation after window is fully loaded
        self.after(100, self.animate_background)
        
        # Add canvas for scrolling
        self.canvas = tk.Canvas(self.main_container, background=self.colors['background'])
        # Configure scrollbar
        self.scrollbar = ttk.Scrollbar(
            self.main_container,
            orient="vertical",
            command=self.canvas.yview,
            style="Vertical.TScrollbar"
        )
        
        # Configure canvas
        self.canvas.configure(
            yscrollcommand=self.scrollbar.set,
            highlightthickness=0,
            bg=self.colors['background'],  # Explicitly set canvas background
            bd=0  # Remove border
        )
        self.scrollable_frame = ttk.Frame(self.canvas, style='Scroll.TFrame')
        
        # Configure scrolling
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            
        def _on_configure(event):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            # Set the canvas width to match the scrollable frame
            self.canvas.configure(width=event.width)
        
        # Bind mouse wheel events
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self.scrollable_frame.bind("<Configure>", _on_configure)
        
        # Create window in canvas
        self.canvas_window = self.canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw",
            width=self.winfo_width()  # Make the frame full width
        )
        
        # Update canvas width when window is resized
        def _on_canvas_configure(event):
            self.canvas.itemconfig(self.canvas_window, width=event.width)
        
        self.canvas.bind("<Configure>", _on_canvas_configure)
        
        # Configure canvas scrolling
        self.canvas.configure(
            yscrollcommand=self.scrollbar.set,
            highlightthickness=0  # Remove highlight border
        )
        
        # Pack scrolling components
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Load saved keys
        self.load_keys()
                
        # Create header
        self.create_header()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.scrollable_frame)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=(20, 10))
        
        # Configure notebook to ensure tabs don't get cut off
        style = ttk.Style()
        style.configure('TNotebook', tabposition='n')
        self.notebook.configure(style='TNotebook')
        
        # Create tabs
        self.create_tabs()
        
        # Create status bar
        self.create_status_bar()
        
        # Set up window close handler
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_header(self):
        """Create application header."""
        header_frame = ttk.Frame(self.scrollable_frame, style='Header.TFrame')
        header_frame.pack(fill="x", padx=20, pady=(0, 20))

        # App title with icon
        title_frame = ttk.Frame(header_frame, style='Header.TFrame')
        title_frame.pack(side="left", fill="y")
        
        # Add app icon
        icon_label = ttk.Label(
            title_frame,
            text="🔒",  # Lock icon
            style='AppIcon.TLabel'
        )
        icon_label.pack(side="left", padx=(0, 10))

        # App title
        title_label = ttk.Label(
            title_frame,
            text="Secure Encryption Tool",
            style='AppTitle.TLabel'
        )
        title_label.pack(side="left")

        # Right side container
        right_frame = ttk.Frame(header_frame, style='Header.TFrame')
        right_frame.pack(side="right", fill="y")

        # Version info with badge style
        version_frame = ttk.Frame(right_frame, style='VersionBadge.TFrame')
        version_frame.pack(side="right", padx=10)
        
        version_label = ttk.Label(
            version_frame,
            text="v1.0.0",
            style='Version.TLabel'
        )
        version_label.pack(padx=8, pady=4)

    def initialize_variables(self):
        """Initialize tkinter variables."""
        self.current_key_name = tk.StringVar(value="No key selected")
        self.current_public_key_name = tk.StringVar(value="No key selected")
        self.current_private_key_name = tk.StringVar(value="No key selected")
        self.server_host = tk.StringVar(value="localhost")
        self.server_port = tk.StringVar(value="5000")
        self.transfer_file_var = tk.StringVar()
        self.status_var = tk.StringVar()
        
        # Initialize key storage
        self.symmetric_keys = {}
        self.public_keys = {}
        self.private_keys = {}

    def configure_styles(self):
        style = ttk.Style()
        # Set theme before configuring styles
        style.theme_use('default')  # This theme works best with custom colors
        
        # Configure main theme
        style.configure(
            "AppIcon.TLabel",
            font=('Segoe UI', 24),
            foreground=self.colors['primary'],
            background=self.colors['surface']
        )
        
        style.configure(
            "AppTitle.TLabel",
            font=('Segoe UI', 24, 'bold'),
            foreground=self.colors['primary'],
            background=self.colors['surface']
        )
        
        style.configure(
            "Version.TLabel",
            font=('Segoe UI', 10, 'bold'),
            foreground='white',
            background=self.colors['primary_light']
        )
        
        # Configure Notebook styles
        style.configure(
            'TNotebook',
            background=self.colors['background'],
            tabmargins=[5, 5, 0, 0],  # [left, top, right, bottom]
            padding=[10, 10]  # [left/right, top/bottom]
        )
        
        style.configure(
            'TNotebook.Tab',
            padding=[25, 5],  # Increased horizontal padding
            width=40,  # Increased minimum width
            font=('Segoe UI', 10)
        )
        
        # Configure tab states
        style.map('TNotebook.Tab',
            background=[
                ('selected', self.colors['primary']),
                ('!selected', self.colors['surface'])
            ],
            foreground=[
                ('selected', 'white'),
                ('!selected', self.colors['text'])
            ]
        )
        
        # Configure Notebook style
        style.configure(
            "TNotebook",
            background=self.colors['background'],
            borderwidth=0,
            tabmargins=[2, 5, 2, 0],
            padding=5
        )
        
        style.configure(
            "TNotebook.Tab",
            padding=[45, 18],  # Increased tab padding
            font=('Segoe UI', 12),  # Larger font
            background=self.colors['surface'],
            foreground=self.colors['text']
        )
        
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", self.colors['primary']),
                ("!selected", self.colors['surface'])
            ],
            foreground=[
                ("selected", 'white'),
                ("!selected", self.colors['text'])
            ],
            padding=[
                ("selected", [30, 15]),
                ("!selected", [30, 15])
            ]
        )

        # Button base configuration
        button_base_config = {
            'font': ('Segoe UI', 11, 'bold'),
            'padding': (40, 16),  # Larger padding
            'relief': 'flat',
            'borderwidth': 0,
            'foreground': 'white'
        }

        # Primary Action Button with shadow effect
        style.configure(
            "Primary.TButton",
            **button_base_config,
            background=self.colors['primary']
        )
        style.map(
            "Primary.TButton",
            background=[
                ("active", self.colors['primary_light']),
                ("pressed", self.colors['primary_dark']),
                ("disabled", self.colors['disabled'])
            ],
            foreground=[("disabled", self.colors['text_secondary'])],
            relief=[("pressed", "sunken")],
            borderwidth=[("pressed", 1)]
        )

        # Secondary Action Button
        style.configure(
            "Secondary.TButton",
            **button_base_config,  # button_base_config already includes foreground='white'
            background=self.colors['secondary']
            # Removed duplicate foreground parameter
        )
        style.map(
            "Secondary.TButton",
            background=[
                ("active", self.colors['secondary_light']),
                ("pressed", self.colors['secondary']),
                ("disabled", self.colors['disabled'])
            ],
            foreground=[
                ("disabled", self.colors['text_secondary']),
                ("pressed", "white")
            ]
        )

        # Success Button
        style.configure(
            "Success.TButton",
            **button_base_config,
            background=self.colors['success']
        )
        style.map(
            "Success.TButton",
            background=[
                ("active", self.colors['success_light']),
                ("pressed", self.colors['success']),
                ("disabled", self.colors['disabled'])
            ],
            foreground=[
                ("disabled", self.colors['text_secondary']),
                ("pressed", "white")
            ]
        )

        # Warning Button
        style.configure(
            "Warning.TButton",
            **button_base_config,
            background=self.colors['warning']
        )
        style.map(
            "Warning.TButton",
            background=[
                ("active", self.colors['warning_light']),
                ("pressed", self.colors['warning']),
                ("disabled", self.colors['disabled'])
            ],
            foreground=[
                ("disabled", self.colors['text_secondary']),
                ("pressed", "white")
            ]
        )

        # Danger/Error Button
        style.configure(
            "Danger.TButton",
            **button_base_config,
            background=self.colors['error']
        )
        style.map(
            "Danger.TButton",
            background=[
                ("active", self.colors['error_light']),
                ("pressed", self.colors['error']),
                ("disabled", self.colors['disabled'])
            ],
            foreground=[
                ("disabled", self.colors['text_secondary']),
                ("pressed", "white")
            ]
        )

        # Generate Button - Success Green
        style.configure(
            "Generate.TButton",
            **button_base_config,
            background=self.colors['success']
        )
        style.map(
            "Generate.TButton",
            background=[
                ("active", self.colors['success_light']),
                ("pressed", self.colors['success']),
                ("disabled", self.colors['disabled'])
            ],
            foreground=[("disabled", "#CCCCCC")],
            relief=[("pressed", "sunken")],
            borderwidth=[("pressed", 3)]
        )

        # Entry fields with enhanced visibility
        style.configure(
            "TEntry",
            padding=14,  # Larger padding
            relief="solid",
            borderwidth=1,
            fieldbackground=self.colors['surface'],
            background=self.colors['surface'],
            font=('Segoe UI', 12)  # Larger font
        )
        style.map(
            "TEntry",
            bordercolor=[
                ("focus", self.colors['primary']),
                ("!focus", self.colors['border'])
            ],
            fieldbackground=[
                ("focus", self.colors['highlight']),
                ("!focus", self.colors['surface'])
            ]
        )

        # Text areas with better visibility
        style.configure(
            "TText",
            padding=15,
            relief="solid",
            borderwidth=2,
            background='white',
            font=('Segoe UI', 11),
            foreground=self.colors['text']
        )

        # Enhanced section headers
        style.configure(
            "Section.TLabel",
            font=('Segoe UI', 14, 'bold'),
            foreground=self.colors['text'],
            background=self.colors['surface'],
            padding=(0, 10, 0, 15)
        )

        # Configure Scrollbar style
        style.configure(
            "Vertical.TScrollbar",
            background=self.colors['background'],
            troughcolor=self.colors['background'],
            width=12,
            arrowsize=13
        )
        
        style.map(
            "Vertical.TScrollbar",
            background=[
                ("active", self.colors['primary']),
                ("pressed", self.colors['primary_dark'])
            ]
        )

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
        
        # Add tabs to notebook with proper titles
        tab_titles = {
            'home': 'Home',
            'symmetric': 'Symmetric',
            'asymmetric': 'Asymmetric',
            'hash': 'Hash Function',
            'key_management': 'Keys Management',
            'digital_signature': 'Digital Signature',
            'password_management': 'Password Management',
            'file_transfer': 'File Transfer'
        }
        
        for tab_id, tab in self.tabs.items():
            self.notebook.add(tab, text=tab_titles[tab_id])
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

    def animate_background(self):
        """Create animated background effect"""
        # Clear previous items
        self.bg_canvas.delete("all")
        self.animation_items.clear()
        
        # Get container dimensions
        width = self.main_container.winfo_width()
        height = self.main_container.winfo_height()
        
        # Only create particles if we have valid dimensions
        if width > 0 and height > 0:
            # Create animated particles
            for _ in range(20):
                x = random.randint(0, width)
                y = random.randint(0, height)
                size = random.randint(2, 5)
                color = random.choice(["#3498db", "#2980b9", "#1abc9c"])
                particle = self.bg_canvas.create_oval(
                    x, y, x+size, y+size,
                    fill=color, outline=""
                )
                self.animation_items.append({
                    "id": particle,
                    "dx": random.uniform(-0.5, 0.5),
                    "dy": random.uniform(-0.5, 0.5)
                })
        
        # Animate particles
        self.animate_particles()
    
    def animate_particles(self):
        """Animate background particles"""
        width = self.main_container.winfo_width()
        height = self.main_container.winfo_height()
        
        if width > 0 and height > 0:
            for item in self.animation_items:
                # Get current position
                x1, y1, x2, y2 = self.bg_canvas.coords(item["id"])
                
                # Update position
                new_x = x1 + item["dx"]
                new_y = y1 + item["dy"]
                
                # Wrap around screen
                if new_x < 0:
                    new_x = width
                elif new_x > width:
                    new_x = 0
                if new_y < 0:
                    new_y = height
                elif new_y > height:
                    new_y = 0
                
                # Move particle
                self.bg_canvas.coords(
                    item["id"],
                    new_x, new_y,
                    new_x + (x2-x1),
                    new_y + (y2-y1)
                )
        
        # Schedule next animation frame
        self.after(50, self.animate_particles)
    
    def on_tab_changed(self, event):
        """Handle tab change animation"""
        new_tab = self.notebook.select()
        if self.current_tab != new_tab:
            self.current_tab = new_tab
            # Trigger background animation refresh
            self.animate_background()
    
    def create_status_bar(self):
        """Create the status bar"""
        status_frame = ttk.Frame(self.main_container, style="StatusBar.TFrame")
        status_frame.pack(side="bottom", fill="x", pady=(10, 0))
        
        # Add separator above status bar
        separator = ttk.Separator(status_frame, orient="horizontal")
        separator.pack(fill="x", pady=(0, 5))
        
        # Left side status
        left_status = ttk.Frame(status_frame, style="StatusBar.TFrame")
        left_status.pack(side="left", fill="y")
        
        # Status label with icon
        status_icon = ttk.Label(
            left_status,
            text="🔵",  # Status icon
            style="StatusIcon.TLabel"
        )
        status_icon.pack(side="left", padx=(10, 5))
        
        status_label = ttk.Label(
            left_status,
            text="Status:",
            style="Status.TLabel"
        )
        status_label.pack(side="left", padx=(0, 5))
        
        status_text = ttk.Label(
            left_status,
            textvariable=self.status_var,
            style="StatusText.TLabel"
        )
        status_text.pack(side="left", padx=(0, 10))

        # Configure additional styles
        style = ttk.Style()
        
        # Status bar frame style
        style.configure(
            "StatusBar.TFrame",
            background=self.colors['surface'],
            relief="solid",
            borderwidth=1
        )
        
        # Status icon style
        style.configure(
            "StatusIcon.TLabel",
            font=('Segoe UI', 12),
            background=self.colors['surface'],
            foreground=self.colors['primary']
        )
        
        # Status label style
        style.configure(
            "Status.TLabel",
            font=('Segoe UI', 10, 'bold'),
            background=self.colors['surface'],
            foreground=self.colors['text_secondary']
        )
        
        # Status text style
        style.configure(
            "StatusText.TLabel",
            font=('Segoe UI', 10),
            background=self.colors['surface'],
            foreground=self.colors['text']
        )
        
        # Enhanced scrollbar style
        style.configure(
            "Vertical.TScrollbar",
            background=self.colors['surface'],
            troughcolor=self.colors['background'],
            width=14,
            arrowsize=14,
            relief="flat",
            borderwidth=0
        )
        
        style.map(
            "Vertical.TScrollbar",
            background=[
                ("active", self.colors['primary_light']),
                ("pressed", self.colors['primary'])
            ],
            troughcolor=[
                ("!disabled", self.colors['background'])
            ],
            arrowcolor=[
                ("!disabled", self.colors['primary']),
                ("disabled", self.colors['disabled'])
            ]
        )

    def update_status(self, message):
        """Update the status bar message"""
        self.status_var.set(message)
        # Change status icon color based on message type
        if "error" in message.lower():
            self.root.after(0, lambda: self._update_status_icon("🔴"))
        elif "success" in message.lower():
            self.root.after(0, lambda: self._update_status_icon("🟢"))
        elif "warning" in message.lower():
            self.root.after(0, lambda: self._update_status_icon("🟡"))
        else:
            self.root.after(0, lambda: self._update_status_icon("🔵"))

    def _update_status_icon(self, icon):
        """Update the status icon"""
        status_frame = self.main_container.winfo_children()[-1]
        status_icon = status_frame.winfo_children()[1]
        status_icon.configure(text=icon)

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

    def on_closing(self):
        """Handle window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.save_keys()
            self.root.destroy()

    def run(self):
        """Start the application main loop."""
        self.root.mainloop()

if __name__ == "__main__":
    app = CryptoTool()
    app.mainloop()