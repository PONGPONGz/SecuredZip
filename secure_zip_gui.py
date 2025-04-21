import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from secure_zip import SecureZip

class SecureZipGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Zip - Compression with Encryption")
        self.root.geometry("600x400")
        self.root.resizable(True, True)
        
        # Set application icon if available
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#ccc")
        self.style.configure("TLabel", padding=6, font=('Helvetica', 10))
        self.style.configure("Header.TLabel", font=('Helvetica', 12, 'bold'))
        
        # Main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_label = ttk.Label(main_frame, text="Secure Zip: Data Compression + Encryption", style="Header.TLabel")
        header_label.pack(pady=(0, 20))
        
        # Action frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(action_frame, text="Action:").pack(side=tk.LEFT, padx=(0, 10))
        self.action_var = tk.StringVar(value="compress")
        compress_radio = ttk.Radiobutton(action_frame, text="Compress & Encrypt", variable=self.action_var, value="compress")
        decompress_radio = ttk.Radiobutton(action_frame, text="Decrypt & Decompress", variable=self.action_var, value="decompress")
        compress_radio.pack(side=tk.LEFT, padx=(0, 10))
        decompress_radio.pack(side=tk.LEFT)
        
        # File selection frame
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT, padx=(0, 10))
        self.file_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_var, width=50)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.LEFT)
        
        # Output file frame
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_frame, text="Output:").pack(side=tk.LEFT, padx=(0, 10))
        self.output_var = tk.StringVar()
        self.output_entry = ttk.Entry(output_frame, textvariable=self.output_var, width=50)
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        browse_output_button = ttk.Button(output_frame, text="Browse", command=self.browse_output)
        browse_output_button.pack(side=tk.LEFT)
        
        # Password frame
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT, padx=(0, 10))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Confirm password frame (only for compression)
        self.confirm_frame = ttk.Frame(main_frame)
        self.confirm_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.confirm_frame, text="Confirm:").pack(side=tk.LEFT, padx=(0, 10))
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(self.confirm_frame, textvariable=self.confirm_var, show="*", width=30)
        self.confirm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Toggle action visibility
        self.action_var.trace("w", self.toggle_confirm_visibility)
        
        # Process button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.process_button = ttk.Button(button_frame, text="Process", command=self.process_file)
        self.process_button.pack(side=tk.RIGHT)
        
        # Status frame
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(20, 0), side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(fill=tk.X)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=100, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5, side=tk.BOTTOM)
    
    def toggle_confirm_visibility(self, *args):
        if self.action_var.get() == "compress":
            self.confirm_frame.pack(fill=tk.X, pady=5)
        else:
            self.confirm_frame.pack_forget()
        
        # Clear password fields when changing modes
        self.password_var.set("")
        self.confirm_var.set("")
    
    def browse_file(self):
        filetypes = [("All files", "*.*")]
        if self.action_var.get() == "decompress":
            filetypes = [("SecZip files", "*.seczip"), ("All files", "*.*")]
        
        filename = filedialog.askopenfilename(
            title="Select a file",
            filetypes=filetypes
        )
        
        if filename:
            self.file_var.set(filename)
            # Auto-generate output filename
            if self.action_var.get() == "compress":
                self.output_var.set(filename + ".seczip")
            else:
                if filename.endswith(".seczip"):
                    self.output_var.set(filename[:-7])
                else:
                    self.output_var.set(filename + ".decoded")
    
    def browse_output(self):
        if self.action_var.get() == "compress":
            filetypes = [("SecZip files", "*.seczip"), ("All files", "*.*")]
            defaultextension = ".seczip"
        else:
            filetypes = [("All files", "*.*")]
            defaultextension = None
        
        filename = filedialog.asksaveasfilename(
            title="Save as",
            filetypes=filetypes,
            defaultextension=defaultextension
        )
        
        if filename:
            self.output_var.set(filename)
    
    def process_file(self):
        input_file = self.file_var.get()
        output_file = self.output_var.get()
        password = self.password_var.get()
        action = self.action_var.get()
        
        # Validation
        if not input_file:
            messagebox.showerror("Error", "Please select an input file")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", "Input file does not exist")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if action == "compress" and password != self.confirm_var.get():
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        # Update UI
        self.progress.start()
        self.status_var.set(f"Processing: {os.path.basename(input_file)}")
        self.process_button.configure(state=tk.DISABLED)
        self.root.update()
        
        try:
            secure_zip = SecureZip(password)
            
            if action == "compress":
                result = secure_zip.compress_and_encrypt(input_file, output_file)
                if result:
                    msg = f"File compressed and encrypted successfully\nOutput: {result}"
                    messagebox.showinfo("Success", msg)
                else:
                    messagebox.showerror("Error", "Failed to compress and encrypt the file")
            
            else:  # decompress
                result = secure_zip.decrypt_and_decompress(input_file, output_file)
                if result:
                    msg = f"File decrypted and decompressed successfully\nOutput: {result}"
                    messagebox.showinfo("Success", msg)
                else:
                    messagebox.showerror("Error", "Failed to decrypt and decompress the file.\nThe password may be incorrect or the file is corrupted.")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        
        finally:
            # Reset UI
            self.progress.stop()
            self.status_var.set("Ready")
            self.process_button.configure(state=tk.NORMAL)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureZipGUI(root)
    root.mainloop() 