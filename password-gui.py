import bcrypt
import tkinter as tk
from tkinter import messagebox

def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def store_password():
    """Store the hashed password in a file."""
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    
    hashed_password = hash_password(password)
    
    with open('password.txt', 'wb') as file:
        file.write(hashed_password)
    
    messagebox.showinfo("Success", "Password stored successfully!")
    password_entry.delete(0, tk.END)

def verify_password():
    """Verify the entered password against the stored hash."""
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    
    try:
        with open('password.txt', 'rb') as file:
            stored_hashed_password = file.read()
        
        if bcrypt.checkpw(password.encode(), stored_hashed_password):
            messagebox.showinfo("Success", "Password is correct!")
        else:
            messagebox.showerror("Error", "Password is incorrect!")
    except FileNotFoundError:
        messagebox.showerror("Error", "No stored password found. Please set a password first.")
    password_entry.delete(0, tk.END)

def create_gui():
    """Create the GUI application."""
    global password_entry
    
    # Create the main window
    window = tk.Tk()
    window.title("Password Manager")
    
    # Create and place the input field
    tk.Label(window, text="Enter your password:").pack(pady=10)
    password_entry = tk.Entry(window, show='*')
    password_entry.pack(pady=5)
    
    # Create and place the buttons
    tk.Button(window, text="Store Password", command=store_password).pack(pady=5)
    tk.Button(window, text="Verify Password", command=verify_password).pack(pady=5)
    
    # Start the GUI event loop
    window.mainloop()

if __name__ == '__main__':
    create_gui()
