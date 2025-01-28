import bcrypt
import tkinter as tk
from tkinter import messagebox
import json
import os

# Path to the file where user data will be stored
USER_DATA_FILE = 'user_data.json'

def load_user_data():
    """Load user data from the JSON file."""
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_user_data(user_data):
    """Save user data to the JSON file."""
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file)

def hash_string(string):
    """Hash a string (username or password) using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_string = bcrypt.hashpw(string.encode(), salt)
    return hashed_string

def create_username():
    """Create a new username and store the hashed password."""
    username = username_entry.get()
    password = password_entry.get()
    if not username or not password:
        messagebox.showwarning("Input Error", "Please enter both username and password.")
        return
    
    user_data = load_user_data()
    
    # Hash the username
    hashed_username = hash_string(username).decode()
    
    # Check if hashed username already exists
    if hashed_username in user_data:
        messagebox.showerror("Error", "Username already exists.")
        return
    
    hashed_password = hash_string(password).decode()
    user_data[hashed_username] = hashed_password
    save_user_data(user_data)
    
    messagebox.showinfo("Success", "Username and password created successfully!")
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

def verify_password():
    """Verify the entered password for the given username."""
    username = username_entry.get()
    password = password_entry.get()
    if not username or not password:
        messagebox.showwarning("Input Error", "Please enter both username and password.")
        return
    
    user_data = load_user_data()
    
    # Hash the username for lookup
    hashed_username = hash_string(username).decode()
    
    if hashed_username not in user_data:
        messagebox.showerror("Error", "Username not found.")
        return
    
    stored_hashed_password = user_data[hashed_username].encode()
    if bcrypt.checkpw(password.encode(), stored_hashed_password):
        messagebox.showinfo("Success", "Password is correct!")
    else:
        messagebox.showerror("Error", "Password is incorrect!")
    
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

def create_gui():
    """Create the GUI application."""
    global username_entry, password_entry
    
    # Create the main window
    window = tk.Tk()
    window.title("Password Manager")
    
    # Create and place the input fields
    tk.Label(window, text="Enter your username:").pack(pady=5)
    username_entry = tk.Entry(window)
    username_entry.pack(pady=5)
    
    tk.Label(window, text="Enter your password:").pack(pady=5)
    password_entry = tk.Entry(window, show='*')
    password_entry.pack(pady=5)
    
    # Create and place the buttons
    tk.Button(window, text="Create Username", command=create_username).pack(pady=5)
    tk.Button(window, text="Verify Password", command=verify_password).pack(pady=5)
    
    # Start the GUI event loop
    window.mainloop()

if __name__ == '__main__':
    create_gui()
