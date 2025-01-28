import bcrypt
import hashlib
import tkinter as tk
from tkinter import messagebox
from tkinter import PhotoImage
import json
import os
from tkinter import Tk, Label, messagebox
from PIL import Image, ImageTk

# Path to the file where user data will be stored
USER_DATA_FILE = 'user_data.json'

def load_user_data():
    """Load user data from the JSON file."""
    if os.path.exists(USER_DATA_FILE):
        try:
            with open(USER_DATA_FILE, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            # Return an empty dictionary if the file is empty or contains invalid JSON
            return {}
    return {}

def save_user_data(user_data):
    """Save user data to the JSON file."""
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file)

def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def hash_username(username):
    """Hash a username using SHA-256."""
    return hashlib.sha256(username.encode()).hexdigest()

def create_username():
    """Create a new username and store the hashed username and password."""
    username = username_entry.get()
    password = password_entry.get()
    if not username or not password:
        messagebox.showerror("Error", "Username and password cannot be empty")
        return
    
    user_data = load_user_data()
    hashed_username = hash_username(username)
    if (hashed_username in user_data):
        messagebox.showerror("Error", "Username already exists")
        return
    
    hashed_password = hash_password(password)
    user_data[hashed_username] = hashed_password.decode()
    save_user_data(user_data)
    messagebox.showinfo("Success", "Username created successfully")

def verify_password():
    """Verify the entered password against the stored hashed password."""
    username = username_entry.get()
    password = password_entry.get()
    if not username or not password:
        messagebox.showerror("Error", "Username and password cannot be empty")
        return
    
    user_data = load_user_data()
    hashed_username = hash_username(username)
    if hashed_username not in user_data:
        messagebox.showerror("Error", "Username does not exist")
        return
    
    stored_hashed_password = user_data[hashed_username].encode()
    if bcrypt.checkpw(password.encode(), stored_hashed_password):
        messagebox.showinfo("Success", "Password verified successfully")
    else:
        messagebox.showerror("Error", "Incorrect password")

def clear_user_data():
    """Clear the user data file."""
    if os.path.exists(USER_DATA_FILE):
        os.remove(USER_DATA_FILE)
        messagebox.showinfo("Success", "User data file cleared")
    else:
        messagebox.showerror("Error", "User data file does not exist")

def resize_image(event=None):
    if hasattr(resize_image, '_after_id'):
        window.after_cancel(resize_image._after_id)
    
    def delayed_resize():
        width = window.winfo_width()
        height = window.winfo_height()
        image = original_image.resize((width, height), Image.ANTIALIAS)
        global photo
        photo = ImageTk.PhotoImage(image)
        label.config(image=photo)
        label.image = photo
    
    resize_image._after_id = window.after(50, delayed_resize)

def enforce_aspect_ratio(event=None):
    if event and event.widget == window:
        width = window.winfo_width()
        height = window.winfo_height()
        if abs(width - height) > 2:
            new_size = min(width, height)
            x = window.winfo_x()
            y = window.winfo_y()
            window.geometry(f"{new_size}x{new_size}+{x}+{y}")

def create_gui():
    global username_entry, password_entry, original_image, label, window, photo
    
    window = tk.Tk()
    window.title("Password Manager")
    window.geometry("800x800")
    
    # Load original image at full resolution without initial resize
    original_image = Image.open("girl with gun.png")
    photo = ImageTk.PhotoImage(original_image)
    label = tk.Label(window, image=photo)
    label.pack(fill="both", expand=True)
    
    # Separate bindings for smoother updates
    window.bind("<Configure>", enforce_aspect_ratio)
    window.bind("<Configure>", resize_image)
    
    # Create and place the input fields and buttons
    input_frame = tk.Frame(window, bg="white")
    input_frame.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(input_frame, text="Enter your username:", bg="white").pack(pady=5)
    username_entry = tk.Entry(input_frame)
    username_entry.pack(pady=5)

    tk.Label(input_frame, text="Enter your password:", bg="white").pack(pady=5)
    password_entry = tk.Entry(input_frame, show='*')
    password_entry.pack(pady=5)

    tk.Button(input_frame, text="Create Username", command=create_username).pack(pady=5)
    tk.Button(input_frame, text="Verify Password", command=verify_password).pack(pady=5)
    tk.Button(input_frame, text="Clear User Data", command=clear_user_data).pack(pady=5)
    
    # Start the GUI event loop
    window.mainloop()

if __name__ == '__main__':
    create_gui()
