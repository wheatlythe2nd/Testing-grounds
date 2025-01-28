import getpass
import bcrypt

def hash_password(password):
    """Hash a password using bcrypt."""
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def store_password():
    """Prompt the user to enter a password and store its hash."""
    password = getpass.getpass('Set your password: ')
    hashed_password = hash_password(password)
    
    # Store the hashed password in a file (in a real application, use a secure storage solution)
    with open('password.txt', 'wb') as file:
        file.write(hashed_password)
    
    print('Password stored successfully!')

def verify_password():
    """Prompt the user to enter the password and verify it."""
    password = getpass.getpass('Enter your password: ')
    
    # Read the stored hashed password
    with open('password.txt', 'rb') as file:
        stored_hashed_password = file.read()
    
    # Verify the entered password against the stored hashed password
    if bcrypt.checkpw(password.encode(), stored_hashed_password):
        print('Password is correct!')
    else:
        print('Password is incorrect!')

if __name__ == '__main__':
    while True:
        print("\n1. Store Password\n2. Verify Password\n3. Exit")
        choice = input("Choose an option: ")
        
        if choice == '1':
            store_password()
        elif choice == '2':
            verify_password()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")
