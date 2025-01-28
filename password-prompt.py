import msvcrt
import bcrypt

def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def get_password(prompt="Enter your password:"):
    """Prompt for a password, use Windows msvcrt to have password display as astricks."""
    print(prompt, end='', flush=True)
    password = []
    while True:
        ch = msvcrt.getch()
        if ch in {b'\r', b'\n'}:  # Enter key
            print('')
            break
        elif ch == b'\x08':  # Backspace key
            if password:
                password.pop()
                print('\b \b', end='', flush=True)
        else:
            password.append(ch.decode())
            print('*', end='', flush=True)
    return ''.join(password)

def store_password():
    password = get_password('Set your password: ')
    hashed_password = hash_password(password)
    
    with open('password.txt', 'wb') as file:
        file.write(hashed_password)
    
    print('Password stored successfully!')

def verify_password():
    password = get_password('Enter your password: ')
    
    with open('password.txt', 'rb') as file:
        stored_hashed_password = file.read()
    
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
