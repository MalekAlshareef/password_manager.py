import hashlib
import bcrypt
import sqlite3
import random
import string
from cryptography.fernet import Fernet

# Database initialization
def init_db():
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY,
                      username TEXT NOT NULL,
                      password TEXT NOT NULL
                  )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                      id INTEGER PRIMARY KEY,
                      user_id INTEGER NOT NULL,
                      service_name TEXT NOT NULL,
                      encrypted_password TEXT NOT NULL
                  )''')
    conn.commit()
    conn.close()

# Hash the password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# Verify user's password
def verify_password(stored_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_hash)

# Generate a strong random password
def generate_password():
    length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

# Encrypt and decrypt passwords
def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

# Password strength checker
def is_strong_password(password):
    # Implement your password strength criteria here
    return len(password) >= 8 and any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password)

# Register a new user
def register_user():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Check if the username already exists
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        print("Username already exists. Please choose a different one.")
        conn.close()
        return

    hashed_password = hash_password(password)

    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()
    print("User registered successfully!")

# Login a user
def login_user():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if user and verify_password(user[2], password):
        print("Login successful!")
        user_id = user[0]
        manage_passwords(user_id)
    else:
        print("Incorrect username or password.")
    conn.close()

# Manage passwords for a user
def manage_passwords(user_id):
    while True:
        print("\nPassword Manager Menu:")
        print("1. View Passwords")
        print("2. Add Password")
        print("3. Update Password")
        print("4. Delete Password")
        print("5. Retrieve Password")
        print("6. Change Master Password")
        print("7. Logout")

        choice = input("Enter your choice: ")

        if choice == "1":
            view_passwords(user_id)
        elif choice == "2":
            add_password(user_id)
        elif choice == "3":
            update_password(user_id)
        elif choice == "4":
            delete_password(user_id)
        elif choice == "5":
            retrieve_password(user_id)
        elif choice == "6":
            change_master_password(user_id)
        elif choice == "7":
            logout()
            break
        else:
            print("Invalid choice. Please try again.")

# View stored passwords for a user
def view_passwords(user_id):
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT service_name, encrypted_password FROM passwords WHERE user_id=?", (user_id,))
    passwords = cursor.fetchall()
    conn.close()

    if not passwords:
        print("No passwords stored.")
    else:
        print("\nStored Passwords:")
        for row in passwords:
            service_name, encrypted_password = row
            decrypted_password = decrypt_password(encrypted_password, str(user_id))
            print(f"Service: {service_name}, Password: {decrypted_password}")

# Add a password for a user
def add_password(user_id):
    service_name = input("Enter the service name: ")
    password = input("Enter the password: ")

    if not is_strong_password(password):
        print("Password is too weak. It should be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one digit.")
        return

    key = Fernet.generate_key()
    encrypted_password = encrypt_password(password, key)

    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (user_id, service_name, encrypted_password) VALUES (?, ?, ?)", (user_id, service_name, encrypted_password))
    conn.commit()
    conn.close()
    print("Password added successfully!")

# Update a stored password for a user
def update_password(user_id):
    service_name = input("Enter the service name for the password you want to update: ")
    password = input("Enter the new password: ")

    if not is_strong_password(password):
        print("Password is too weak. It should be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one digit.")
        return

    key = Fernet.generate_key()
    encrypted_password = encrypt_password(password, key)

    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE passwords SET encrypted_password=? WHERE user_id=? AND service_name=?", (encrypted_password, user_id, service_name))
    conn.commit()

    if cursor.rowcount == 1:
        print("Password updated successfully!")
    else:
        print("Password not found for the specified service.")
    conn.close()

# Delete a stored password for a user
def delete_password(user_id):
    service_name = input("Enter the service name for the password you want to delete: ")

    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE user_id=? AND service_name=?", (user_id, service_name))
    conn.commit()

    if cursor.rowcount == 1:
        print("Password deleted successfully!")
    else:
        print("Password not found for the specified service.")
    conn.close()

# Retrieve a stored password for a user
def retrieve_password(user_id):
    service_name = input("Enter the service name for the password you want to retrieve: ")

    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_password FROM passwords WHERE user_id=? AND service_name=?", (user_id, service_name))
    encrypted_password = cursor.fetchone()
    conn.close()

    if encrypted_password:
        decrypted_password = decrypt_password(encrypted_password[0], str(user_id))
        print(f"Service: {service_name}, Password: {decrypted_password}")
    else:
        print("Password not found for the specified service.")

# Change the master password for a user
def change_master_password(user_id):
    new_password = input("Enter your new master password: ")

    if not is_strong_password(new_password):
        print("Password is too weak. It should be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one digit.")
        return

    hashed_password = hash_password(new_password)

    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, user_id))
    conn.commit()
    conn.close()

    print("Master password changed successfully!")

# Logout function
def logout():
    print("Logout successful!")

# Main menu and main script
def main():
    init_db()

    while True:
        print("\nPassword Manager Menu:")
        print("1. Register")
        print("2. Login")
        print("3. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
