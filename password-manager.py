"""
Gavin Burgess
3/17/2026
CYBR 315
password-manager.py

This program is a simple password manager that allows user to store and manage their credentials with AES-128 encryption.
Users can add new credentials, view existing credentials, and save the encrypted database to a file. The master key is used for encryption and decryption of the credentials database.
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import json

# ///// PADDING /////
def pad(data):
    """Pads data so that its length is a multiple of 16 bytes.
    Params:
        data (bytes): The data to pad.
    Returns:
        padded_data (bytes): The padded data."""
    padding_length = 16 - (len(data) % 16) # Calculate how many bytes of padding are needed
    padding = bytes([padding_length]) * padding_length # Create bytes for padding
    return data + padding


def unpad(data):
    """Removes padding from data.
    Params:
        data (bytes): The padded data.
    Returns:
        unpadded_data (bytes): The original data without padding."""
    padding_length = data[-1] # Get the value of the last byte to determine padding length
    return data[:-padding_length] # Remove the padding bytes from the end of the data



# ///// ENCRYPT/DECRYPT /////
def encrypt(key, data):
    """Encrypts plaintext using AES-128 CBC encryption.
    Params:
        key (bytes): The encryption key (must be 16 bytes for AES-128).
        data (bytes): The plaintext data to encrypt.

    Returns:
        iv + ciphertext (bytes): The initialization vector concatenated with the ciphertext.
    """
    iv = get_random_bytes(16) # Generate a random 16-byte IV
    cipher = AES.new(key, AES.MODE_CBC, iv) # Create a new AES cipher object in CBC mode with the given key and IV
    padded_data = pad(data) # Pad the plaintext data to be a multiple of 16 bytes
    ciphertext = cipher.encrypt(padded_data) # Encrypt the padded data using the cipher
    return iv + ciphertext


def decrypt(key, data):
    """Decrypts ciphertext using AES-128 CBC decryption.
    Params:
        key (bytes): The decryption key (must be the same as the encryption key).
        data (bytes): The IV concatenated with the ciphertext to decrypt.
    Returns:
        plaintext (bytes): The decrypted plaintext data.
    """
    iv = data[:16] # Extract the IV
    ciphertext = data[16:] # Extract the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext) # Decrypt the ciphertext using the cipher
    return unpad(padded_plaintext) # Remove padding from the decrypted plaintext to get the original data



# ///// CREDENTIALS /////
def add_credential(database):
    """Adds a new credential to the database.
    Params:
        database (dict): Thedatabase to update.
    """
    
    account = input("Enter account name: ")
    username = input("Enter username: ")        # Prompt user for account name, username, and password to create a new credential
    password = input("Enter password: ")

    credential = {
        "account": account,
        "username": username,
        "password": password
    }

    database.append(credential) # Add the new credential to the database list
    print("Credential added.\n")


def view_credentials(database):
    """Displays all credentials in the database.
    Params:
        database (dict): The credentials database to display.
    """
    if len(database) == 0:
        print("No credentials stored.\n")
        return
    
    for entry in database:
        print(f"Account: {entry['account']}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}\n")



# ///// DB SAVE/LOAD /////
def save_database(database, key):
    """Encrypt and save to passwords.dat"""
    json_data = json.dumps(database) # Convert the database (list of credentials) to a JSON string
    data_bytes = json_data.encode('utf-8') # Encode the JSON string to bytes for encryption
    encrypted_data = encrypt(key, data_bytes) # Encrypt the byte data using the provided key
    with open("passwords.dat", "wb") as file:
        file.write(encrypted_data) # Write the encrypted data to a file named passwords.dat in binary mode
    print("Database saved.\n")


def load_database(key):
    """Load and decrypt from passwords.dat"""
    if not os.path.exists("passwords.dat"): # Check if the passwords.dat file exists
        print("No database found. Starting with an empty database.\n")
        return []
    
    with open("passwords.dat", "rb") as file:
        encrypted_data = file.read() # Read the encrypted data from the file in binary mode

    decrypted_data = decrypt(key, encrypted_data) # Decrypt the data using the provided key
    json_string = decrypted_data.decode('utf-8') # Decode the decrypted byte data back to a JSON string
    return json.loads(json_string) # Convert the JSON string back to a Python list of credentials and return it


# ///// MASTER KEY /////
def master_key():
    """Prompts the user to enter a master key and validates its length. If the key is not exactly 16 characters long, it will continue to prompt the user until a valid key is entered."""
    while True:
        key = input("Enter master key (16 characters): ")
        if len(key) != 16:
            print("Invalid key length. Master key must be exactly 16 characters long.\n")
        else:
            print("Master key accepted.\n")
            return key
        

# ///// MAIN /////
def main():
    key = master_key()
    key_bytes = key.encode('utf-8')
    database = load_database(key_bytes) # Load the credentials database using the provided master key

    while True:
        print("Password Manager")
        print("1. Add Credential")
        print("2. View Credentials")
        print("3. Save and Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            add_credential(database) # Add a new credential to the database
        
        elif choice == '2':
            view_credentials(database) # Display all credentials in the database

        elif choice == '3':
            save_database(database, key_bytes) # Save the database to a file and exit the program
            print("Exiting...")
            break

        else:
            print("Invalid option. Please try again.\n")

if __name__ == "__main__":
    main()