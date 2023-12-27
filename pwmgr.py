## This is a password manager program 

import json
import os
from cryptography.fernet import Fernet
from getpass import getpass
import bcrypt
import base64
import random

def derive_key(password: str, salt: bytes) -> bytes:
    return bcrypt.kdf(
        password=password.encode(), 
        salt=salt, 
        desired_key_bytes=32, 
        rounds=100
    )

def generate_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        password = getpass("Enter your password to decrypt the key: ")
        with open(key_file, 'rb') as file:
            file_content = file.read()
            encrypted_key, salt = file_content.split(b':')
            derived_key = derive_key(password, salt)
            fernet = Fernet(base64.urlsafe_b64encode(derived_key))
            return fernet.decrypt(encrypted_key)
    else:
        password = getpass("Set a password for encrypting the key: ")
        key = Fernet.generate_key()
        salt = os.urandom(16)
        derived_key = derive_key(password, salt)
        fernet = Fernet(base64.urlsafe_b64encode(derived_key))
        encrypted_key = fernet.encrypt(key)
        with open(key_file, 'wb') as file:
            file.write(encrypted_key + b':' + salt)
        return key

key = generate_key()
fernet = Fernet(key)

# Functions for password management
def create_or_load_database():
    if not os.path.exists('passwords.json'):
        with open('passwords.json', 'w') as db_file:
            json.dump({}, db_file)

def add_password(service, password):
    with open('passwords.json', 'r+') as db_file:
        db = json.load(db_file)
        encrypted_password = fernet.encrypt(password.encode()).decode()
        db[service] = encrypted_password
        db_file.seek(0)
        json.dump(db, db_file)

def get_password(service):
    with open('passwords.json', 'r') as db_file:
        db = json.load(db_file)
        if service in db:
            encrypted_password = db[service].encode()
            return fernet.decrypt(encrypted_password).decode()
        return None

## Password Generator
def generate_password(length=12):
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()'
    return ''.join(random.choice(characters) for i in range(length))

## Command line interface
def main():
    create_or_load_database()

    while True:
        action = input("What would you like to do? [Add/Get/Generate/Quit]: ").lower()
        if action == 'add':
            service = input("Enter the service name: ")
            password = getpass("Enter the password: ")
            add_password(service, password)
            print("Password added successfully.")
        elif action == 'get':
            service = input("Enter the service name: ")
            password = get_password(service)
            if password:
                print(f"Password for {service}: {password}")
            else:
                print("No password found for this service.")
        elif action == 'generate':
            length = int(input("Enter the desired length of the password: "))
            print(f"Generated password: {generate_password(length)}")
        elif action == 'quit':
            break
        else:
            print("Invalid action.")

# Run the main Function
if __name__ == '__main__':
    main()
