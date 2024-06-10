import os
import shutil
from cryptography.fernet import Fernet
import hashlib
import base64
import getpass

MENU = \
"""\
SELECT AN OPTION
1 - ENCRYPT
2 - DECRYPT
3 - SET PASSWORD
4 - CREATE DECRYPT DIR
0 - EXIT
"""

def reset_password():
    password1 = getpass.getpass("Enter your password: ")
    password2 = getpass.getpass("Repeat your password: ")
    
    if password1 == password2:
        password_hash = generating_sha512_hash(password1)
        with open('keep', 'w+') as file:
            file.write(password_hash)
    else:
        print('Password mismatch.')


def generating_sha512_hash(password):
    sha512 = hashlib.sha512()
    sha512.update(password.encode('ascii', errors='ignore'))
    hash_result = sha512.hexdigest()
    return hash_result

def cheking_pass(password):
    sent_hash = generating_sha512_hash(password)

    with open('keep', 'r') as file:
        actual_hash = file.read()

    if sent_hash == actual_hash:
        return True
    else:
        return False

def generate_key_from_password(password, salt=b'', iterations=100000):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return key

def generate_fernet_key(password):
    key = generate_key_from_password(password)
    return base64.urlsafe_b64encode(key)

def remove_dir(path):
    for root, dirs, files in os.walk(path, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            os.remove(file_path)
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            os.rmdir(dir_path)
    os.rmdir(path)

def encrypt_file(file_path, key):
    """
    Encrypt a file using the given key.
    """
    with open(file_path, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    with open(file_path + '.encrypted', 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(file_path, key):
    """
    Decrypt a file using the given key.
    """
    with open(file_path, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(data)
    with open(file_path[:-10], 'wb') as f:  # remove '.encrypted' extension
        f.write(decrypted_data)

def encrypt_directory(source_dir, destination_dir, key):
    """
    Encrypt all files in a directory and its subdirectories.
    """
    for root, _, files in os.walk(source_dir):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)
            shutil.move(file_path + '.encrypted', destination_dir)

def decrypt_directory(source_dir, destination_dir, key):
    """
    Decrypt all files in a directory and its subdirectories.
    """
    for root, _, files in os.walk(source_dir):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, key)
            shutil.move(file_path[:-10], destination_dir)


# Example usage:
password = "super_secret_password"

encrypted_directory = "encrypted"
decrypted_directory = "decrypted"

def main():
    while True:
        print(MENU)
        option = input("> ")

        if option == '0':
            break
        
        elif option == '1':
            if os.path.isdir(encrypted_directory):
                print("Directory exists, delete it before.")

            else:
                password = getpass.getpass("Enter your password: ")
                if cheking_pass(password):
                    key = generate_fernet_key(password)
                    os.mkdir(encrypted_directory)
                    encrypt_directory(decrypted_directory, encrypted_directory, key)
                    remove_dir(decrypted_directory)
                else:
                    print("Incorrect password.")

        elif option == '2':
            if os.path.isdir(decrypted_directory):
                print("Directory exists, delete it before.")
            else:
                password = getpass.getpass("Enter your password: ")

                if cheking_pass(password):
                    key = generate_fernet_key(password)
                    os.mkdir(decrypted_directory)
                    decrypt_directory(encrypted_directory, decrypted_directory, key)
                    remove_dir(encrypted_directory)
                else:
                    print("Incorrect password.")
        elif option == '3':
            if os.path.isfile('keep') and os.path.isdir(encrypted_directory):
                print("You're trying to reset your password with your data encrypted you can lose all your data, are you shure?")
                o = input('[y/n]')
                if o.lower() == 'y':
                    remove_dir(encrypted_directory)
                    reset_password()
                    os.mkdir(decrypted_directory)
                else:
                    print('Nothing to do.')
            else:
                reset_password()
        elif option == '4':
            os.mkdir(decrypted_directory)
        else:
            print("Option not defined.")

main()
