from cryptography.fernet import Fernet

def encrypt_key(key):
    return Fernet(key)
