from cryptography.fernet import Fernet

def encrypt_note(note, key):
    fernet = Fernet(key)
    return fernet.encrypt(note.encode()).decode()

def decrypt_note(encrypted_note, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_note.encode()).decode() 