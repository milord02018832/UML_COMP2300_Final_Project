import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

def get_contacts_file(email):
    return f"contacts_{email.replace('@', '_at_')}.bin"


def derive_key(password_hash, salt):
    """Derive a symmetric key from password hash and salt."""
    # Use SHA-256 of (password_hash + salt) for key
    key_material = (password_hash + salt).encode('utf-8')
    return hashlib.sha256(key_material).digest()


def encrypt_contacts(key, contacts):
    data = json.dumps(contacts).encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')


def decrypt_contacts(key, enc_data):
    raw = base64.b64decode(enc_data.encode('utf-8'))
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(data.decode('utf-8'))


def load_contacts(email, password_hash, salt):
    filename = get_contacts_file(email)
    key = derive_key(password_hash, salt)
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            enc_data = f.read()
        # decode to str for decrypt_contacts
        return decrypt_contacts(key, enc_data.decode('utf-8'))
    return []


def save_contacts(email, password_hash, salt, contacts):
    filename = get_contacts_file(email)
    key = derive_key(password_hash, salt)
    enc_data = encrypt_contacts(key, contacts)
    with open(filename, 'wb') as f:
        f.write(enc_data.encode('utf-8'))


def add_contact(email, password_hash, salt, contact_email):
    contacts = load_contacts(email, password_hash, salt)
    if contact_email in contacts:
        raise ValueError("Contact already added.")
    contacts.append(contact_email)
    save_contacts(email, password_hash, salt, contacts)
    return True


def list_contacts(email, password_hash, salt):
    return load_contacts(email, password_hash, salt)
