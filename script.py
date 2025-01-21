from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os, base64

def derive_key(password, salt, iterations=100000):
    return PBKDF2HMAC(SHA256(), 32, salt, iterations, default_backend()).derive(password.encode())

def encrypt(plaintext, password):
    salt, iv = os.urandom(16), os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).encryptor()
    padded_data = padding.PKCS7(128).padder().update(plaintext.encode()) + padding.PKCS7(128).padder().finalize()
    return base64.b64encode(iv + cipher.update(padded_data) + cipher.finalize()).decode(), salt

def decrypt(ciphertext, password, salt):
    ciphertext = base64.b64decode(ciphertext)
    iv, encrypted_data = ciphertext[:16], ciphertext[16:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).decryptor()
    padded_data = cipher.update(encrypted_data) + cipher.finalize()
    return padding.PKCS7(128).unpadder().update(padded_data) + padding.PKCS7(128).unpadder().finalize()

if __name__ == "__main__":
    password = "HardcorePassword"
    plaintext = "Confidential Data: Encrypt This!"
    
    ciphertext, salt = encrypt(plaintext, password)
    print(f"Encrypted: {ciphertext}")
    print(f"Salt: {salt.hex()}")
    
    decrypted_text = decrypt(ciphertext, password, salt)
    print(f"Decrypted: {decrypted_text.decode()}")
