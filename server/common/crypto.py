import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

BYTE_SIZE = 8


def generate_aes_key(aes_key_size: int) -> bytes:
    """Generates and returns an AES key."""
    return os.urandom(aes_key_size)


def encrypt_aes_key(aes_key: bytes, pub_key: bytes) -> bytes:
    """Encrypts a given aes key using a given rsa key, and returns it."""
    rsa_pub_key = RSA.import_key(pub_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_pub_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return encrypted_aes_key


def decrypt_using_aes(data: bytes, aes_key: bytes) -> bytes:
    """Decrypting given data by given aes_key, and returning the decrypted data"""
    # We are assuming IV is always set to zeros
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)
    decrypted_data = cipher_aes.decrypt(data)

    padding_length = decrypted_data[-1]
    return decrypted_data[:-padding_length]  # Remove PKCS#7 padding
