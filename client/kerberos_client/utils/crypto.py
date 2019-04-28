
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

import secrets

class AES:
    AES_BLOCK_SIZE = 128 # 16 bytes

    @classmethod
    def generate_new_key(cls):
        return secrets.token_hex(32) # 32 bytes = 256 bits

    @classmethod
    def encrypt(cls, data_str, key):
        # Transforma a string em bytes
        data = data_str.encode()

        # Faz padding, pois o AES criptografa por blocos
        # (e o tamanho da string tem que ser um multiplo do tamanho do bloco)
        padder = padding.PKCS7(cls.AES_BLOCK_SIZE).padder()
        data = padder.update(data) + padder.finalize()

        # Criptografa
        iv = os.urandom(16)

        encryptor = Cipher(
            algorithms.AES(bytes.fromhex(key)),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()

        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Retorna como uma string em base64
        encrypted_str = base64.b64encode(encrypted_data).decode('utf-8')
        iv_str = base64.b64encode(iv).decode('utf-8')

        return encrypted_str, iv_str

    @classmethod
    def decrypt(cls, encrypted_data_str, key, iv_str):
        # Transforma a string e o iv em bytes (não esquecendo que estava em base64)
        encrypted_data = base64.b64decode(encrypted_data_str.encode())
        iv = base64.b64decode(iv_str.encode())

        # Descriptografa
        decryptor = Cipher(
            algorithms.AES(bytes.fromhex(key)),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove o padding
        unpadder = padding.PKCS7(cls.AES_BLOCK_SIZE).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Retorna como uma string utf-8
        return decrypted_data.decode('utf-8')