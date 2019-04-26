
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

class AES:
    AES_BLOCK_SIZE = 128 # 16 bytes

    @classmethod
    def encrypt(cls, data_str, key):
        # Transforma a string em bytes
        data = data_str.encode()

        # Faz padding, pois o AES criptografa por blocos
        # (e o tamanho da string tem que ser um multiplo do tamanho do bloco)
        padder = padding.PKCS7(cls.AES_BLOCK_SIZE).padder()
        data = padder.update(data) + padder.finalize()

        # Criptografa
        encryptor = Cipher(
            algorithms.AES(bytes.fromhex(key)),
            modes.CBC(os.urandom(16)),
            backend=default_backend()
        ).encryptor()

        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Retorna como uma string em base64
        return base64.b64encode(encrypted_data).decode('utf-8')

    @classmethod
    def decrypt(cls, encrypted_data_str, key):
        # Transforma a string em bytes (não esquecendo que estava em base64)
        encrypted_data = base64.b64decode(encrypted_data_str.encode())

        # Descriptografa
        decryptor = Cipher(
            algorithms.AES(bytes.fromhex(key)),
            modes.CBC(os.urandom(16)),
            backend=default_backend()
        ).decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove o padding
        unpadder = padding.PKCS7(cls.AES_BLOCK_SIZE).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Retorna como uma string em base64
        return base64.b64encode(decrypted_data).decode('utf-8')