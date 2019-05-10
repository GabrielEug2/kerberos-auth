
from cryptography.fernet import Fernet

class AES:
    @classmethod
    def generate_new_key(cls):
        return Fernet.generate_key()

    @classmethod
    def encrypt(cls, data, key):
        f = Fernet(key)
        encrypted_data = f.encrypt(data)

        return encrypted_data

    @classmethod
    def decrypt(cls, encrypted_data, key):
        f = Fernet(key)
        data = f.decrypt(encrypted_data)

        return data