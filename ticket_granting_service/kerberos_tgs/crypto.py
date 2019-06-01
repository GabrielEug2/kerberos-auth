
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Crypto:
    """Criptografia simétrica.
    
    AES-128 com modo CBC e padding PKCS7 (Fernet)
    """

    @classmethod
    def generate_key(cls):
        """Gera uma nova chave simétrica
        
        Returns:
            bytes: Chave gerada
        """
        return Fernet.generate_key()

    @classmethod
    def generate_key_from_password(cls, password, salt):
        """Deriva uma chave simétrica a partir da senha
        
        Args:
            password (str): Senha
            salt (bytes): Salt
        
        Returns:
            bytes: Chave gerada
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=2000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        return key

    @classmethod
    def encrypt(cls, data, key):
        """Criptografa os dados usando a chave especificada.
        
        Args:
            data (bytes): Dados a serem criptografados
            key (bytes): Chave para a criptografia
        
        Returns:
            bytes: Dados encriptados
        """

        f = Fernet(key)
        encrypted_data = f.encrypt(data)

        return encrypted_data

    @classmethod
    def decrypt(cls, encrypted_data, key):
        """Descriptografa os dados usando a chave especificada.
        
        Args:
            encrypted_data (bytes): Dados a serem descriptografados
            key (bytes): Chave para descriptografar

        Returns:
            bytes: Dados desencriptados
        """

        f = Fernet(key)
        data = f.decrypt(encrypted_data)

        return data