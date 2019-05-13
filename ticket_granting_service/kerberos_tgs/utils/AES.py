
from cryptography.fernet import Fernet

class AES:
    """Criptografia AES com modo CBC, chaves de 128 bits e padding PKCS7."""

    @classmethod
    def generate_new_key(cls):
        """Gera uma nova chave simétrica.
        
        Returns:
            bytes: Chave codificada em Base64
        """

        return Fernet.generate_key()

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