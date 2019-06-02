import secrets

class Random:
    """Gerador de valores aleatórios"""

    @classmethod
    def rand_int(cls):
        """Retorna um inteiro aleatório"""
        return secrets.randbits(32) # 4 bytes