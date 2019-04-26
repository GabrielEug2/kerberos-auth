import secrets

class RandomGenerator:
    @classmethod
    def rand_int(cls):
        return secrets.randbits(256) # 32 bytes