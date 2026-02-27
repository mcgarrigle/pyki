import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Key:

    def __init__(self, key):
        self.key = key

    @staticmethod
    def generate(key_size=2048):
        return Key(rsa.generate_private_key(public_exponent=65537, key_size=key_size))

    @staticmethod
    def load_pem_file(path):
        with open(path) as f:
            pem = bytearray(f.read(), "utf8")
            return serialization.load_pem_private_key(pem, password=None)

    @staticmethod
    def load(path):
        return Key(Key.load_pem_file(path))

    @staticmethod
    def new(path, key_size = 2048):
        if os.path.isfile(path):
            k = Key.load(path)
        else:
            k = Key.generate(key_size)
            k.save(path)
        return k

    def save(self, path):
        with open(path, "w") as f:
            f.write(self.pem())

    def private(self):
        return self.key

    def public(self):
        return self.key.public_key()

    def pem(self):
        key = self.key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return key.decode('utf8')
