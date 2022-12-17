from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Key:

    def __init__(self):
        pass

    def generate(self, key_size=2048):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        return self

    def read(self, f):
        self.key = serialization.load_pem_private_key(f.read(), password=None)
        return self

    def private(self):
        return self.key

    def public(self):
        pass

    def pem(self):
        return self.key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

k = Key()
print(k.generate().pem())
