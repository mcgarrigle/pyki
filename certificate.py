from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime
import ipaddress

from dn import DN
from san import SAN

class Certificate:

    @staticmethod
    def load(path):
        new = Certificate()
        with open(path) as f:
            pem = bytearray(f.read(), "utf8")
            new.cert = x509.load_pem_x509_certificate(pem)
        return new

    def create(self, dn, private_key, san):
        self.dn = DN(dn)
        self.san = SAN(san)

    def sign(self, ca_certificate, ca_private_key):
        pass

    def pem(self):
       return self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

c = Certificate.load('/etc/ssl/certs/GTS_Root_R2.pem')
print(c.pem())

print(c.cert.subject.rfc4514_string())
