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

    def save(self, path):
        with open(path, "w") as f:
            f.write(self.pem())

    @staticmethod
    def create(subject, private_key, extensions):
        one_day = datetime.timedelta(1, 0, 0)
        public_key = private_key.public()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(DN(subject).name)
        builder = builder.public_key(public_key)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        for extension in extensions:
            builder = builder.add_extension(extension, critical=True)
        new = Certificate()
        new.builder = builder
        return new

    def sign(self, issuer, ca_private_key):
        self.builder = self.builder.issuer_name(DN(issuer).name)
        self.cert = self.builder.sign(
           private_key=ca_private_key.private(),
           algorithm=hashes.SHA256(),
        )

    def pem(self):
       return self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    def __repr__(self):
      return repr(self.cert)
