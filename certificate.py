from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import datetime
import ipaddress

from dn import DN
from san import SAN

class Certificate:

    one_day = datetime.timedelta(1, 0, 0)

    def __init__(self, subject, key, extensions):
        self.subject     = subject
        self.key         = key
        self.extensions  = extensions

    @staticmethod
    def x509_load(path):
        with open(path, 'rb') as f:
            pem  = f.read()
            cert = x509.load_pem_x509_certificate(pem)
        return cert

    @staticmethod
    def load(path):
        new = Certificate(None, None, None)
        new.cert = Certificate.x509_load(path)
        return new

    def save(self, path):
        with open(path, "w") as f:
            f.write(self.pem())

    def sign(self, issuer, ca_private_key, expires=365):
        issuer_x509_name  = DN(issuer).name
        subject_x509_name = DN(self.subject).name
        builder = x509.CertificateBuilder()
        builder = builder \
            .subject_name(subject_x509_name) \
            .issuer_name(issuer_x509_name) \
            .public_key(self.key.public()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.today()) \
            .not_valid_after(datetime.datetime.today() + (self.one_day * expires))
        for (extension, criticality) in self.extensions:
            builder = builder.add_extension(extension, critical=criticality)
        self.cert = builder.sign(
           private_key=ca_private_key.private(),
           algorithm=hashes.SHA256(),
        )

    @property
    def issuer(self):
        return str(DN(self.cert.issuer))

    #@property
    #def subject(self):
    #    return str(DN(self.cert.subject))

    def pem(self):
       return self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    def __repr__(self):
      return repr(self.subject)
