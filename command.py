import os

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from key import Key
from certificate import Certificate
from san import SAN

class Command:

    usage_defaults = {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False
    }

    def key_usage(self, **kwargs):
        args = Command.usage_defaults.copy()
        args.update(kwargs)
        return x509.KeyUsage(**args)
      
    def key(self, key_path, key_size):
        Key.generate(key_size).save(key_path)

    def ca(self, dn, ca_key_path, ca_cert_path, expires, key_size):
        ca_key     = Key.new(ca_key_path, key_size)
        basic      = x509.BasicConstraints(ca=True, path_length=None) 
        usage      = self.key_usage(key_cert_sign=True, crl_sign=True)
        extensions = [ (basic, True) , (usage, True) ]
        # extensions = [ (basic, True) ]
        cert = Certificate(dn, ca_key, extensions)
        cert.sign(dn, ca_key, expires)
        cert.save(ca_cert_path)

    def cert(self, dn, key_path, cert_path, ca_key_path, ca_cert_path, san_list, expires, key_size):
        key        = Key.new(key_path, key_size)
        ca_key     = Key.load(ca_key_path)
        ca_cert    = Certificate.load(ca_cert_path)
        basic      = x509.BasicConstraints(ca=False, path_length=None) 
        usage      = self.key_usage(key_encipherment=True)
        extended   = x509.ExtendedKeyUsage([ x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH ])
        extensions = [ (basic, False), (usage, True), (extended, False) ]
        if san_list:
            san = SAN(san_list)
            extensions.append((san.value, False))
        cert = Certificate(dn, key, extensions)
        cert.sign(ca_cert.issuer, ca_key, expires)
        cert.save(cert_path)

    def pkcs12(self, keystore_path, key_path, cert_path, ca_certs, password):
        key = Key.load(key_path)
        cert = Certificate.load(cert_path)
        password = password.encode('utf-8')
        ca_certs = [ Certificate.x509_load(c) for c in ca_certs ]
        p12 = pkcs12.serialize_key_and_certificates(b'store', key.private(), cert.cert, ca_certs,  BestAvailableEncryption(password))
        with open(keystore_path, "wb") as f:
            f.write(p12)
