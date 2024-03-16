import os
import argparse

from cryptography import x509
from  cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from key import Key
from certificate import Certificate
from san import SAN

class Command:

    def create_parser(self):
        parser = argparse.ArgumentParser()
        subparser = parser.add_subparsers(dest='command')

        p = subparser.add_parser('key', help='generate private key')
        p.add_argument('-k', '--key', required=True, help="output path for private key with PEM encoding")

        p = subparser.add_parser('ca', help='generate root key and cert')
        p.add_argument('-n', '--dn', required=True)
        p.add_argument('-C', '--ca-cert', required=True, help="CA certificate file path")
        p.add_argument('-K', '--ca-key', nargs='?', help="CA private key path. If missing it will will generate a key")
        p.add_argument('-e', '--expires', type=int, default=3650, help="expiry in days")

        p = subparser.add_parser('cert', help='generate key and cert')
        p.add_argument('-n', '--dn', required=True)
        p.add_argument('-k', '--key', required=True, help="private key with PEM encoding. if missing will generate a key file in this location")
        p.add_argument('-c', '--cert', required=True, help="certificate file path")
        p.add_argument('-K', '--ca-key', required=True, help="CA private key path. If missing it will look for a key file in the same diretory as --ca-cert")
        p.add_argument('-C', '--ca-cert', required=True, help="CA certificate file path. If missing will generate a self-signed-certificate")
        p.add_argument('-s', '--san', nargs='*', default=[], help="list of SAN in the form DNS:<FQDN> and IP:<IPV4 ADDRESS>")
        p.add_argument('-e', '--expires', type=int, default=365, help="expiry in days")

        p = subparser.add_parser('pkcs12', help='create pkcs12 keystore')
        p.add_argument('-s','--keystore', required=True, help="keystore file parth")
        p.add_argument('-k', '--key', required=True, help="private key with PEM encoding. if missing will generate a key file in this location")
        p.add_argument('-c', '--cert', required=True, help="certificate file path")
        p.add_argument('-C', '--ca-certs', nargs='*', default=[], help="CA certificates file paths")
        p.add_argument('-p', '--password', type=str, default='changeit', help='password for keystore (default is "changeit")')

        return parser

    usage_defaults = {
        "digital_signature": False,
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
      
    def key(self, key_arg):
        Key.generate().save(key_arg)

    def ca(self, dn, ca_key_path, ca_cert_path, expires):
        ca_key = Key.new(ca_key_path)
        basic = x509.BasicConstraints(ca=True, path_length=None) 
        usage = self.key_usage(digital_signature=True, key_cert_sign=True, crl_sign=True)
        extensions = [ (basic, True) , (usage, True) ]
        cert = Certificate.create(dn, ca_key, extensions)
        cert.sign(dn, ca_key, expires)
        cert.save(ca_cert_path)

    def cert(self, dn, key_path, cert_path, ca_key_path, ca_cert_path, san_list, expires):
        key = Key.new(key_path)
        ca_key = Key.load(ca_key_path)
        ca_cert = Certificate.load(ca_cert_path)
        basic = x509.BasicConstraints(ca=False, path_length=None) 
        usage = self.key_usage(digital_signature=True, key_encipherment=True)
        usages = x509.ExtendedKeyUsage([ x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH ])
        if san_list:
            san = SAN(san_list)
            extensions = [ (basic, False), (usage, True), (usages, False), (san.value, False) ]
        else:
            extensions = [ (basic, False), (usage, True), (usages, False) ]
        cert = Certificate.create(dn, key, extensions)
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
