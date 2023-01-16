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
      
    def key(self, args):
        Key.generate().save(args.key)

    # Namespace(command='ca', dn='ss', ca_cert='c', ca_key=None)

    def ca(self, args):
        ca_key = Key.new(args.ca_key)
        basic = x509.BasicConstraints(ca=True, path_length=None) 
        usage = self.key_usage(digital_signature=True, key_cert_sign=True, crl_sign=True)
        extensions = [ (basic, True) , (usage, True) ]
        cert = Certificate.create(args.dn, ca_key, extensions)
        cert.sign(args.dn, ca_key, args.expires)
        cert.save(args.ca_cert)

    # Namespace(command='cert', dn='CN=X', key='www.key', cert='www.crt', ca_key='ca.key', ca_cert='ca.crt', san=[])

    def cert(self, args):
        san = SAN(args.san)
        ca_key = Key.load(args.ca_key)
        ca_cert = Certificate.load(args.ca_cert)
        key = Key.new(args.key)
        basic = x509.BasicConstraints(ca=False, path_length=None) 
        usage = self.key_usage(digital_signature=True, key_encipherment=True)
        usages = x509.ExtendedKeyUsage([ x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH ])
        extensions = [ (basic, False), (usage, True), (usages, False), (san.value, False) ]
        cert = Certificate.create(args.dn, key, extensions)
        cert.sign(ca_cert.issuer, ca_key, args.expires)
        cert.save(args.cert)

    # Namespace(command='pkcs12', keystore='www.p12', key='www.key', cert='www.crt', ca_certs=['ca.crt'], password='inc0rrect')

    def pkcs12(self, args):
        key = Key.load(args.key)
        cert = Certificate.load(args.cert)
        password = args.password.encode('utf-8')
        ca_certs = [ Certificate.x509_load(c) for c in args.ca_certs ]
        print(ca_certs)
        p12 = pkcs12.serialize_key_and_certificates(b'store', key.private(), cert.cert, ca_certs,  BestAvailableEncryption(password))
        with open(args.keystore, "wb") as f:
            f.write(p12)

    def run(self, args):
        fn = eval(f"self.{args.command}")
        fn(args)
