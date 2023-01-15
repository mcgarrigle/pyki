import os
import argparse

from cryptography import x509
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
      
    def key(self,args):
        Key.generate().save(args.key)

    # Namespace(command='ca', dn='ss', ca_cert='c', ca_key=None)

    def ca(self,args):
        ca_key = Key.new(args.ca_key)
        basic = x509.BasicConstraints(ca=True, path_length=None) 
        usage = self.key_usage(digital_signature=True, key_cert_sign=True, crl_sign=True)
        extensions = [ (basic, True) , (usage, True) ]
        cert = Certificate.create(args.dn, ca_key, extensions)
        cert.sign(args.dn, ca_key, args.expires)
        cert.save(args.ca_cert)

    # Namespace(command='cert', dn='CN=X', key='x.key', cert='x.crt', ca_key='ca.key', ca_cert='ca.crt', san=[])

    def cert(self,args):
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

    def run(self, args):
        fn = eval(f"self.{args.command}")
        fn(args)
