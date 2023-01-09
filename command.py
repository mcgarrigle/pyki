import os
from cryptography import x509
from key import Key
from certificate import Certificate
from san import SAN

class Command:

    def new_key(self, path):
        if os.path.isfile(path):
            private_key = Key.load(path)
        else:
            print("new key")
            private_key = Key.generate()
            private_key.save(path)
        return private_key

    def key(self,args):
        Key.generate().save(args.key)

    # ca Namespace(command='ca', dn='ss', ca_cert='c', ca_key=None)

    def ca(self,args):
        print(args)
        ca_key = self.new_key(args.ca_key)
        basic = x509.BasicConstraints(ca=True, path_length=None) 
        extensions = [ basic ]
        cert = Certificate.create(args.dn, ca_key, extensions)
        cert.sign(args.dn, ca_key)
        cert.save(args.ca_cert)

    # Namespace(command='cert', dn='CN=X', key='x.key', cert='x.crt', ca_key='ca.key', ca_cert='ca.crt', san=[])

    def cert(self,args):
        print(args)
        san = SAN(args.san)
        print(san)
        ca_key = self.new_key(args.ca_key)
        ca_cert = Certificate.load(args.ca_cert)
        key = self.new_key(args.key)
        basic = x509.BasicConstraints(ca=False, path_length=None) 
        extensions = [ basic, san ]
        cert = Certificate.create(args.dn, key, extensions)
        cert.sign(ca_cert.cert.issuer.rfc4514_string(), ca_key)
        cert.save(args.cert)

    def run(self, args):
        fn = eval(f"self.{args.command}")
        fn(args)
