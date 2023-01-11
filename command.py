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

    def key_usage(self, **kwargs):
        defaults = {
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
        args = defaults.update(kwargs)
        return x509.KeyUsage(**defaults)
      
    def key(self,args):
        Key.generate().save(args.key)

    # ca Namespace(command='ca', dn='ss', ca_cert='c', ca_key=None)

    #   X509v3 extensions:
    #       X509v3 Key Usage: critical
    #           Digital Signature, Certificate Sign, CRL Sign
    #       X509v3 Basic Constraints: critical
    #           CA:TRUE

    def ca(self,args):
        ca_key = self.new_key(args.ca_key)
        basic = x509.BasicConstraints(ca=True, path_length=None) 
        usage = self.key_usage(digital_signature=True, key_cert_sign=True, crl_sign=True)
        extensions = [ (basic, True) , (usage, True) ]
        cert = Certificate.create(args.dn, ca_key, extensions)
        cert.sign(args.dn, ca_key)
        cert.save(args.ca_cert)

    # Namespace(command='cert', dn='CN=X', key='x.key', cert='x.crt', ca_key='ca.key', ca_cert='ca.crt', san=[])

     # X509v3 Subject Alternative Name:
     #     DNS:bt.com, DNS:home.bt.com, DNS:img01.products.bt.co.uk, DNS:www.bt.com, DNS:www.home.bt.com, DNS:www.products.bt.com, DNS:www.productsandservices.bt.com
     # X509v3 Key Usage: critical
     #     Digital Signature, Key Encipherment
     # X509v3 Basic Constraints:
     #     CA:FALSE

    def cert(self,args):
        san = SAN(args.san)
        ca_key = self.new_key(args.ca_key)
        ca_cert = Certificate.load(args.ca_cert)
        key = self.new_key(args.key)
        basic = x509.BasicConstraints(ca=False, path_length=None) 
        usage = self.key_usage(digital_signature=True, key_encipherment=True)
        usages = x509.ExtendedKeyUsage([ x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH ])
        extensions = [ (basic, False), (usage, True), (usages, False), (san.value, False) ]
        cert = Certificate.create(args.dn, key, extensions)
        cert.sign(ca_cert.cert.issuer.rfc4514_string(), ca_key)
        cert.save(args.cert)

    def run(self, args):
        fn = eval(f"self.{args.command}")
        fn(args)
