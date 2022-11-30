
from cryptography import x509
import ipaddress

san = x509.SubjectAlternativeName(
        [ x509.DNSName(u'cryptography.io'), x509.DNSName(u'www.cryptography.io'), x509.IPAddress(ipaddress.IPv4Address('192.168.1.1')) ]
    )


class SAN:

    def __init__(self, san):
        self.san = san

    def entry(self):
        (label, subject) = self.san.split(":")
        if label == "DNS":
            return x509.DNSName(subject)
        if label == "IP":
            return x509.IPAddress(ipaddress.IPv4Address(subject))
        raise RuntimeError(f"SAN type for {self.san} not known")

#builder = builder.subject_name(x509.Name([
#    x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
#]))

#dn=[ x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography'), x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'example') , x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'com') ]
#print(dn)

for subject in [ "DNS:www.cryptography.io", "IP:192.168.1.1" ]:
  dn = SAN(subject)
  print(dn.entry())
