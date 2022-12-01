import ipaddress
from cryptography import x509

class SAN:

    def __init__(self, san):
        self.san = san

    @property
    def value(self):
        (label, subject) = self.san.split(":")
        if label == "DNS":
            return x509.DNSName(subject)
        if label == "IP":
            return x509.IPAddress(ipaddress.IPv4Address(subject))
        raise RuntimeError(f"SAN type for {self.san} not known")

for subject in [ "DNS:www.cryptography.io", "IP:192.168.1.1" ]:
  dn = SAN(subject)
  print(dn.value)
