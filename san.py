import ipaddress
from cryptography import x509

class SAN:

    def __init__(self, san):
        self.san = san

    def item(self, name):
        (label, subject) = name.split(":", 1)
        if label == "DNS":
            return x509.DNSName(subject)
        if label == "IP":
            return x509.IPAddress(ipaddress.IPv4Address(subject))
        raise RuntimeError(f"SAN type for {name} not known")

    @property
    def value(self):
        items = [ self.item(element) for element in self.san ]
        return x509.SubjectAlternativeName(items)
