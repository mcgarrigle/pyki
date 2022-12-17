
from cryptography import x509
from cryptography.x509.oid import NameOID

class DN:

    mapping = {
        "CN":  NameOID.COMMON_NAME,
        "DC":  NameOID.DOMAIN_COMPONENT,
        "C":   NameOID.COUNTRY_NAME,
        "L":   NameOID.LOCALITY_NAME,
        "UID": NameOID.USER_ID,
        "OU":  NameOID.ORGANIZATIONAL_UNIT_NAME
    }

    def __init__(self, dn):
        attributes = [ self.attribute(self.chop(s, "=")) for s in self.chop(dn, ",") ]
        self.name = x509.Name(attributes)

    def chop(self, s, c):
        return [ e.strip() for e in s.split(c) ]

    def attribute(self, pair):
        (name, value) = pair
        return x509.NameAttribute(DN.mapping[name], value)

    def oid(self):
        return self.name

    def __str__(self):
        return self.name.rfc4514_string()

#dn = DN("CN =foo, OU= blue team ,DC = example , DC=org")
#print(dn.oid())
#print(dn)
