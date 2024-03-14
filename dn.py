from cryptography import x509
from cryptography.x509.oid import NameOID

class DN:

    mapping = {
        "CN":  NameOID.COMMON_NAME,
        "DC":  NameOID.DOMAIN_COMPONENT,
        "C":   NameOID.COUNTRY_NAME,
        "L":   NameOID.LOCALITY_NAME,
        "S":   NameOID.STATE_OR_PROVINCE_NAME,
        "ST":  NameOID.STATE_OR_PROVINCE_NAME,
        "UID": NameOID.USER_ID,
        "O":   NameOID.ORGANIZATION_NAME,
        "OU":  NameOID.ORGANIZATIONAL_UNIT_NAME
    }

    def __init__(self, dn):
        attributes = [ self.attribute(self.chop(s, "=")) for s in self.chop(dn, ",") ]
        self.name = x509.Name(attributes)

    def chop(self, s, c):
        return [ e.strip() for e in s.split(c) ]

    def attribute(self, pair):
        (name, value) = pair
        oid = DN.mapping[name]
        if oid is None:
            raise RuntimeError(f"DN attribute {name} not known")
        return x509.NameAttribute(oid, value)

    def __str__(self):
        return self.name.rfc4514_string()
