
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
        self.dn = dn

    def element(self, s):
        (name, value) = [ e.strip() for e in s.split("=") ]
        return x509.NameAttribute(DN.mapping[name], value)

    def oid(self):
        elements = [ self.element(s.strip()) for s in self.dn.split(",") ]
        return x509.Name(elements)


#builder = builder.subject_name(x509.Name([
#    x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
#]))

#dn=[ x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography'), x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'example') , x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'com') ]
#print(dn)

dn = DN("CN =foo, OU=hq ,DC = example , DC=org")

print(dn.oid())
