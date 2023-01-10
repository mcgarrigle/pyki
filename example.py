
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import ipaddress


san = x509.SubjectAlternativeName(
        [ x509.DNSName(u'cryptography.io'), x509.DNSName(u'www.cryptography.io'), x509.IPAddress(ipaddress.IPv4Address('192.168.1.1')) ]
    )

print(san)

one_day = datetime.timedelta(1, 0, 0)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
builder = x509.CertificateBuilder()
dn=[ x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography'), x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'example') , x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'com') ]
print(dn)
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
]))
builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
]))
builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(public_key)
builder = builder.add_extension(san, critical=False)
builder = builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None), critical=True,
)
certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
)
print(isinstance(certificate, x509.Certificate))
pem = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
print(pem)
