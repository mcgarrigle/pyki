from dn import DN

issuer_dn = 'C = UK, ST = Wales, O = Mac, CN = CA'
dn = DN(issuer_dn)

print(type(dn))
print(dn.to_string())
print(str(dn))
