#!/bin/bash -e

cert() {
  echo
  echo "--- $1 --------------"
  openssl x509 -noout -issuer -subject -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName -in $1
}

rm -f *.key *.crt

./pyki ca \
  --dn 'C=UK, S=Wales, O=Mac, CN=CA' \
  --ca-cert secrets/ca.crt \
  --ca-key  secrets/ca.key

./pyki cert \
  --dn 'C=UK, S=Wales, O=Mac, CN=www' \
  --ca-cert secrets/ca.crt \
  --ca-key  secrets/ca.key \
  --cert secrets/www.crt \
  --key  secrets/www.key \
  --san 'DNS:mac.wales' 'DNS:www.mac.wales' 'IP:192.168.0.1'

./pyki pkcs12 \
  --key secrets/www.key \
  --cert secrets/www.crt \
  --ca-certs secrets/ca.crt \
  -s secrets/www.p12 \
  --password inc0rrect

cert secrets/ca.crt
cert secrets/www.crt

echo
echo "--- keystore www.p12 --------------"
openssl pkcs12 -nokeys -info -in secrets/www.p12 -passin pass:inc0rrect

echo
keytool -list -keystore secrets/www.p12 -storepass inc0rrect
