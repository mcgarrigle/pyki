#!/bin/bash -e

key() {
  echo
  echo "--- key $1 --------------"
  openssl rsa -in $1 -text -noout |grep Private
}

cert() {
  echo
  echo "--- certificate $1 --------------"
  openssl x509 -noout -issuer -subject -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName -in $1
}

rm -f secrets/*.{key,crt,p12}

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
  --san 'DNS:mac.wales' \
  --san 'DNS:www.mac.wales' \
  --san 'IP:192.168.0.1'

./pyki pkcs12 \
  --keystore secrets/www.p12 \
  --password inc0rrect \
  --key secrets/www.key \
  --cert secrets/www.crt \
  --ca-cert secrets/ca.crt 

key secrets/ca.key
key secrets/www.key

cert secrets/ca.crt
cert secrets/www.crt

echo
echo "--- keystore www.p12 --------------"
openssl pkcs12 -nokeys -info -noout -in secrets/www.p12 -passin pass:inc0rrect

echo
keytool -list -keystore secrets/www.p12 -storepass inc0rrect
