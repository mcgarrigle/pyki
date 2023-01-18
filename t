#!/bin/bash -e

cert() {
  echo
  echo "--- $1 --------------"
  openssl x509  -noout -issuer -subject -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName -in $1
}

rm -f *.key *.crt

./pyki ca --dn 'C=UK, S=Wales, O=Mac, CN=CA' \
  --ca-cert ca.crt \
  --ca-key  ca.key

./pyki cert --dn 'C=UK, S=Wales, O=Mac, CN=www' \
  --cert www.crt \
  --key  www.key \
  --ca-cert ca.crt \
  --ca-key  ca.key \
  --san 'DNS:mac.wales' 'DNS:www.mac.wales' 'IP:192.168.0.1'

./pyki pkcs12 --key www.key --cert www.crt \
  --ca-certs ca.crt \
  -s www.p12 \
  --password inc0rrect

cert ca.crt
cert www.crt

echo
echo "--- keystore www.p12 --------------"
openssl pkcs12 -nokeys -info -in www.p12 -passin pass:inc0rrect

echo
keytool -list -keystore www.p12 -storepass inc0rrect
