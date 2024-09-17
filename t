#!/bin/bash -e

header() {
  echo
  echo "--- $1 --------------"
}

key() {
  header "key $1"
  openssl rsa -in $1 -text -noout |grep Private
}

cert() {
  header "certificate $1"
  openssl x509 -noout -issuer -subject -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName -startdate -enddate -in $1
}

rm -f secrets/*.{key,crt,p12}

./pyki ca \
  --dn 'C=UK, S=Wales, O=Mac, CN=CA' \
  --ca-cert secrets/ca.crt \
  --ca-key  secrets/ca.key

# python3 -m trace --trace ./pyki cert \
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

header "verify www.crt"
openssl verify -verbose -CAfile secrets/ca.crt secrets/www.crt
exit

echo
header "keystore www.p12"
openssl pkcs12 -nokeys -info -noout -in secrets/www.p12 -passin pass:inc0rrect

echo
keytool -list -keystore secrets/www.p12 -storepass inc0rrect
