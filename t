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
  --cert x.crt \
  --key  x.key \
  --ca-cert ca.crt \
  --ca-key  ca.key \
  --san 'DNS:mac.wales' 'DNS:www.mac.wales' 'IP:192.168.0.1'

cert ca.crt
cert x.crt
