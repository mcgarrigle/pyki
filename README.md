# pyki


```
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
```
