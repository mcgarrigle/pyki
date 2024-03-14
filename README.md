# pyki


```
./pyki ca --dn 'O=MAC, CN=CA' \
  --ca-cert secrets/ca.crt \
  --ca-key secrets/ca.key

./pyki cert --dn 'CN=X' \
  --cert secrets/x.crt \
  --key secrets/x.key \
  --ca-cert secrets/ca.crt \
  --ca-key secrets/ca.key \
  --san 'IP:10.0.0.1' 'DNS:x.com' 'DNS:y.com'
```
