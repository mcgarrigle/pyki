# pyki


```
 ./pyki ca --dn 'O=MAC, CN=CA' --ca-cert ca.crt --ca-key ca.key
 ./pyki cert --dn 'CN=X' --cert x.crt --key x.key --ca-cert ca.crt --ca-key ca.key --san 'DNS:x.com' 'DNS:y.com'
```
