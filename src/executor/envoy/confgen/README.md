
If you want, using the following script to refresh the dummy TLS cert used by TNG, which is used as a fallback cert when the tng server is not an attester.

```sh
openssl ecparam -out ./serverkey.pem -name secp256r1 -genkey
openssl req -new -key ./serverkey.pem -x509 -nodes -days 365000 -subj "/CN=TNG Dummy Cert,O=Inclavare Containers" -out ./servercert.pem
```
