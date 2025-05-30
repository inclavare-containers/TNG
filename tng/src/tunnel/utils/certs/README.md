# Dummy TLS cert

The x509 cert and key files in this directory are only used when no authentication is needed. This depends on the `verify`, `attest` and `no_ra` fields in your configuration.


You can using the following script to refresh the dummy TLS cert used by TNG, which is used as a fallback cert when the tng server is not an attester.

```sh
openssl ecparam -out ./serverkey.pem -name secp256r1 -genkey
openssl req -new -key ./serverkey.pem -x509 -nodes -days 365000 -subj "/CN=TNG Dummy Cert,O=Inclavare Containers" -out ./servercert.pem
```
