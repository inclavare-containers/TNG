# Tng


Example:

```sh
cargo run launch --config-content='
{
  "add_ingress": [
    {
      "mapping": {
        "in": {
          "port": 10001
        },
        "out": {
          "host": "127.0.0.1",
          "port": 20001
        }
      },
      "verify": {
        "as_addr": "http://127.0.0.1:50004/",
        "policy_ids": [
          "default"
        ]
      }
    }
  ],
  "add_egress": [
    {
      "mapping": {
        "in": {
          "host": "127.0.0.1",
          "port": 20001
        },
        "out": {
          "host": "127.0.0.1",
          "port": 30001
        }
      },
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
'
```

```sh
openssl ecparam -out ./src/confgen/serverkey.pem -name secp256r1 -genkey
openssl req -new -key ./src/confgen/serverkey.pem -x509 -nodes -days 365000 -subj "/CN=TNG Dummy Cert,O=Inclavare Containers" -out ./src/confgen/servercert.pem
```
