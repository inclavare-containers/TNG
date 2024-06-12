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
      "attest": {
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
      "verify": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
'

```
