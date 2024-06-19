# Tng

## Build Docker Image

To get tng ready you need to git clone all of the three repos (`rats-rs`, `tng-envoy`, `tng`)

1. build rats-rs with docker

```sh
cd rats-rs
git submodule update --init --recursive
docker build --tag rats-rs:builder-c-api --target builder-c-api .
```

2. build envoy with docker

```sh
cd tng-envoy
docker build -t tng-envoy:latest --target envoy -f tng/Dockerfile .
```

3. build envoy with docker

```sh
cd tng
docker build -t tng:latest --target release -f Dockerfile .
```

## Example

- tng client as verifier and tng server as attester:

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


- tng client as attester and tng server as verifier:

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
        "aa_addr": "unix:///tmp/attestation.sock"
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
        "as_addr": "http://127.0.0.1:50004/",
        "policy_ids": [
          "default"
        ]
      }
    }
  ]
}
'
```



- both tng client and tng server are attester and verifier:

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
        "aa_addr": "unix:///tmp/attestation.sock"
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
      },
      "verify": {
        "as_addr": "http://127.0.0.1:50004/",
        "policy_ids": [
          "default"
        ]
      }
    }
  ]
}
'
```


- tng client as verifier and tng server as attester, while tng server is using `netfilter` mode instead of `mapping` mode :

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
          "port": 30001
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
      "netfilter": {
        "capture_dst": {
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

tng will generate iptables rules like the following, before running envoy:

```sh
iptables -t nat -N TNG_ENGRESS
iptables -t nat -A TNG_ENGRESS -p tcp -m mark --mark 565 -j RETURN
iptables -t nat -A TNG_ENGRESS -p tcp --dport 30001 -j REDIRECT --to-ports 30000
# Or with specific dst ip address if capture_dst.host is provided in tng config file:
# iptables -t nat -A TNG_ENGRESS -p tcp --dst 127.0.0.1/32 --dport 30001 -j REDIRECT --to-ports 30000
iptables -t nat -A PREROUTING -p tcp -j TNG_ENGRESS
iptables -t nat -A OUTPUT -p tcp -j TNG_ENGRESS ;
```


- Generate dummy TLS cert used by TNG, which is used as a fallback cert when the tng server is not an attester.

```sh
openssl ecparam -out ./src/confgen/serverkey.pem -name secp256r1 -genkey
openssl req -new -key ./src/confgen/serverkey.pem -x509 -nodes -days 365000 -subj "/CN=TNG Dummy Cert,O=Inclavare Containers" -out ./src/confgen/servercert.pem
```


- You may need to switch to iptanles-nft if you are using a newer kernel where iptables-legacy not work

```sh
update-alternatives --set iptables /usr/sbin/iptables-nft
```