# TNG

## What is TNG?

TNG (Trust Network Gateway) 是一个用于建立安全通信隧道的工具，支持多种流量入站和出站方式，并且能够提供基于远程证明（Remote Attestation）的安全会话能力。通过配置不同的入口（Ingress）和出口（Egress）端点，用户可以在无需修改已有应用程序的同时，根据自己的需求灵活地控制流量的加密和解密过程。


## Usage

The simplest way to launch a TNG instance is the `launch` subcommand. Here is the usage:

```txt
Usage: tng launch [OPTIONS]

Options:
  -c, --config-file <CONFIG_FILE>
      --config-content <CONFIG_CONTENT>
  -h, --help                             Print help
```

You should provide a JSON config file, or provide configuration content in JSON directly from the command line arguments, which will be used to configure the TNG instance.

Check the [reference document](docs/configuration.md) for the configuration. 

## Build

### Build and run with the docker image

It is recommend to build TNG with docker. Here are the steps.

1. Pull the code

2. Pull the dependencies

```sh
cd tng
git submodule update --init
```

3. Build with docker

```sh
docker build -t tng:latest --target tng-release -f Dockerfile .
```

Now we have got the docker image `tng:latest`.

4. Run tng

```sh
docker run -it --rm --network host tng:latest tng launch --config-content='<your config json string>'
```


### Create a TNG tarball

1. First you should build `tng:latest` docker image with the steps above.

2. Then run the script to package a tarball

```sh
./pack-sdk.sh
```

The tarball will be generated with name `tng-<version>.tar.gz`

3. To install the tarball in a new environment

```sh
tar -xvf tng-*.tar.gz -C /
```

To run the tng binary, you also need to install some dependencies. For ubuntu20.04:

```
apt-get install -y libssl1.1 iptables
```

4. Run tng

```sh
/opt/tng-0.1.0/bin/tng launch --config-content='<your config json string>'
```


5. To uninstall it, just remove the dir

```sh
rm -rf /opt/tng-*
```


## Example

For simplicity, in the following examples, the running tng instance serves as both the tng client and the tng server.

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
        "as_addr": "http://127.0.0.1:8080/",
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
        "as_addr": "http://127.0.0.1:8080/",
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
        "as_addr": "http://127.0.0.1:8080/",
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
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": [
          "default"
        ]
      }
    }
  ]
}
'
```


- tng client as verifier and tng server as attester, while tng server is using `netfilter` mode instead of `mapping` mode:

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
        "as_addr": "http://127.0.0.1:8080/",
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
        },
        "capture_local_traffic": true
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
iptables -t nat -A TNG_ENGRESS -p tcp -m addrtype --dst-type LOCAL --dport 30001 -j REDIRECT --to-ports 30000
# Or with specific dst ip address if capture_dst.host is provided in tng config file:
# iptables -t nat -A TNG_ENGRESS -p tcp --dst 127.0.0.1/32 --dport 30001 -j REDIRECT --to-ports 30000
iptables -t nat -A PREROUTING -p tcp -j TNG_ENGRESS
iptables -t nat -A OUTPUT -p tcp -j TNG_ENGRESS ;
```


- both tng client and tng server are in non-tee env:

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
      "no_ra": true
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
      "no_ra": true
    }
  ]
}
'
```

- tng client as verifier and tng server as attester, with "HTTP encapulation" enabled.

```sh
cargo run launch --config-content='
{
  "add_ingress": [
    {
      "mapping": {
        "in": {
          "host": "0.0.0.0",
          "port": 10001
        },
        "out": {
          "host": "127.0.0.1",
          "port": 20001
        }
      },
      "encap_in_http": {
        "path_rewrites": [
          {
            "match_regex": "^/api/predict/([^/]+)([/]?.*)$",
            "substitution": "/api/predict/\\1"
          }
        ]
      },
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
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
      "decap_from_http": {},
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
'
```

You may test it by launch a python http server and connect it with curl via tng:

```sh
python3 -m http.server 30001
```

```sh
curl --connect-to 1242424451954755.vpc.cn-shanghai.pai-eas.aliyuncs.com:80:127.0.0.1:10001 http://1242424451954755.vpc.cn-shanghai.pai-eas.aliyuncs.com:80/api/predict/service_name/foo/bar -vvvv
```

You can use tcpdump to observe the encapsulated HTTP traffic:

```sh
tcpdump -n -vvvvvvvvvv -qns 0 -X -i any tcp port 20001
```

You will see a POST request with `/api/predict/service_name` as path and `tng` as one of the headers.


- tng client as verifier and tng server as attester, with "HTTP encapulation" enabled, while tng server is using `netfilter` mode instead of `mapping` mode:

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
      "encap_in_http": {
        "path_rewrites": [
          {
            "match_regex": "^/api/predict/([^/]+)([/]?.*)$",
            "substitution": "/api/predict/\\1"
          }
        ]
      },
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
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
        },
        "capture_local_traffic": true
      },
      "decap_from_http": {},
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
'
```

- tng client as verifier and tng server as attester, with "HTTP encapulation" enabled and `allow_non_tng_traffic_regexes` set, while tng server is using `netfilter` mode instead of `mapping` mode:

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
      "encap_in_http": {
        "path_rewrites": [
          {
            "match_regex": "^/api/predict/([^/]+)([/]?.*)$",
            "substitution": "/api/predict/\\1"
          }
        ]
      },
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
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
        },
        "capture_local_traffic": true
      },
      "decap_from_http": {
        "allow_non_tng_traffic_regexes": ["/api/builtin/.*"]
      },
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
'
```

To test this, Launch a http server:

```sh
python3 -m http.server 30001
```

First, try to send request via tng client. It should work.

```sh
all_proxy="http://127.0.0.1:41000" curl http://127.0.0.1:30001 -vvvvv
```

Then, try to send non-tng traffic, it should be denied.

```sh
curl http://127.0.0.1:30001 -vvvvv
```

Finally, try to send non-tng traffic which is in the configed `allow_non_tng_traffic_regexes` option.

```sh
# it should not work, since `/api/builtin` not matches `/api/builtin/.*`
curl http://127.0.0.1:30001/api/builtin
# it should work, since `/api/builtin/` matches `/api/builtin/.*`
curl http://127.0.0.1:30001/api/builtin/
# it should work, since `/api/builtin/abc` matches `/api/builtin/.*`
curl http://127.0.0.1:30001/api/builtin/abc
# it should work, since `/api/builtin/abc` matches `/api/builtin/.*`
curl -X POST http://127.0.0.1:30001/api/builtin/abc
```


- tng client as verifier and tng server as attester, with "HTTP encapulation" enabled, while tng server is using `netfilter` mode, and tng client is using `http_proxy` mode:

Here the http_proxy ingress only accept all domain `*` and any port (because `port` is not set).


```sh
cargo run launch --config-content='
{
  "add_ingress": [
    {
      "http_proxy": {
        "proxy_listen": {
          "host": "0.0.0.0",
          "port": 41000
        },
        "dst_filters": {
          "domain": "*",
          "port": 30001
        }
      },
      "encap_in_http": {
        "path_rewrites": [
          {
            "match_regex": "^/api/predict/([^/]+)([/]?.*)$",
            "substitution": "/api/predict/\\1"
          }
        ]
      },
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
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
        },
        "capture_local_traffic": true
      },
      "decap_from_http": {},
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
'
```

To test this case, first setup a http server on 3001 port.

```sh
python3 -m http.server 30001
```

And then, send http request via proxy with `all_proxy` environment variable set.

```sh
all_proxy="http://127.0.0.1:41000" curl http://127.0.0.1:30001 -vvvvv
```

You will see the correct response.

And then, test sending request to target which is not matched by the `dst_filter` filter rule, for example, `http://www.baidu.com` and `https://www.baidu.com`.

```sh
all_proxy="http://127.0.0.1:41000" curl http://www.baidu.com -vvvvv
all_proxy="http://127.0.0.1:41000" curl https://www.baidu.com -vvvvv
```

You can see it also works since tng will not send these request via tng tunnel.


- The cachefs case, where both tng client and tng server are verifier and attester, while tng client is using `http_proxy` mode, and tng server is using `netfilter` mode:

```sh
cargo run launch --config-content='
{
  "add_ingress": [
    {
      "http_proxy": {
        "proxy_listen": {
          "host": "0.0.0.0",
          "port": 41000
        },
        "dst_filters": {
          "domain": "*",
          "port": 9991
        }
      },
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      },
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
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
          "port": 9991
        },
        "capture_local_traffic": true
      },
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      },
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": [
          "default"
        ]
      }
    }
  ]
}
'
```

launch a netcat TCP listener instance to act as a cachefs node

```sh
nc -l -v 9991
```

and launch a netcat client instance to act as another cachefs node, who connects other cachefs nodes (127.0.0.1 9991) via a http_proxy endpoint (127.0.0.1:41000)

```sh
nc -X connect -x 127.0.0.1:41000 -v 127.0.0.1 9991
```

You can take a look at the encrypted rats-tls traffic
```sh
tcpdump -n -vvvvvvvvvv -qns 0 -X -i any tcp port 40000
```
where `40000` is the value of `listen_port` of `add_egress.netfilter`.

- Enable Admin interface of envoy for debugging

```sh
cargo run launch --config-content='
{
  "admin_bind": {
    "host": "0.0.0.0",
    "port": 9901
  },
  "add_ingress": [
    {
      "http_proxy": {
        "proxy_listen": {
          "host": "0.0.0.0",
          "port": 41000
        },
        "dst_filters": {
          "domain": "*",
          "port": 8080
        }
      },
      "encap_in_http": {
        "path_rewrites": [
          {
            "match_regex": "^/api/predict/([^/]+)([/]?.*)$",
            "substitution": "/api/predict/\\1"
          }
        ]
      },
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": [
          "default"
        ]
      }
    }
  ]
}
'
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

## 贡献

欢迎社区贡献，让TNG成为机密计算场景下更好的工具！如果有任何问题或建议，请随时提交 Issue 或 Pull Request。

## 许可证

TODO
