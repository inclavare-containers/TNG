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

## 参数手册

### 流量入站到tng隧道

在`add_ingress`数组中添加tng隧道的入口端点（ingress），根据client侧用户场景，可以选择对应的流量入站方式。

#### 端口映射方式（mapping）

在该场景中，tng监听一个本地tcp端口（`in.host`, `in.port`），将所有tcp请求加密后发送到指定tcp端点（`out.host`, `out.port`）。因此用户的client程序需要改变其tcp请求的目标到（`in.host`, `in.port`）上。

```json
{
  "add_ingress": [
    {
      "mapping": {
        "in": {
          "host": "0.0.0.0",  // 可选，默认为0.0.0.0
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
  ]
}
```

#### http_proxy代理方式（http-proxy）

在该场景中，tng监听一个本地http proxy端口，用户容器通过设置`http_proxy`环境变量，将流量走代理到tng client监听的端口，后者负责将所有用户tcp请求加密后发送到原目标地址。因此用户的client程序无需修改其tcp请求的目标。

> 实现中

#### 透明代理方式（netfilter）

在该场景中，tng监听一个本地tcp端口，并通过配置iptables规则，将用户流量转发到tng client监听的该端口。后者负责将所有用户tcp请求加密后发送到原目标地址。因此用户的client程序无需修改其tcp请求的目标。

> 实现中

### 流量从tng隧道出站

在`add_egress`数组中添加tng隧道的出口端点（egress），根据server侧用户场景，可以选择对应的流量出站方式。

#### 端口映射方式（mapping）

在该场景中，tng监听一个本地tcp端口（`in.host`, `in.port`），将所有tcp请求解密后发送到指定tcp端点（`out.host`, `out.port`）。用户的server程序需要改变其tcp监听端口监听在（`in.host`, `in.port`）上。

```json
{
  "add_egress": [
    {
      "mapping": {
        "in": {
          "host": "127.0.0.1",  // 可选，默认为0.0.0.0
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
```

#### 端口劫持方式（netfilter）

在该场景中，用户的server程序已监听在本机某一端口，且因业务原因不便变更端口号或为tng server新增开放端口。为了让tng server能够解密发往server程序端口（`capture_dst.host`, `capture_dst.port`）上的TCP流量，需要结合内核netfilter提供的能力，将流量重定向到tng server监听的`listen_port`上。tng server在解密完流量后，将TCP流量按照原先的目标（`capture_dst.host`, `capture_dst.port`）发出

```json
{
  "add_egress": [
    {
      "netfilter": {
        "capture_dst": {
          "host": "127.0.0.1",  // 可选，若不填则过滤时忽略tcp请求的目标ip
          "port": 30001
        },
        "listen_port": 40000,   // 可选，tng server监听的端口号，用于接收由netfilter重定向的流量。默认从40000端口开始递增取值。
        "so_mark": 565          // 可选，tng server解密后，承载明文流量的TCP请求对应socket的SO_MARK标记值，用于避免解密后的流量流量再次被netfilter转发到tng server。默认值为565
      },
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
```

### 远程证明选项

不论是`add_ingress`还是`add_egress`选项，都可以指定`verify`和`attest`或者`no_ra`参数，表示在隧道端点上的远程证明相关配置。

#### 配置示例

- `attest`：表示在该隧道端点上，tng扮演Attester角色，目前只支持通过AA获取evidence。

```json
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
```

- `verify`：表示在该隧道端点上，tng扮演Verifier角色，目前只支持通过AS消费和验证对端发来的evidence

```json
      "verify": {
        "as_addr": "http://127.0.0.1:50004/",
        "policy_ids": [
          "default"
        ]
      }
```

- `no_ra`：表示在该隧道端点上，tng用普通的X.509证书进行通信，而不触发远程证明流程。请注意该证书为tng代码中内嵌的一个固定的P256 X509自签名证书，不具有机密性，因此**该选项仅作调试用途，不应被用于生产环境**。

```json
      "no_ra": true
```


#### 组合与双向远程证明

通过在隧道两端（包括ingress和egress）上配置不同的`attest`和`verify`属性组合，可以实现灵活的信任模型

|远程证明场景|tng client配置|tng server配置|说明|
|---|---|---|---|
|单向|`verify`|`attest`|最常见场景，tng server在TEE中，tng client在普通环境|
|双向|`attest`、`verify`|`attest`、`verify`|tng server和tng client在两个不同TEE中|
|（逆）单向|`attest`|`verify`|tng server在普通环境，tng client在TEE中。此时等于只验证client证书，在tls握手中，tng server会用tng代码中内嵌的一个固定的P256 X509自签名证书来作为自己的证书|
|无TEE（仅作调试用途）|`no_ra`|`no_ra`|tng server和tng client都在非TEE环境中，此时tng client和tng server之间通过单向验证建立普通的TLS会话|

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

- Generate dummy TLS cert used by TNG, which is used as a fallback cert when the tng server is not an attester.

```sh
openssl ecparam -out ./src/confgen/serverkey.pem -name secp256r1 -genkey
openssl req -new -key ./src/confgen/serverkey.pem -x509 -nodes -days 365000 -subj "/CN=TNG Dummy Cert,O=Inclavare Containers" -out ./src/confgen/servercert.pem
```


- You may need to switch to iptanles-nft if you are using a newer kernel where iptables-legacy not work

```sh
update-alternatives --set iptables /usr/sbin/iptables-nft
```