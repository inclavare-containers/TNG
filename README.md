# Tng

## Build Docker Image

To get tng ready you need to git clone all of the three repos (`rats-rs`, `tng-envoy`, `tng`)

1. build rats-rs with docker

```sh
cd rats-rs
git submodule update --init --recursive
docker build --tag rats-rs:builder-c-api --target builder-c-api-coco-only .
```

2. build envoy with docker

```sh
cd tng-envoy
docker build -t tng-envoy:latest --target envoy -f tng/Dockerfile .
```

3. build tng with docker

```sh
cd tng
docker build -t tng:latest --target release -f Dockerfile .
```

4. (optional) push docker image to ACR

```sh
docker tag tng:latest registry.cn-hangzhou.aliyuncs.com/lxx/tng:latest
docker push registry.cn-hangzhou.aliyuncs.com/lxx/tng:latest
```

## Create tarball

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

To use the tng binary, you also need to install some dependencies. For ubuntu20.04:

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
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": [
          "default"
        ]
      }
    }
  ]
}
```

#### http_proxy代理方式（http_proxy）

在该场景中，tng监听一个本地http proxy端口，用户容器可通过设置`http_proxy`环境变量（或在业务代码中发送请求时特地设置`http_proxy`代理），将流量走代理到tng client监听的端口，后者负责将所有用户tcp请求加密后发送到原目标地址。因此用户的client程序无需修改其tcp请求的目标。


```json
{
  "add_ingress": [
    {
      "http_proxy": {
        "proxy_listen": {
          "host": "0.0.0.0",  // 可选，默认为0.0.0.0
          "port": 41000
        },
        "dst_filter": {
          "domain": "*.pai-eas.aliyuncs.com", // 可选，默认为 "*"
          "port": 80 // 可选，默认为 80
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
```

- `proxy_listen`指定了tng暴露的`http_proxy`协议监听端口的监听地址(`host`)和端口(`port`)值。
- `dst_filter`指定了一个过滤规则，指示需要被tng隧道保护的目标域名（或ip）和端口的组合。除了被该过滤规则匹配的流量外，其余流量将不会进入tng隧道，而是以明文形式转发出去（这样能够确保不需要保护的普通流量请求正常发出
- `dst_filter`的`domain`字段并不支持正则表达式，但是支持部分类型的通配符（*）。具体语法，请参考envoy文档中`config.route.v3.VirtualHost`类型的`domains`字段的[表述文档](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost)


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
          "host": "127.0.0.1",  // 可选，若不填，则默认匹配本机上所有端口的本地ip地址（见iptables的 -m addrtype --dst-type LOCAL 选项：https://ipset.netfilter.org/iptables-extensions.man.html）
          "port": 30001
        },
        "capture_local_traffic": false, // 可选（默认为false），若值为false则在捕获时会忽略源ip为本机ip的请求，不会将它们重定向到listen_port。若值为true，则会连带捕获源ip为本机ip到请求。
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
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": [
          "default"
        ]
      }
```

`as_addr`默认是AS的Restful HTTP地址，但也支持通过`as_is_grpc`选项来使用Grpc地址，例如：

```json
      "verify": {
        "as_addr": "http://127.0.0.1:5000/",
        "as_is_grpc": true,
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

### 伪装成七层流量

在一些业务场景中，app client和app server之间采用http的方式通信，且链路中可能经过如nginx反向代理、7层负载均衡SLB之类的中间组件，这些中间组件无法通过tng的rats-tls流量。为了在业务中以尽可能少的负担接入tng，需要将tng的rats-tls流量伪装成七层http流量。

鉴于这些中间组件的特性，tng在伪装成http流量后通常需要保留原始流量的一些字段，以便路由、负载均衡等功能正常运作。但出于数据机密性的考虑，伪装后http流量中的字段不应该包含敏感信息。因此，tng提供了一些规则来配置伪装后http流量的字段：
1. 伪装后http流量的请求method统一为`POST`
2. 伪装后http流量的请求路径path默认为`/`，也可以通过指定`path_rewrites`字段，根据内层被保护的业务http请求的path以正则表达式的方式重写出伪装后http流量的path。
3. 伪装后http流量的Host（或者`:authority`）和内层被保护的业务http请求保持一致。
4. 伪装后http流量将带有一个名为`tng`的请求头，可用于区分普通流量和伪装后流量。同时原业务流量中的请求头将被隐去。

> [!WARNING]  
> 当前的tng实现，在配置「伪装成七层流量」特性时，要求内层被保护的业务必须是http流量，而不能是普通的tcp流量。

#### 入站侧流量的伪装

可通过在`add_ingress`对象中指定的`encap_in_http`字段来开启伪装能力。如未指定`encap_in_http`则不会开启伪装能力。

示例如下：

```json
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
  ]
}
```

其中，`path_rewrites`字段是一个列表，其中指定了以正则表达式的方式进行流量path重写的参数。例如，指定

```json
        "path_rewrites": [
          {
            "match_regex": "^/api/predict/([^/]+)([/]?.*)$",
            "substitution": "/api/predict/\\1"
          }
        ]
```
表示将path能够匹配上`"^/api/predict/([^/]+)([/]?.*)$"`的内层http请求，对应的伪装后http流量的path被重写为`"/api/predict/\\1"`。注意这里支持`\数字`的方式来引用正则匹配到的group。

所有的重写将按照在`path_rewrites`列表中的顺序进行，且只会匹配上列表中的一项。对于未能匹配任何`path_rewrites`列表成员的请求，将默认设置伪装后http流量的path为`/`

#### 出站侧流量的伪装

与入站侧的配置对应，出站侧可通过在`add_egress`对象中指定`decap_from_http`字段来开启对已伪装流量的拆解，例如。
```json
      "decap_from_http": {},
```

如不指定`decap_from_http`字段则不开启。

此外，还可通过配置`allow_non_tng_traffic_regexes`子项，除了允许tng加密流量传入端点，还将允许非加密http请求流量传入，这可以满足一些同时需要两种流量的场景（如healthcheck）。该子项的值为一个json字符串列表，其中的每项是一个正则表达式匹配语句，只有http请求PATH与该正则语句完全匹配的非加密http请求流量，才会被TNG放行。子项的默认值为`[]`，即拒绝任何非加密http请求。

示例如下：

```json
{
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
      "decap_from_http": {
        "allow_non_tng_traffic_regexes": ["/api/builtin/.*"]
      },
      "attest": {
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
```

### 网页注入

有些场景中希望让浏览器用户强感知到远程证明的存在，可使用ingress的`web_page_inject`选项在网页流量中注入一个顶栏，显示当前页面的远程证明信息。

> 注意该功能目前仅支持开启了「伪装成七层流量」的ingress

例如：
```json
{
  "add_ingress": [
    {
      ...
      "encap_in_http": {
        ...
      },
      "web_page_inject": true
      ...
    }
  ]
}
```

### Envoy Admin Interface

可使用`admin_bind`选项开启envoy实例的[admin interface](https://www.envoyproxy.io/docs/envoy/latest/operations/admin)。在未指定该选项时默认不开启。请不要在生产环境中使用该选项。

例如：

```json
  "admin_bind": {
    "host": "0.0.0.0",
    "port": 9901
  },
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
        "dst_filter": {
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
        "dst_filter": {
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
        "dst_filter": {
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