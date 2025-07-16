# TNG Client JavaScript SDK

## 说明

提供，SDK使用wasm-pack进行构建

浏览器环境使用的


## 构建npm包


1. Docker环境准备

```sh
docker run -it --name tng-dev --privileged --network=host alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest bash
```
上述命令将基于Alibaba Cloud Linux发行版，创建一个名为tng-dev的容器，该容器将作为TNG的开发环境。我们将在该容器中继续后面的步骤。

安装依赖：
```sh
yum install -y git make clang protobuf-compiler npm rsync
```

2. 拉取源码

```sh
cd /
git clone https://github.com/inclavare-containers/tng.git --branch wasm
cd tng
git submodule update --init
```

现在，你已经在`/tng`目录中拥有了tng仓库源码。

3. 安装rust工具链

```sh
cat <<EOF >> ~/.bashrc
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
EOF

. ~/.bashrc

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

mkdir -p ~/.cargo/
cat <<EOF > ~/.cargo/config.toml
[source.crates-io]
replace-with = 'ustc'

[source.ustc]
registry = "git://mirrors.ustc.edu.cn/crates.io-index"
EOF

. "$HOME/.cargo/env"
```

4. 构建TNG SDK的npm包

```sh
make wasm-pack-debug
```

> [!NOTE]
> 如果希望构建最终生产版本，请使用`make wasm-pack-release`

产物`tar.gz`文件将存放在`./tng-wasm/pkg/`目录下，您可以将其使用`npm install`安装到您的web项目中。

## 运行Demo

pkg目录中包含一个使用TNG SDK发送加密请求的示例程序，该示例需要一个机密计算服务器实例，以及一台本地计算机，下面介绍如何运行该示例

1. 准备server端服务

使用[dummyhttp](https://github.com/svenstaro/dummyhttp)这个简单的http server程序模拟我们的后端服务，我们需要安装并运行它

安装

```sh
cargo install dummyhttp
```

运行这个http server，并使其监听在30001端口，现在我们拥有了一个监听在30001端口上的后端http服务

```sh
dummyhttp -p 30001 -vvvv
```

> [!NOTE]
> 您可以使用curl 命令在本地计算机中测试直接访问这个http server，以检查网络联通性

2. 编译并安装服务端侧的TNG

构建rpm包

```sh
make create-tarball
make rpm-build
```
产物将存放在`~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm`，您可以使用如下方式安装

```sh
yum install ~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm -y
```

如果你希望构建容器版本的tng

```sh
# 首先安装podman
yum install podman podman-docker -y
# 构建容器镜像
docker build -t tng:test .
```

将产生名为`tng:test`容器镜像。

3. 在服务端侧运行Attestation-Agent

您可以选择从yum源安装attestation-agent，或者编译部署自己的attestation-agent

```sh
yum install -y attestation-agent
```

运行

```sh
RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock
```

4. 在服务端侧运行TNG

```sh
tng launch --config-content='
    {
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
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        ]
    }'
```

> [!NOTE]
> - 目前TNG SDK仅支持对服务端进行验证，因此您必须提供`"attest"`选项
> - 如上所示，您需要在TNG配置中添加一项`"decap_from_http": {}`，以开启在WebSocket流（而不是普通TCP流）中进行双向加密流量的传输。

该规则

5. 运行Attestation Service实例

您需要准备一个暴露Restful HTTP接口的Attestation Service实例，这可以通过安装yum源中的`trustee`包或者编译部署自己的`restful-as`来实现。

一个参考的运行命令如下：
```sh
cat <<EOF > /tmp/config_with_cert.json
{
    "work_dir": "/var/lib/attestation-service/",
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "LocalFs"
        }
    },
    "attestation_token_broker": {
        "type": "Simple",
        "duration_min": 5
    }
}
EOF

RUST_LOG=debug restful-as --socket 0.0.0.0:9080 --config-file /tmp/config_with_cert.json

# 由于restful-as原生并不支持配置跨域规则，这里运行一个跨域代理服务（https://github.com/bulletmark/corsproxy），从8080端口转发请求到真正的Attestation Service。
podman run -it --rm --net=host docker.1ms.run/bulletmark/corsproxy:latest 8080=http://127.0.0.1:9080
```

以上将在8080端口暴露一个Attestation Service服务。

> [!NOTE]
> 由于TNG SDK需要在浏览器中向Attestation Service实例发起请求，因此请确保您处理好跨域(CORS)规则。

以下是一个示例：


6. 编译TNG SDK

```sh
make wasm-build-debug
```

这将在`tng-wasm/pkg/`目录中产生对应的`.wasm`和`.js`文件

7. 修改前端页面中的代码

请按需修改[tng-wasm/pkg/index.html](./pkg/index.html)中的如下内容

访问的后端服务的URL：
```js
const url = "http://127.0.0.1:30001/foo/bar?baz=qux";
```

验证用的Attestation Service的URL及policy id：
```js
const asAddr = "http://127.0.0.1:8080/";
const policyIds = ["default"];
```

8. 在服务端侧运行前端服务

首先安装miniserve

```sh
cargo +nightly-2025-07-07 install miniserve
```

运行miniserve

```sh
miniserve ./tng-wasm/pkg --index index.html --header "Cross-Origin-Opener-Policy:same-origin" --header "Cross-Origin-Embedder-Policy:require-corp" --port 8082
```

> [!NOTE]
> - [`miniserve`](https://github.com/svenstaro/miniserve)是一个纯粹的静态资源服务器，它和Nginx以及python的http.server没有什么差别，你也可以用其它组件来替代。
> - 由于TNG SDK使用了Web Worker，在生产部署时，您需要为Web页面的HTTP响应添加`Cross-Origin-Opener-Policy:same-origin`和`Cross-Origin-Embedder-Policy:require-corp`这两个HTTP头，否则将无法正常工作。如果您希望在chrome extension中集成，请在manifest清单中添加[cross_origin_embedder_policy](https://developer.chrome.com/docs/extensions/reference/manifest/cross-origin-embedder-policy)和[cross_origin_opener_policy](https://developer.chrome.com/docs/extensions/reference/manifest/cross-origin-opener-policy)这两个manifest key。

9. 在本地计算机中打开浏览器，访问`http://<机密计算服务实例ip>:8082/`，您可以在F12中查看请求响应的日志

