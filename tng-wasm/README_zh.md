# TNG Client JavaScript SDK

## 说明

TNG Client JavaScript SDK为浏览器环境提供客户端功能，使用wasm-pack构建。

## 获取 SDK

您可以通过两种方式获取 TNG SDK：

### 1. 从 GitHub Packages 下载

直接从 GitHub Packages 页面下载预编译的 npm 包：
[https://github.com/inclavare-containers/TNG/pkgs/npm/tng](https://github.com/inclavare-containers/TNG/pkgs/npm/tng)

### 2. 从源码构建

#### Docker 环境准备

```sh
docker run -it --name tng-dev --privileged --network=host alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest bash
```

上述命令将基于 Alibaba Cloud Linux 发行版，创建一个名为 tng-dev 的容器，该容器将作为 TNG 的开发环境。我们将在该容器中继续后面的步骤。

安装依赖：

```sh
yum install -y git make clang protobuf-devel npm
```

#### 拉取源码

```sh
cd /
git clone https://github.com/inclavare-containers/tng.git
cd tng
git submodule update --init
```

现在，你已经在`/tng`目录中拥有了 tng 仓库源码。

#### 安装 rust 工具链

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

#### 构建 TNG SDK 的 npm 包

```sh
make wasm-pack-debug
```

> [!NOTE]
> 如果希望构建最终生产版本，请使用`make wasm-pack-release`

产物`tar.gz`文件将存放在`./tng-wasm/pkg/`目录下，您可以将其使用`npm install`安装到您的 web 项目中。

## 在您的项目中使用 SDK

### 安装 SDK 到您的项目

```bash
npm install tng-<version>.tgz
```

### 在您的 HTML 中集成 SDK

将以下代码添加到您的 HTML 页面中以使用 TNG SDK：

```html
<!DOCTYPE html>
<html>
  <head> </head>
  <body>
    <!-- Your page content -->

    <script type="module">
      import tng_init, { fetch as tng_fetch } from "tng_wasm.js";

      // Initialize the TNG WASM module
      await tng_init();

      // Configure attestation parameters
      const asAddr = "http://127.0.0.1:8080/";
      const policyIds = ["default"];

      // Create a wrapped fetch function
      const attested_fetch = (input, init) => {
        const tng_config = {
          ohttp: {},
          verify: {
            model: "background_check",
            as_addr: asAddr,
            policy_ids: policyIds,
          },
        };
        return tng_fetch(input, init, tng_config);
      };

      // Send a request using the wrapped fetch function
      attested_fetch("http://127.0.0.1:30001/foo/bar?baz=qux", {
        method: "GET",
        headers: {},
      })
        .then((response) => {
          const attest_info = response?.attest_info
            ? response.attest_info
            : null;
          console.log("Attest Info:", attest_info);
          // Access remote attestation report information

          console.log("Got response:", response);
          // Process response
        })
        .catch((error) => {
          console.error("Error:", error);
          // Handle errors
        });
    </script>
  </body>
</html>
```

主要步骤包括：

1. 在 HTML 头部添加必要的安全策略元标签
2. 导入并初始化 TNG WASM 模块
3. 配置证明服务地址和策略 ID
4. 使用封装的 `tng_fetch` 函数发送加密请求

### 部署配置

#### 在网页中使用

由于 TNG SDK 使用了 Web Workers，在生产部署时，您需要为网页的 HTTP 响应添加 `Cross-Origin-Opener-Policy:same-origin` 和 `Cross-Origin-Embedder-Policy:require-corp` 这两个 HTTP 头，否则将无法正常工作。

> [!NOTE]
> 由于构建产生的`.wasm`文件通常比较大，我们建议您在部署页面时开启gzip压缩，以减少传输大小，这大约能减少50%的体积。

#### 在 Chrome 扩展中使用

如果您希望在 Chrome 扩展中集成，由于 manifest v3 的限制，您需要在清单中添加一些额外内容。

1. 修改 `manifest.json` 文件中的 `background` 配置项，将 `type` 配置项设置为 `"module"`。

```json
  "background": {
    "service_worker": "background.js",
    "type": "module"
  }
```

2. 修改 `manifest.json` 文件中的 `content_security_policy` 配置项为以下内容：

```json
  "content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
  }
```

## 运行示例代码

pkg 目录中包含一个使用 TNG SDK 发送加密请求的示例程序，该示例需要一个机密计算服务器实例，以及一台本地计算机，下面介绍如何运行该示例

### 1. 准备 server 端服务

使用[dummyhttp](https://github.com/svenstaro/dummyhttp)这个简单的 http server 程序模拟我们的后端服务，我们需要安装并运行它

安装

```sh
cargo install dummyhttp
```

运行这个 http server，并使其监听在 30001 端口，现在我们拥有了一个监听在 30001 端口上的后端 http 服务

```sh
dummyhttp -p 30001 -vvvv
```

> [!NOTE]
> 您可以使用 curl 命令在本地计算机中测试直接访问这个 http server，以检查网络联通性

### 2. 编译并安装服务端侧的 TNG

构建 rpm 包

```sh
make create-tarball
make rpm-build
```

产物将存放在`~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm`，您可以使用如下方式安装

```sh
yum install ~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm -y
```

如果你希望构建容器版本的 tng

```sh
# 首先安装podman
yum install podman podman-docker -y
# 构建容器镜像
docker build -t tng:test .
```

将产生名为`tng:test`容器镜像。

### 3. 在服务端侧运行 Attestation-Agent

您可以选择从 yum 源安装 attestation-agent，或者编译部署自己的 attestation-agent

```sh
yum install -y attestation-agent
```

运行

```sh
RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock
```

### 4. 在服务端侧运行 TNG

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
                "ohttp": {},
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        ]
    }'
```

> [!NOTE]
>
> - 目前 TNG SDK 仅支持对服务端进行验证，因此您必须提供`"attest"`选项
> - 如上所示，您需要在 TNG 配置中添加一项`"ohttp": {}`，以开启使用 OHTTP 作为加密协议（而不是 rats-tls）中进行双向加密流量的传输。

### 5. 运行 Attestation Service 实例

您需要准备一个暴露 Restful HTTP 接口的 Attestation Service 实例，这可以通过安装 yum 源中的`trustee`包或者编译部署自己的`restful-as`来实现。

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
podman run -it --rm --net=host docker.io/bulletmark/corsproxy:latest 8080=http://127.0.0.1:9080
```

以上将在 8080 端口暴露一个 Attestation Service 服务。

> [!NOTE]
> 由于 TNG SDK 需要在浏览器中向 Attestation Service 实例发起请求，因此请确保您处理好跨域(CORS)规则。

以下是一个示例：

### 6. 编译 TNG SDK

```sh
make wasm-build-debug
```

这将在`tng-wasm/pkg/`目录中产生对应的`.wasm`和`.js`文件

### 7. 修改前端页面中的代码

请按需修改[index.html](pkg/index.html)中的如下内容

访问的后端服务的 URL：

```js
const url = "http://127.0.0.1:30001/foo/bar?baz=qux";
```

验证用的 Attestation Service 的 URL 及 policy id：

```js
const asAddr = "http://127.0.0.1:8080/";
const policyIds = ["default"];
```

### 8. 在服务端侧运行前端服务

首先安装 miniserve

```sh
cargo +nightly-2025-07-07 install miniserve
```

运行 miniserve

```sh
miniserve ./tng-wasm/pkg --index index.html --header "Cross-Origin-Opener-Policy:same-origin" --header "Cross-Origin-Embedder-Policy:require-corp" --port 8082
```

> [!NOTE]
>
> - [`miniserve`](https://github.com/svenstaro/miniserve)是一个纯粹的静态资源服务器，它和 Nginx 以及 python 的 http.server 没有什么差别，你也可以用其它组件来替代。

### 9. 从浏览器访问

在本地计算机中打开浏览器，访问`http://<机密计算服务实例ip>:8082/`，您可以在 F12 中查看请求响应的日志

