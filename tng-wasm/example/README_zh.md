# 运行静态示例

`tng-wasm/example/` 目录包含一个使用 TNG SDK 发送加密请求的示例页面。该示例需要一个机密计算服务器实例以及一台本地计算机。下面介绍如何运行该示例。

> [!NOTE]
> 示例页面通过 `../pkg/tng_wasm.js` 引用 SDK 构建产物，因此无需手动拷贝文件——只要本地构建过 SDK（产物在 `tng-wasm/pkg/`），直接用静态服务器服务 `tng-wasm/` 根目录即可。

### 1. 准备 server 端服务

使用[dummyhttp](https://github.com/svenstaro/dummyhttp)这个简单的 http server 程序模拟我们的后端服务，我们需要安装并运行它。

安装：

```sh
cargo install dummyhttp --locked
```

运行这个 http server，并使其监听在 30001 端口：

```sh
dummyhttp -p 30001 -vvvv
```

> [!NOTE]
> 您可以使用 curl 命令在本地计算机中测试直接访问这个 http server，以检查网络联通性。

### 2. 编译并安装服务端侧的 TNG

构建 rpm 包：

```sh
make create-tarball
make rpm-build
```

产物将存放在 `~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm`，您可以使用如下方式安装：

```sh
yum install ~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm -y
```

如果你希望构建容器版本的 tng：

```sh
# 首先安装 podman
yum install podman podman-docker -y
# 构建容器镜像
docker build -t tng:test .
```

将产生名为 `tng:test` 的容器镜像。

### 3. 在服务端侧运行 Attestation-Agent

您可以选择从 yum 源安装 attestation-agent，或者编译部署自己的 attestation-agent：

```sh
yum install -y attestation-agent
```

运行：

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
> - 目前 TNG SDK 仅支持对服务端进行验证，因此您必须提供 `"attest"` 选项。
> - 如上所示，您需要在 TNG 配置中添加一项 `"ohttp": {}`，以开启使用 OHTTP 作为加密协议（而不是 rats-tls）来进行双向加密流量的传输。

### 5. 运行 AttestationService 实例

您需要准备一个暴露 Restful HTTP 接口的 Attestation Service 实例，这可以通过安装 yum 源中的 `trustee` 包或者编译部署自己的 `restful-as` 来实现。

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

# 由于 restful-as 原生并不支持配置跨域规则，这里运行一个跨域代理服务（https://github.com/bulletmark/corsproxy），从 8080 端口转发请求到真正的 Attestation Service。
podman run -it --rm --net=host docker.io/bulletmark/corsproxy:latest 8080=http://127.0.0.1:9080
```

以上将在 8080 端口暴露一个 Attestation Service 服务。

> [!NOTE]
> 由于 TNG SDK 需要在浏览器中向 Attestation Service 实例发起请求，因此请确保您处理好跨域 (CORS) 规则。

### 6. 编译 TNG SDK

```sh
make wasm-build-debug
```

这将在 `tng-wasm/pkg/` 目录中产生对应的 `.wasm` 和 `.js` 文件。

### 7. 修改前端页面中的代码

请按需修改 [index.html](index.html) 中的如下内容。

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

最简单的方式是使用仓库提供的 make 目标（会自动带上跨源隔离所需的 COOP/COEP 头）：

```sh
make wasm-example-serve
```

然后访问 `http://<机密计算服务实例 ip>:8082/example/`。

如果你想手动起静态服务，可安装 [miniserve](https://github.com/svenstaro/miniserve)：

```sh
cargo +nightly-2025-07-07 install miniserve --locked
miniserve ./tng-wasm \
    --header "Cross-Origin-Opener-Policy:same-origin" \
    --header "Cross-Origin-Embedder-Policy:require-corp" \
    --port 8082
```

然后访问 `http://<机密计算服务实例 ip>:8082/example/`。

> [!NOTE]
> [`miniserve`](https://github.com/svenstaro/miniserve) 是一个纯粹的静态资源服务器，它和 Nginx 以及 python 的 http.server 没有什么差别，你也可以用其它组件来替代。

### 9. 从浏览器访问

在本地计算机中打开浏览器，访问 `http://<机密计算服务实例 ip>:8082/example/`，您可以在 F12 中查看请求响应的日志。

## GitHub Pages 演示站点

本仓库还会把一个交互式 SDK 演示发布到 GitHub Pages（站点源码在 `tng-wasm/www/`）。`.github/workflows/build-wasm-sdk.yml` 中的 `deploy-pages` 任务会在每次推送到 `master`、打 tag 或手动触发时构建 SDK 并部署站点。仓库管理员需一次性设置 **Settings → Pages → Source = "GitHub Actions"**。
