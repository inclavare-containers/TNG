# TNG Client JavaScript SDK

## 说明

TNG Client JavaScript SDK为浏览器环境提供客户端功能，使用wasm-pack构建。

## 在线示例

我们在 GitHub Pages 上提供了一个集成 TNG JavaScript SDK 的网页在线示例：<https://inclavare-containers.github.io/TNG/>

## 获取 SDK

您可以通过两种方式获取 TNG SDK：

### 1. 安装预编译包

直接从 npm 安装：

```bash
npm install @inclavare-containers/tng
```

也可从 [GitHub Packages](https://github.com/inclavare-containers/TNG/pkgs/npm/tng) 下载。

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
npm install @inclavare-containers/tng
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

### 进程内证明服务（`as_type: "builtin"`）

默认情况下，wasm SDK 在构建时即启用了 builtin-as——`make wasm-build-*` 目标会在 `tng-wasm` → `tng` 依赖上开启 `__builtin-as-wasm` feature。这使得浏览器 SDK 可以充当自身的证明服务（Attestation Service）：它在进程内转换并验证服务端的证明 token，因此客户端**无需运行外部证明服务进程**。通过 `as_type: "builtin"` 选择该模式（并省略 `as_addr`）：

```js
const tng_config = {
  ohttp: {},
  verify: {
    model: "background_check",
    as_type: "builtin",
  },
};
```

wasm 上支持的度量策略：

- `trust_all`——完全支持。
- `hardware_only`——可接受，但在 wasm 上退化为 trust-all（没有 TEE 验证器运行）。
- `hardware_with_reference_values` / `inline` / `path` rego 策略——在 wasm 上**不支持**（regorus 策略引擎没有 wasm 目标）。

参考值：`Sample` 参考值仅为配置兼容性而接受，但**不被度量**（wasm builtin-as 为 trust-all，始终签发 affirming token——由于没有 TEE 验证器 / RVPS 可为 wasm 编译，wasm 上不存在参考值度量）；`Slsa` / `ReleaseManifest` 参考值仅原生支持（需要 RVPS/rekor，在 wasm 上不可用）。

> [!IMPORTANT]
> wasm builtin-as **不执行真实的 TEE 证据度量**。TEE 验证器 crate（Intel TDX、AMD SEV-SNP、SGX、CSV、TPM）没有 `wasm32-unknown-unknown` 目标，因此浏览器 SDK 无法对硬件证据进行度量。wasm builtin-as 是一个自包含的 trust-all 路径——同一个 TNG 实例既签名又验证 token（闭环系统；验证器以 `insecure_key: true` 信任嵌入的密钥）。它适用于开发、演示以及不希望运行外部 AS 进程的场景。如需真实的 TEE 验证，请使用 `as_type: "restful"`（外部证明服务）或原生 TNG。

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

`example/` 目录中包含一个使用 TNG SDK 发送加密请求的示例页面，详细的端到端部署步骤见 [example/README_zh.md](example/README_zh.md)。

