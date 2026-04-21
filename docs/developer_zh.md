# 开发者指南

本指南面向需要修改 TNG 源码或在本地调试 / 运行集成测试的开发者，介绍项目结构，以及如何从头搭建一个 TNG 的源码开发环境。

## 项目结构概览

- **tng/**：核心服务实现，包含命令行入口、配置解析、隧道（Ingress/Egress）、远程证明、观测性等主要逻辑。
- **tng-testsuite/**：集成测试套件，提供可编排的“场景任务”，覆盖 HTTP 代理、透明代理、Socks5、单向/双向远程证明等典型用法。
- **tng-wasm/**：浏览器侧 JavaScript SDK，对外提供 `tng_fetch` 等接口，配合 OHTTP 和远程证明使用，具体用法见 `tng-wasm/README_zh.md`。
- **docs/**：用户和开发文档，包括配置手册（`configuration_zh.md`）和本开发者指南。
- **rpm/**：RPM 打包相关脚本与 Dockerfile，用于构建发行包。

如果你只是想在本地编译并运行 TNG，可以只关注 `tng/` 目录；如果需要调试某个完整链路场景（例如“HTTP 代理 + 单向远程证明”），推荐优先运行对应的 `tng-testsuite` 用例来复现。

## 最低支持的 Rust 版本（MSRV）

本项目需要两个版本的 Rust 工具链：

- `1.89.0`：这是构建 TNG 二进制文件或 RPM 包（无论是从源码还是发布的源码 tar 包构建）所要求的最低支持的 Rust 版本。
- `nightly-2025-07-07`：这是以下场景所需的 Rust 工具链：
    - 构建 TNG 的 JavaScript SDK。详细信息请参见 [tng-wasm/README_zh.md](../tng-wasm/README_zh.md)。
    - 使用 `make create-tarball` 命令创建源代码 tar 包。这是因为我们的一些 crate 依赖项需要更新的 Rust 工具链才能解析。

## 开发环境搭建

## 获取源码

为避免依赖差异，我们推荐使用Docker来搭建开发环境，并完成TNG的编译。下面的步骤将介绍完整过程：

1. Docker环境准备

```sh
docker run -it --name tng-dev --privileged --network=host registry.openanolis.cn/openanolis/anolisos:23 bash
```
上述命令将基于Anolis23发行版，创建一个名为tng-dev的容器，该容器将作为TNG的开发环境。我们将在该容器中继续后面的步骤。

如果您不慎退出了该容器，使用如下命令重新进入
```sh
docker start tng-dev
docker exec -it tng-dev bash
```

2. 拉取源码

```sh
cd /
git clone https://github.com/inclavare-containers/tng.git --branch <tag名称>
cd tng
```
现在，你已经在`/tng`目录中拥有了tng仓库源码。

## 编译组件

### tng 编译

1. 切换到tng目录

```sh
cd /tng
```

2. 安装Rust

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

3. 编译并安装tng
```sh
cargo install --locked --path ./tng/ --root /usr/local/
```

现在，您可以直接使用tng命令来启动一个TNG实例了。


## 从开发环境打包rpm

一般来说，我们建议通过由git触发的[自动化的构建流程](/.github/workflows/build-rpm.yml)来打包，如果您在开发过程中有临时打包需求，可以使用如下流程。

1. 安装打包依赖

```
apt install chrpath
```

2. 构建rpm包

```sh
cat <<EOF > /tmp/trusted-network-gateway.spec
%global debug_package %{nil}

Name: trusted-network-gateway
Version: 1.0.0
Release: 1
Summary: Trusted Network Gateway
Group: Applications/System
License: ASL 2.0
URL: www.alibaba.com

Requires: curl iptables openssl

ExclusiveArch: x86_64

%description
A tool for establishing secure communication tunnels in confidential computing.

%install
mkdir -p %{buildroot}/usr/bin/
install -p -m 755 /usr/local/bin/tng %{buildroot}/usr/bin/tng

%files
/usr/bin/tng
EOF

rpmbuild -ba /tmp/trusted-network-gateway.spec
```

产物将存放在`~/rpmbuild/RPMS/x86_64/`目录中，请将其拷贝到目标环境

2. 在目标环境上，安装rpm包

首先卸载旧版本tng

```sh
yum remove trusted-network-gateway -y
```
安装新版本
```sh
yum install -y <rpm包在目标环境中的路径>
```

现在，您可以直接使用tng命令来启动一个TNG实例了。


## 运行测试

部分测试需要依赖于attestation-agent和attestation-service实例，接下来步骤将介绍这部分的搭建。

在本仓库中，集成测试主要集中在 `tng-testsuite` crate 中，通过不同的测试文件覆盖常见场景，例如：

- **`tcp_two_way_ra.rs`**：验证客户端和服务端都开启远程证明（双向 RA）的 TCP 场景。
- **`http_encapulation_with_ingress_httpproxy.rs`**：验证客户端通过 HTTP 代理接入、服务端使用 netfilter 的加密 HTTP 场景。
- **`js_sdk_http.rs`**：验证浏览器侧 JavaScript SDK（`tng-wasm`）配合 OHTTP 和远程证明的场景。

### 运行attestation-agent

1. 从[此处](https://github.com/inclavare-containers/guest-components/releases)获得最新的attestation-agent rpm包，并使用yum安装

> [!TIP]
> 如果您正在使用Alibaba Cloud Linux发行版，您可以直接从yum源安装我们提供的版本
> ```sh
> yum install -y attestation-agent
> ```

2. 运行

```sh
RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock
```

这将运行一个attestation-agent实例，并在`/run/confidential-containers/attestation-agent/attestation-agent.sock`上创建ttrpc监听

### 运行attestation-service

1. 从[此处](https://github.com/openanolis/trustee/releases)获得最新的trustee rpm包，并使用yum安装

> [!TIP]
> 如果您正在使用Alibaba Cloud Linux发行版，您可以直接从yum源安装我们提供的版本
> ```sh
> yum install -y trustee
> ```


2. 准备证书

```sh
openssl ecparam -genkey -name prime256v1 -out /tmp/as-ca.key
openssl req -x509 -sha256 -nodes -days 365 -key /tmp/as-ca.key -out /tmp/as-ca.pem -subj "/O=Trustee CA" \
      -addext keyUsage=critical,cRLSign,keyCertSign,digitalSignature
openssl ecparam -genkey -name prime256v1 -out /tmp/as.key
openssl req -new -key /tmp/as.key -out /tmp/as.csr -subj "/CN=Trustee/O=Trustee CA"
openssl x509 -req -in /tmp/as.csr -CA /tmp/as-ca.pem -CAkey /tmp/as-ca.key -CAcreateserial -out /tmp/as.pem -days 365 -extensions v3_req -extfile <(echo -e "[v3_req]\nsubjectKeyIdentifier = hash") -sha256

cat /tmp/as.pem /tmp/as-ca.pem > /tmp/as-full.pem

cat config.json | jq '.attestation_token_broker.signer.cert_path="/tmp/as-full.pem" | .attestation_token_broker.signer.key_path="/tmp/as.key" | .rvps_config={"type":"BuiltIn","storage":{"type":"LocalFs"}}' > config_with_cert.json
```

3. 配置调试策略（可选）

如果您希望在开发或测试过程中跳过远程证明（Attestation）的严格检查，可以配置一个默认通过的 OPA 策略。**注意：这绝对不应在生产环境中使用。**

```sh
mkdir -p /opt/trustee/attestation-service/policies/opa
cat <<EOF > /opt/trustee/attestation-service/policies/opa/default.rego
package policy

default executables := 3
default hardware := 2
default configuration := 2
default file_system := 2
EOF
```

4. 运行

```sh
RUST_LOG=debug restful-as --socket 0.0.0.0:8080 --config-file /trustee/attestation-service/config_with_cert.json
```

这将运行一个attestation-service实例，并在`0.0.0.0:8080`上创建HTTP restful监听

### 运行tng测试

1. 安装依赖

```sh
apt-get update && apt-get install -y curl iptables && update-alternatives --set iptables /usr/sbin/iptables-nft
```

2. 运行测试

```sh
make run-test
```

## 构建与部署

TNG 有两种常见的运行形态，可以以容器镜像形式部署，也可以通过构建 RPM 包来部署。下面给出推荐的构建流程，适合作为发布或在目标环境中安装使用。

### 构建并以容器镜像形式部署 TNG

1. 拉取代码

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <编译的版本tag名>
cd tng
git submodule update --init
```

2. 使用 Docker 构建

这将从源码完全重新编译 TNG 及其依赖项：

```sh
docker build -t tng:latest --target release -f Dockerfile .
```

3. 以容器形式运行 TNG

```sh
docker run -it --rm --privileged --network host --cgroupns=host tng:latest tng launch --config-content='<your config json string>'
```

### 构建并以 RPM 包形式部署 TNG

以下步骤介绍如何从源码构建 RPM 包并安装到目标环境（适用于使用 yum 作为包管理器的发行版）。

1. 拉取代码

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <编译的版本tag名>
cd tng
git submodule update --init
```

2. 安装依赖

请先安装 [Rust 工具链](https://rustup.rs/)，以及 Docker（或 Podman）。

3. 创建 RPM 构建所需的源码 tar 包

```sh
make create-tarball
```

4. 构建 RPM 包

可以选择在全新的 Anolis8 发行版 Docker 容器中构建 RPM 包，该 RPM 包同时适用于 [Anolis8](https://openanolis.cn/anolisos) 和 [ALinux3](https://help.aliyun.com/zh/alinux/product-overview/alibaba-cloud-linux-overview) 发行版：

```sh
make rpm-build-in-docker
```

也可以直接在当前发行版环境中构建：

```sh
make rpm-build
```

构建产物将存放在 `~/rpmbuild/RPMS/x86_64/` 目录中。

5. 安装 RPM 包

```sh
rpm -ivh ~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm
```

安装完成后，可以直接使用 `tng` 命令启动一个 TNG 实例。
