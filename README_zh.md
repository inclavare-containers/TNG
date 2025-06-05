# TNG
[![Docker](/../../actions/workflows/build-docker.yml/badge.svg)](/../../actions/workflows/build-docker.yml)
[![RPM](/../../actions/workflows/build-rpm.yml/badge.svg)](/../../actions/workflows/build-rpm.yml)
[![codecov](https://codecov.io/gh/inclavare-containers/TNG/graph/badge.svg?token=7CUZW26SH6)](https://codecov.io/gh/inclavare-containers/TNG)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## What is TNG?

TNG (Trusted Network Gateway) 是一个用于建立安全通信隧道的工具，支持多种流量入站和出站方式，并且能够提供基于远程证明（Remote Attestation）的安全会话能力。通过配置不同的入口（Ingress）和出口（Egress）端点，用户可以在无需修改已有应用程序的同时，根据自己的需求灵活地控制流量的加密和解密过程。

## 使用方法

TNG的最主要部分是其 launch 子命令。以下是其用法：

```txt
Usage: tng launch [OPTIONS]

Options:
  -c, --config-file <CONFIG_FILE>
      --config-content <CONFIG_CONTENT>
  -h, --help                             Print help
```

在开始之前，需要提供一个 JSON 配置文件，或者直接从命令行参数中提供 JSON 格式的配置内容，这些配置将被用来配置 TNG 实例。

启动 TNG 实例最简单的方法是使用我们预构建好的Docker镜像：

```sh
docker run -it --rm --privileged --network host --cgroupns=host ghcr.io/inclavare-containers/tng:latest tng launch --config-content='<your config json string>'
```

请参考[配置文档](docs/configuration_zh.md)获取详细的配置说明。

## 构建

TNG有两种常见的运行形态，您可以以容器形式部署和运行TNG，或者，也可以通过构建rpm包来部署TNG。

如果你希望修改后编译TNG，请参考[开发人员文档](docs/developer_zh.md)。

### 构建并以容器镜像形式部署TNG

推荐使用 Docker 来构建 TNG。以下是步骤：

1. 拉取代码

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <编译的版本tag名>
cd tng
git submodule update --init
```

2. 使用 Docker 构建

这将从源码完全重新编译tng及其依赖项

```sh
docker build -t tng:latest --target tng-release -f Dockerfile .
```

现在我们已经得到了 `tng:latest` 的 Docker 镜像，您可以直接部署运行该镜像。

3. 以容器形式运行 tng

```sh
docker run -it --rm --privileged --network host --cgroupns=host tng:latest tng launch --config-content='<your config json string>'
```


### 构建并以RPM包形式部署TNG

该步骤介绍如何从源码构建rpm包，并安装rpm包。这仅适用于使用yum作为包管理的发行版。

1. 拉取代码

```sh
git clone git@github.com:inclavare-containers/tng.git --branch <编译的版本tag名>
cd tng
git submodule update --init
```

2. 请先[安装rust工具链](https://rustup.rs/)，以及docker（或podman）。

3. 创建rpm构建所需的源码tar包

```sh
make create-tarball
```

4. 构建rpm包

您可以选择在全新的Anolis8发行版docker容器中构建rpm包，该rpm包同时适用于[Anolis8](https://openanolis.cn/anolisos)发行版和[ALinux3](https://help.aliyun.com/zh/alinux/product-overview/alibaba-cloud-linux-overview)发行版

```sh
make rpm-build-in-docker
```

或者，您也可以直接在当前发行版环境中构建rpm包：

```sh
make rpm-build
```

产物将存放在`~/rpmbuild/RPMS/x86_64/`目录中

5. 安装rpm包

```sh
rpm -ivh ~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm
```

现在，你可以直接使用`tng`命令来启动一个TNG实例。


## 示例

你可以从[集成测试用例](./tests/)中获取一些示例。

## 贡献

欢迎社区贡献，让TNG成为机密计算场景下更好的工具！如果有任何问题或建议，请随时提交 Issue 或 Pull Request。

## 许可证

Apache-2.0
