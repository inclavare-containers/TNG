# TNG
[![Testing](/../../actions/workflows/docker-build.yml/badge.svg)](/../../actions/workflows/docker-build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## What is TNG?

TNG (TEE Network Gateway) 是一个用于建立安全通信隧道的工具，支持多种流量入站和出站方式，并且能够提供基于远程证明（Remote Attestation）的安全会话能力。通过配置不同的入口（Ingress）和出口（Egress）端点，用户可以在无需修改已有应用程序的同时，根据自己的需求灵活地控制流量的加密和解密过程。

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
docker run -it --rm --network host ghcr.io/inclavare-containers/tng:latest tng launch --config-content='<your config json string>'
```

请参考[配置文档](docs/configuration_zh.md)获取详细的配置说明。

## 构建

### 使用 Docker 镜像构建并运行

推荐使用 Docker 来构建 TNG。以下是步骤：

1. 拉取代码

2. 拉取依赖项

```sh
cd tng
git submodule update --init
```

3. 使用 Docker 构建

```sh
docker build -t tng:latest --target tng-release -f Dockerfile .
```

现在我们已经得到了 `tng:latest` 的 Docker 镜像。

4. 运行 tng

```sh
docker run -it --rm --network host tng:latest tng launch --config-content='<your config json string>'
```


### 创建 TNG tar包

1. 首先按照上面的步骤构建 `tng:latest` Docker 镜像。

2. 然后运行脚本来打包压缩包

```sh
./pack-sdk.sh
```

生成的压缩包名称为 `tng-<version>.tar.gz`。

3. 在新环境中安装压缩包

```sh
tar -xvf tng-*.tar.gz -C /
```

要运行 TNG 二进制文件，还需要安装一些依赖项。对于 Ubuntu 20.04：

```
apt-get install -y libssl1.1 iptables
```

4. 更新 iptables

如果你使用的是较新的内核，可能需要切换到 `iptables-nft`，因为 `iptables-legacy` 可能无法工作。

```sh
update-alternatives --set iptables /usr/sbin/iptables-nft
```

5. 运行 TNG

```sh
/opt/tng-0.1.0/bin/tng launch --config-content='<your config json string>'
```


6. 卸载

只需删除目录即可

```sh
rm -rf /opt/tng-*
```

## 示例

你可以从[集成测试用例](./tests/)中获取一些示例。

## 贡献

欢迎社区贡献，让TNG成为机密计算场景下更好的工具！如果有任何问题或建议，请随时提交 Issue 或 Pull Request。

## 许可证

Apache-2.0
