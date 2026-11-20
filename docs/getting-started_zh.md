# 通过 TNG 发出第一个请求

[English](getting-started.md) · [文档首页](README_zh.md)

先运行本地 RATS-TLS 非复用隧道，再为 TEE 部署启用远程证明。本地演示加密隧道，但在两端设置 `no_ra: true`，不认证可信环境，也不防御主动冒充对端。请将所有监听地址保留为 loopback，仅在本地开发中使用这份配置。

## 前置条件

- 从 [Releases](https://github.com/inclavare-containers/TNG/releases) 下载适合系统的预编译 `tng` 二进制，解压，在 Unix 系统上用 `chmod +x` 添加执行权限，再加入 `PATH`。运行 `tng --version` 检查。
- Git、Python 3 和 curl。需要三个终端，均在仓库根目录运行。
- `127.0.0.1` 上的 TCP 端口 38080、38081、38082 空闲。

示例使用端口映射，无需 root 权限、网络拦截、TEE 或证明服务。源码构建见[开发者指南](developer_zh.md)。

```sh
git clone https://github.com/inclavare-containers/TNG.git
cd TNG
```

## 启动后端

在终端 1 运行：

```sh
cd examples/quickstart/backend
python3 -m http.server 38080 --bind 127.0.0.1
```

后端提供仓库内的 `hello.txt` 文件。保持进程运行。

## 启动隧道

在终端 2 的仓库根目录运行：

```sh
tng launch --config-file examples/quickstart/local.json
```

本次演示由一个 TNG 进程运行两个端点：

```text
curl → 127.0.0.1:38082   → 127.0.0.1:38081   → 127.0.0.1:38080
       TNG Ingress        TNG Egress          Python 后端
       └── TLS 加密链路 ────┘
```

Ingress 是流量进入隧道的位置，Egress 是离开的位置。本例中该段之外的应用链路使用明文 HTTP。[local.json](../examples/quickstart/local.json)提供完整的 `add_ingress` 和 `add_egress` 配置，两端均显式选择 `rats_tls.multiplex: false` 和 `no_ra: true`。

## 请求与清理

在终端 3 运行：

```sh
curl --fail --noproxy '*' http://127.0.0.1:38082/hello.txt
```

预期响应正文：

```text
Hello through TNG.
```

在终端 2 和终端 1 按 Ctrl+C，停止 TNG 与后端。示例不创建系统网络规则或持久服务。

若启动时报端口占用，停止之前的演示进程，或同步修改 JSON、后端命令和请求 URL 中的三个端口。若 curl 无法连接，检查两个进程是否仍在运行，以及各终端是否位于仓库根目录。`--noproxy '*'` 可让本机请求绕过环境变量中的代理设置。

## 启用真实远程证明

实际部署时，将 Egress 与后端放在 TEE 中，将 Ingress 放在调用方环境。把两个配置项拆成独立文件，将隧道的 loopback 地址替换为实际部署地址，并限制为预期对端可访问。移除两端的 `no_ra`。

Egress 配置 `attest`，从 TEE 内的 Attestation Agent 收集证据；Ingress 配置 `verify`，使用内置验证器或外部服务按策略验证证据。[远程证明接入建议](remote_attestation_zh.md#接入建议)说明字段与依赖；[通过 HTTP 代理访问机密节点](scenarios/02-http-proxy-single/README_zh.md)提供完整部署示例。

内置 `hardware_only` 策略验证硬件证据，不将工作负载测量值与指定基线比较。如果你的信任决策包含允许运行哪些工作负载，应选择相应的测量策略并提供参考值。使用服务前，验证一次允许的部署，再故意配置不匹配策略验证拒绝路径；被拒绝的对端不应到达后端。策略选择和前置条件见[远程证明](remote_attestation_zh.md)。

## 选择下一种接入方式

- [场景目录](scenarios/README_zh.md)：透明代理、机密 AI 推理、集群和 relay 隐私。
- [SDK 与接入方式](README_zh.md#选择接入方式)：浏览器、Python、Go 和现有进程。
- [配置参考](configuration_zh.md)：端口映射、代理、UDP over QUIC 和协议选项。
