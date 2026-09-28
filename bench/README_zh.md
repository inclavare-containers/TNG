# TNG 双主机基准测试

测量两台主机之间通过 eth0 的真实 TNG 隧道性能。支持长连接（keep-alive）和短连接两种模式，可开关远程证明（RA）。

## 前置条件

**两台主机**都需要：
- TNG release 二进制：`cargo build --release -p tng`（默认特性含 `builtin-as-tdx-rust`）。
- podman（或 docker）：无则 `dnf install -y podman`。
- `python3`、`openssl`。

**服务端（TEE 主机）**（仅 RA 模式需要）：
- Attestation Agent：`dnf install -y attestation-agent libtdx-attest && systemctl start attestation-agent`。
- TDX 硬件（`/dev/tdx_guest`）。

## 两个重点基准测试场景

### 1. 长连接（keep-alive）： 持续连接

wrk 维持 `-c` 条持久 TCP+TLS 连接（HTTP/1.1 keep-alive）。每条连接只在建立时做一次 TLS 握手，之后所有请求复用该连接。**RA 开销被摊薄**（每连接一次握手，非每请求）。

测量稳态吞吐和已建立隧道上的每请求延迟：适用于长连接的生产场景（微服务间调用、持久 API 客户端）。

```bash
# 服务端（P 主机）：
TNG_BIN=/root/tng bash bench/server.sh

# 客户端（D 主机）：
# 无 RA：
TNG_BIN=/root/tng bash bench/client.sh <SERVER_IP>
# 带 RA（builtin AS + hardware_only）：
TNG_BIN=/root/tng RA_MODE=1 bash bench/client.sh <SERVER_IP>
```

### 2. 短连接（Connection: close）： 每请求新连接

wrk 发送 `Connection: close` → 服务端响应后关闭连接 → wrk 为下一个请求建立新的 TCP+TLS 连接。**每个请求都支付一次完整 TLS 握手**（若开启 RA，还包括证明+验证）。隔离每连接的握手成本。

测量连接建立的成本：适用于短连接的生产场景（API 网关、每请求负载均衡、Serverless）。

```bash
# 服务端（P 主机）：
TNG_BIN=/root/tng bash bench/server.sh          # 无 RA
# 或带 RA：
TNG_BIN=/root/tng RA_MODE=1 bash bench/server.sh

# 客户端（D 主机）：
# 无 RA 短连接：
TNG_BIN=/root/tng WRK_SHORT_CONN=1 bash bench/client.sh <SERVER_IP>
# 带 RA 短连接：
TNG_BIN=/root/tng RA_MODE=1 WRK_SHORT_CONN=1 bash bench/client.sh <SERVER_IP>
```

## 报告生成

每次运行写出三个 JSON 文件：`server-info.json` 与 `client-info.json`（主机环境与工具版本）、`bench-results.json`（测量指标）。从服务端主机拷回 `server-info.json` 后，生成 Markdown 报告：

```bash
bash bench/gen-report.sh <server-info.json> <client-info.json> <bench-results.json> [output.md]
```

报告按场景（iperf3、HTTP）各一张表，每行一个负载、每列一个指标。每张表下方附有采样方法说明，本 README 不再重复。读取一行：

- **吞吐 (Gbps)：** 负载带宽（iperf3）或 HTTP 带宽（wrk）。
- **RPS：** wrk 每秒请求数（仅 HTTP）。
- **Mean / p50 / p90 / p95 / p99：** 请求延迟分位数，单位微秒（仅 HTTP）；p95 与 p99 反映尾部延迟。
- **成功率：** 无错误完成请求占比（仅 HTTP）。
- **服务端 CPU % / 内存：** 运行期间服务端隧道进程的 CPU 与内存；`100` 等于一个逻辑核。raw 基线无隧道，显示为 `-`。
- **Δ vs raw：** 每个 non-raw 值后附相对同并发 raw 基线的百分比变化。吞吐/RPS 负值表示更低，延迟正值表示更慢。

## 关键环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `TNG_BIN` | `./target/release/tng` | tng 二进制路径。 |
| `SERVER_IP` | —（必填，客户端） | 服务端 IP。 |
| `RA_MODE` | `0` | `1` = 开启远程证明（服务端 attest，客户端 builtin AS + hardware_only verify）。 |
| `WRK_SHORT_CONN` | `0` | `1` = 每请求新 TCP+TLS 连接（`Connection: close`）。`0` = keep-alive（默认）。 |
| `WRK_WARMUP` | `1` | `1` = 每个测量点前跑一次 1 连接预热（prime TLS session ticket，为 0-RTT 恢复做准备）。 |
| `IPERF_STREAMS` | `1,8,16,32,64,128` | iperf3 并发流数。 |
| `IPERF_DURATION` | `15` | 每个 iperf3 轮秒数。 |
| `IPERF_ROUNDS` | `3` | 每点轮数（取中位数）。 |
| `WRK_CONNS` | `1,8,16,32,64,128` | wrk 连接数（长连接）或并发数（短连接）。 |
| `WRK_DURATION` | `15` | 每个 wrk 轮秒数。 |
| `WRK_ROUNDS` | `3` | 每点轮数（取中位数）。 |
| `HTTP_BODY_KB` | `64` | nginx 提供的 HTTP 响应体大小（KiB）。 |
| `BENCH_LABEL` | `bench-host` | 每次运行输出目录名前缀。 |
| `--output-dir DIR` | `bench/artifacts` | 每次运行输出目录的父目录。 |

## 输出目录结构

运行目录默认写到 `bench/artifacts/`（已 gitignore），多次运行的输出集中存放：

```
${BENCH_LABEL}-YYYYmmdd-HHMMSS/
  server-info.json     # 服务端主机环境 + 工具（iperf3/nginx/stunnel/haproxy）
  client-info.json     # 客户端主机环境 + 工具（iperf3/wrk/stunnel/haproxy）+ 参数
  bench-results.json   # 负载 -> {流数|连接数} -> 指标，N 轮中位数
  configs/             # 生成的 ingress.json / egress.json
  logs/                # tng 启动日志
  logs/raw/            # 每轮完整原始输出：<负载>-{s|c}<n>-r<i>.{json,txt}
```

## 负载

| 场景 | TNG 负载 | 基线 |
| --- | --- | --- |
| iperf3（TCP 吞吐） | rats-tls, rats-tls+mux | raw, stunnel, haproxy |
| HTTP（wrk, 64 KiB body） | rats-tls, rats-tls+mux, ohttp | raw, stunnel, haproxy |

所有 TNG 路径使用 `mapping` 模式。RA 模式在服务端加 `attest`（经 AA），客户端加 `verify`（builtin AS + hardware_only）。

### 端口矩阵

每个 TNG 隧道负载把客户端 ingress 端口 `5000X` 与服务端 egress 端口 `4000X` 配对；egress 转发到服务端本机的后端。

| 负载 | TNG 传输 | multiplex | 服务端端口 | 客户端端口 | 后端 |
| --- | --- | --- | --- | --- | --- |
| iperf3+rats-tls | rats-tls | false | 40001 | 50001 | iperf3 :5201 |
| iperf3+rats-tls+mux | rats-tls | true | 40002 | 50002 | iperf3 :5201 |
| http+rats-tls | rats-tls | false | 40003 | 50003 | nginx :8080 |
| http+rats-tls+mux | rats-tls | true | 40004 | 50004 | nginx :8080 |
| http+ohttp | ohttp | n/a | 40005 | 50005 | nginx :8080 |

基线（无 TNG）：`iperf3+raw` / `http+raw` 直连后端；`iperf3+stunnel` / `http+stunnel` 经 stunnel TLS 隧道（OpenSSL）以隔离通用 TLS 路径成本；`http+haproxy` / `iperf3+haproxy` 经 haproxy（TLS，线程每核事件循环）。stunnel 服务端端口 `:5210`（iperf3）/`:5211`（http）；haproxy 服务端端口 `:5213`（iperf3）/`:5212`（http）。

## 容器镜像

优先从 Aliyun 镜像拉取，失败回退到主 registry。解析出的来源、版本、sha256 digest 记入 `env.json` 以便复现。

| 工具 | 镜像（Aliyun） | 主回退 |
| --- | --- | --- |
| iperf3 | `mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest` | `networkstatic/iperf3:latest` |
| nginx | `mirrors-ssl.aliyuncs.com/library/nginx:stable-alpine` | `lscr.io/linuxserver/nginx:latest` |
| wrk | `mirrors-ssl.aliyuncs.com/ghcr.io/william-yeh/wrk:latest` | `ghcr.io/william-yeh/wrk:latest` |
| stunnel | `mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest` | `dockurr/stunnel:latest` |
| haproxy | `mirrors-ssl.aliyuncs.com/library/haproxy:latest` | `docker.io/library/haproxy:latest` |

服务端拉 iperf3/nginx/stunnel/haproxy（后端）；客户端拉 iperf3/wrk/stunnel/haproxy（压测 + TLS 基线客户端）。iperf3 低于 3.21 会告警（不失败）。

## Makefile 目标

```bash
make bench-host-server         # 启动服务端（无 RA）
make bench-host-client SERVER_IP=<P_IP>   # 运行客户端（无 RA）
make bench                    # 单主机 netns 开发基准（不变）
make bench-multiplex          # 同上，multiplex=true
```

RA 或短连接模式请用上面的环境变量直接 `bash bench/server.sh` / `bash bench/client.sh` 运行。
