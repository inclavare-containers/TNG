# tng-hook

基于 LD_PRELOAD 的 TNG 钩子库。支持出口模式（拦截 `bind()`/`getsockname()` 透明重定向监听端口）和入口模式（拦截 `connect()` 将出站连接路由到加密隧道）——**零应用修改**。

## 架构

```
┌──────────────────────────────────────────────────────────────┐
│  tng exec --config-file=/etc/tng.json -- vllm serve ...       │
│                                                              │
│  子进程                                                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  LD_PRELOAD=libtng_hook.so                             │  │
│  │  TNG_HOOK_EGRESS_MAPPINGS=<json>                              │  │
│  │                                                        │  │
│  │  应用调用 bind(0.0.0.0:8080)                            │  │
│  │       ↓                                                 │  │
│  │  libtng_hook.so 拦截 bind()                             │  │
│  │  查找 0.0.0.0:8080 → 真实端口 48080                     │  │
│  │  调用真实 bind(0.0.0.0:48080)                           │  │
│  │       ↓                                                 │  │
│  │  应用调用 getsockname()                                 │  │
│  │  libtng_hook.so 将 48080 改写回 8080                    │  │
│  │  应用看到端口 8080（伪装）                               │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  TNG 父进程在 0.0.0.0:8080 绑定，接收隧道流量                 │
│  将解密后的流量转发到 127.0.0.1:48080                         │
└──────────────────────────────────────────────────────────────┘
```

## 工作原理

### 映射表分发

TNG 将端口映射表序列化为 JSON，通过 `TNG_HOOK_EGRESS_MAPPINGS` 环境变量传递：

```json
{"entries":[{"host":"0.0.0.0","origin_port":8080,"real_port":48080}]}
```

每条记录含义：当应用调用 `bind(host:origin_port)` 时，重定向到 `host:real_port`。TNG 在 `origin_port` 上监听以接收隧道流量，然后将解密后的连接转发到 `real_port`。

`.so` 在 `#[ctor]` 初始化阶段（`main()` 之前）反序列化此数据，构建两个 HashMap：
- **forward**: `SocketAddrV4(原始地址) → real_port`（用于 `bind()` 拦截）
- **reverse**: `SocketAddrV4(真实地址) → origin_port`（用于 `getsockname()` 改写）

### 拦截点

#### `bind(sockfd, addr, addrlen)`

1. 检查地址是否为 `AF_INET`（仅支持 IPv4）
2. 在 forward map 中查找 `(ip, port)`（先精确匹配，再回退到通配符 `0.0.0.0`）
3. 命中：改写 `sin_port` 为 `real_port`，用修改后的地址调用真实 `bind()`
4. 未命中：原样传递给真实 `bind()`

#### `getsockname(sockfd, addr, addrlen)`

1. 先调用真实 `getsockname()`
2. 在 reverse map 中查找返回的 `(ip, port)`
3. 命中：改写 `sin_port` 回 `origin_port`（维持应用看到原始端口的假象）
4. 未命中：原样返回

### 真实函数解析

使用 `dlopen("libc.so.6")` + `dlsym()` 解析真实的 `bind` 和 `getsockname`——**不使用** `dlsym(RTLD_NEXT)`，因为当我们位于 LD_PRELOAD 链首位时，`RTLD_NEXT` 会返回我们自己的钩子函数。

### 线程安全

查找 HashMap 在初始化时构建一次，之后不再修改。`HashMap` 读取在构造完成后是线程安全的——不需要 `Mutex`。

### fork 处理

`fork()` 后，子进程继承 `.so` 的映射表（通过 fork 的内存语义复制）、环境变量和已有文件描述符。无需特殊处理。

## 项目结构

```
tng-hook/
├── types/              # tng-hook-types：共享结构体定义
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs      # HookMappingTable, HookMappingEntry, HookMappingLookup
└── cdylib/             # tng-hook-cdylib：.so 库
    ├── Cargo.toml
    └── src/
        └── lib.rs      # bind/getsockname 拦截, #[ctor] 初始化
```

- **`tng-hook-types`** — 纯数据结构 + serde 序列化。无系统调用，无 unsafe 代码。被 `tng`（配置解析）和 `.so` 同时依赖。
- **`tng-hook-cdylib`** — 实际的 LD_PRELOAD 库（`libtng_hook.so`）。依赖 `tng-hook-types` 获取共享类型。

## 构建

```bash
# 构建 .so 库
cargo build -p tng-hook-cdylib

# Release 模式
cargo build --release -p tng-hook-cdylib

# 构建并运行类型测试
cargo test -p tng-hook-types
```

产物为 `target/debug/libtng_hook.so`（或 `target/release/libtng_hook.so`）。

## 打包说明

`libtng_hook.so` 仅被 `tng exec` 子命令使用，且**仅支持 Linux**（依赖 Linux glibc 进行 LD_PRELOAD 系统调用拦截）。以下 TNG 发行制品包含此库：

| 制品类型 | 包含 | 安装路径 |
|---|---|---|
| RPM 包 | ✅ | `/usr/lib/tng/libtng_hook.so` |
| Docker 镜像 | ✅ | `/usr/lib/tng/libtng_hook.so` |
| 二进制发布包（Linux） | ✅ | 与 `tng` 一同打包在 `.tar.gz` 中 |
| Python SDK | ❌ 不需要 — `tng exec` 是 CLI 工具 |
| WASM SDK | ❌ 不适用 — 浏览器环境 |

二进制发布版中，`tng` 按以下顺序搜索该库：
1. `$TNG_HOOK_LIB` 环境变量
2. `tng` 二进制同目录
3. `/usr/lib/tng/libtng_hook.so`

## 使用

通过 `tng exec` 运行：

```bash
tng exec --config-file=/etc/tng.json -- your-server --port 8080
```

`tng exec` 自动处理所有步骤：
1. 解析配置，验证 hook 模式
2. 构建映射表，自动分配真实端口
3. 在原始端口启动 TNG 隧道监听器
4. 启动子进程，设置 `LD_PRELOAD` 和 `TNG_HOOK_EGRESS_MAPPINGS`

### 手动调用（调试用）

```bash
LD_PRELOAD=/path/to/libtng_hook.so \
TNG_HOOK_EGRESS_MAPPINGS='{"entries":[{"host":"0.0.0.0","origin_port":8080,"real_port":48080}]}' \
your-server --port 8080
```

## Ingress Hook 模式

除了 egress hook 模式（拦截 `bind()`/`getsockname()`）外，`libtng_hook.so` 还支持 **ingress hook 模式**——拦截子进程的出站 `connect()` 调用，通过 HTTP CONNECT 协议将其路由到 TNG 加密隧道中。

### 架构

```
┌──────────────────────────────────────────────────────────────┐
│  tng exec --config-file=/etc/tng.json -- curl http://...      │
│                                                              │
│  子进程                                                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  LD_PRELOAD=libtng_hook.so                             │  │
│  │  TNG_HOOK_INGRESS_MAPPINGS=<json>                      │  │
│  │                                                        │  │
│  │  应用调用 connect(10.0.0.1:80)                          │  │
│  │       ↓                                                 │  │
│  │  libtng_hook.so 拦截 connect()                          │  │
│  │  查找 10.0.0.1:80 → 匹配                                │  │
│  │  连接到内部代理 127.0.0.1:49001 替代                     │  │
│  │  向代理发送 HTTP CONNECT → 隧道到目标                    │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  内部 HTTP 代理监听在 127.0.0.1:49001                          │
│  通过 TNG 加密隧道路由到出口                                   │
└──────────────────────────────────────────────────────────────┘
```

### 工作原理

**映射表分发**

TNG 将 ingress 映射表序列化为 JSON，通过 `TNG_HOOK_INGRESS_MAPPINGS` 环境变量传递：

```json
{"proxies":[{"proxy_port":49001,"capture_rules":[{"host_cidr":"10.0.0.0/24","port":80},{"host_cidr":"10.0.0.0/24","port":443}]}]}
```

每条代理记录指定一个 `proxy_port` 和一组 `capture_rules`。当应用调用 `connect(host:port)` 匹配捕获规则时，连接会被重定向到内部 HTTP 代理。

`.so` 在 `#[ctor]` 初始化阶段（`main()` 之前）反序列化此数据，构建查找表。

**`connect(sockfd, addr, addrlen)` 拦截**

1. 检查地址是否为 `AF_INET`（仅支持 IPv4）
2. 在捕获表中查找 `(ip, port)`（CIDR 匹配，通配符回退）
3. 命中：连接到内部代理，发起 HTTP CONNECT
4. 未命中：原样传递给真实 `connect()`

### 配置

Ingress hook 模式通过 `add_ingress` 中的 `"hook"` 模式配置：

```json
{
  "add_ingress": [
    {
      "hook": {
        "capture_dst": [
          { "host": "10.0.0.0/24", "port": 80 },
          { "host": "10.0.0.0/24", "port": 443 },
          { "port": 8080, "port_end": 8090 }
        ],
        "proxy_port": 49001
      },
      "attest": { "no_ra": true }
    }
  ]
}
```

| 字段 | 类型 | 必需 | 描述 |
|---|---|---|---|
| `capture_dst` | 数组 | 是 | 需要拦截的目标 IP+端口规则。 |
| `capture_dst[].host` | CIDR 或 IP | 否 | IPv4 地址或 CIDR 前缀。省略表示匹配任意 IP（`*`）。 |
| `capture_dst[].port` | 整数 | 是 | 需要拦截的目标端口。 |
| `capture_dst[].port_end` | 整数 | 否 | 端口范围结束（包含）。省略时为单端口匹配。 |
| `proxy_port` | 整数 | 否 | 内部 HTTP 代理端口。省略时自动分配。 |
| `proxy_listen` | 字符串 | 否 | 内部代理的绑定地址。默认：`127.0.0.1`。 |

## 日志

`.so` 在初始化时自行初始化 tracing subscriber，输出到 stderr。日志级别通过 `RUST_LOG` 控制：

```bash
# 默认：info 级别
RUST_LOG=info LD_PRELOAD=... your-server

# 调试：查看所有拦截细节
RUST_LOG=debug LD_PRELOAD=... your-server
```

**bind 拦截日志**（info 级别）：
```
bind hijacked: 0.0.0.0:8080 → 0.0.0.0:48080
```

## 故障排查

### "libtng_hook.so not found"

TNG 按以下顺序搜索：
1. `$TNG_HOOK_LIB` — 显式指定路径
2. `tng` 二进制同目录
3. `/usr/lib/tng/libtng_hook.so` — 系统安装路径

通过 `TNG_HOOK_LIB=/path/to/libtng_hook.so` 指定自定义位置。

### Port already in use

真实端口（如 `48080`）已被其他进程占用。用 `ss -tlnp | grep 48080` 检查。解决方法：
- 在配置中使用 `redirect_to_port` 指定不同的真实端口
- 不指定 `redirect_to_port` 时 TNG 通过 `portpicker` 自动分配

### 原始端口连接被拒绝

TNG 隧道监听器未能绑定原始端口。检查是否有其他进程已占用：`ss -tlnp | grep 8080`。

### getsockname 返回错误端口

反向映射可能未覆盖 `getsockname()` 返回的地址。检查 `TNG_HOOK_EGRESS_MAPPINGS` 环境变量：
```bash
echo $TNG_HOOK_EGRESS_MAPPINGS | python3 -m json.tool
```
确认 `host` 和 `real_port` 与应用实际绑定的地址一致。

### connect() 未被拦截

捕获规则可能未匹配目标地址。检查 `TNG_HOOK_INGRESS_MAPPINGS` 环境变量：
```bash
echo $TNG_HOOK_INGRESS_MAPPINGS | python3 -m json.tool
```
确认 `host`（或 CIDR）和 `port` 与应用实际连接的目标一致。

### bind 拦截后应用崩溃

仅支持 `AF_INET`（IPv4）。如果应用使用 IPv6（`AF_INET6`），会原样传递给真实函数。检查应用日志中的 IPv6 绑定尝试。
