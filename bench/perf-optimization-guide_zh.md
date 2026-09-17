# TNG 性能优化指南

迭代式缩小 TNG rats-tls 与 HAProxy（或其他 TLS 代理基线）在短连接和长连接场景下差距的参考方法。

## 概述

TNG rats-tls 相比 HAProxy 这类纯 TLS 代理有两层额外开销：
1. **TLS 握手层**：rustls vs OpenSSL、tokio 异步 vs HAProxy 事件循环、每连接建立成本。影响 no_ra 和 RA。
2. **RA（远程证明）层**：TDX quote 收集（经 AA）+ builtin-AS 验证。仅影响 RA 模式。

短连接模式下（每请求 = 新 TCP+TLS），两层开销都是每请求的。长连接模式下（keep-alive），每连接一次性（被摊薄）。

## 基线差距（优化前，4-vCPU TDX，短连接）

| 指标 | rats-tls no_ra | rats-tls RA | HAProxy | raw |
|---|---|---|---|---|
| RPS @ c=1 | 277 | 35 | 661 | 3237 |
| RPS @ c=128 | 921 | 75 | 3894 | 30278 |
| p50 @ c=1 | 3.5ms | 28ms | 1.4ms | 0.3ms |
| p50 @ c=128 | 132ms | 1470ms | 32ms | — |

## Phase 0：部署 + 基线

1. 构建最新 tng：`cargo build --release -p tng`。
2. 部署到两台主机：`scp target/release/tng root@<host>:/root/tng`。
3. 部署 bench 脚本：`scp -r bench/ root@<host>:/root/`。
4. 跑基线（4 个场景：no_ra 长连接、no_ra 短连接、RA 长连接、RA 短连接）。
5. 记录为第 0 轮，写入 `bench/.perf-iteration-state.md`。

## Phase 1：自动化测量

bench 脚本（`bench/client.sh`）跑全部负载（iperf3 + http，rats-tls + 基线），写出 `bench-results.json`。报告生成器（`bench/gen-report.sh`）产出 Markdown 报告。

迭代间对比：从 `bench-results.json` 提取 `http+rats-tls` 和 `http+haproxy` 的指标，计算差距：

```
gap_pct = (1 - rats_tls_RPS / haproxy_RPS) * 100
```

在每个并发级别记录：RPS、p50、p99、CPU%、内存、成功率。

## Phase 2：Profiling

### perf 火焰图

```bash
# 在客户端，wrk 运行期间（短连接 c=32）：
perf record -p <tng_pid> -g --call-graph dwarf -F 99 -- sleep 10
perf script | flamegraph.pl > flamegraph-iter-N.svg
```

### pidstat（perf 不可用时）

```bash
pidstat -p <tng_pid> -urd 1 10
# -u: CPU, -r: 内存, -d: I/O。1 秒间隔，10 个样本。
```

### eBPF/offcpu profiling（如果可用）

```bash
# off-CPU time（进程在哪里等待）：
perf record -p <tng_pid> -e sched:sched_switch -- sleep 10
```

### 热点区域（按优先级）

1. **RA 验证路径**（`ra/common.rs:verity_pending_cert` → builtin-AS TDX quote 验证）：预计占 RA 开销的 ~80%。
2. **TLS 握手**（rustls `connect`/`accept`，证书交换）：预计 ~10-15%。
3. **连接管理**（tokio accept、连接建立、buffer 分配）：预计 ~5%。
4. **内存分配**（每连接的证书、TLS 上下文、buffer）：预计 ~5%。

## Phase 3：根因分析

对每个热点回答：
1. **HAProxy 哪里更快？**（OpenSSL vs rustls？多进程 vs tokio？无 RA？连接池？）
2. **具体瓶颈是什么？**（CPU 计算？锁竞争？内存分配？系统调用？异步调度？）
3. **优化空间有多大？**（算法层面？实现层面？架构层面？）

## Phase 4：优化清单

### 第 1 层：RA 验证（最大杠杆，针对 RA-only 差距）

| 优化项 | 预期效果 | 复杂度 | 状态 |
|---|---|---|---|
| 共享 CertVerifyCache（同证书跳过重复验证） | TTL 内消除重复 builtin-AS 调用 | 低 | 已完成（共享缓存） |
| 0-RTT 会话恢复（恢复连接跳过 RA） | 恢复连接完全跳过证书验证 | 中 | 进行中（ticket 修复） |
| AA 启动时预生成 TDX quote | AA 缓存 quote，不按需生成 | 低 | 待评估 |
| RA 验证并行化（并发验证） | 多个验证并发而非串行 await | 中 | 待评估 |
| 异步 RA 验证（不阻塞数据面） | forward + 验证并发 | 高 | 已排除（必须先验证再传数据） |

### 第 2 层：TLS 握手（针对 no_ra 差距）

| 优化项 | 预期效果 | 复杂度 |
|---|---|---|
| 会话恢复普及（0-RTT 给返回客户端） | 1-RTT → 0-RTT，跳过证书交换 | 中 |
| rustls 配置调优（减少证书链步骤） | 每次握手更少验证步骤 | 低 |
| TLS ticket 预签发（服务端预生成 ticket） | 更快的 ticket 可用性 | 中 |
| 减小证书体积（更小的 RA 证据） | 每次握手更少数据传输 | 中 |

### 第 3 层：连接管理（针对剩余差距）

| 优化项 | 预期效果 | 复杂度 |
|---|---|---|
| 连接池（复用底层 TLS session） | 短连接请求复用池化 session | 高 |
| Buffer 池（预分配每连接 buffer） | 消除每连接 malloc/free | 中 |
| tokio worker 线程调优 | 线程数匹配负载 | 低 |
| 减少每连接分配（Arc、Box 等） | 更少 GC 压力、更快建立 | 中 |

## Phase 5：迭代循环

```
1. 跑 bench（no_ra + RA 短连接）
2. 生成对比报告
3. 检查差距：rats-tls vs HAProxy 每个并发级别
4. 若差距 < 10% → 完成
5. Profile（perf 火焰图）
6. 找到最大热点
7. 做一个优化（不批量改）
8. 重新构建 + 部署
9. 更新 bench/.perf-iteration-state.md
10. 回到 1
```

**迭代纪律**：每轮一个优化，不批量改，保证可归因。

## 成功标准

| 指标 | 目标 |
|---|---|
| RA RPS / HAProxy RPS | >= 90%（c=1,8,32,128） |
| RA p50 / HAProxy p50 | <= 110%（c=1,8,32,128） |
| no_ra RPS / HAProxy RPS | >= 90%（c=1,8,32,128） |

## 机器信息

- 服务端（TDX）：`ssh` to the server host（4 vCPU，/dev/tdx_guest，AA via systemd）
- 客户端：`ssh` to the client host（4 vCPU）
- 控制端：仓库 worktree（cargo，bench 脚本）
