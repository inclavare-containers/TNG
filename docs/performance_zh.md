# TNG 性能快照

> 本页记录当前 TNG 版本的跟踪式性能快照，每次性能变更合入后重新生成。页面展示单次运行的数据，不做前后对比。

## 本页是什么

本页在标准双主机压测方法下跟踪当前开发版本的实测性能：三个场景（iperf3 TCP 吞吐、HTTP keep-alive、HTTP 无 keep-alive），每个场景一张表，一行一个 workload、一列一个指标，并为每个场景配一张图。页面始终描述当前版本：性能变更合入时，其 PR 会用新的最终实测结果重新生成本页（见[更新规则](#更新规则)一节）。单个变更的前后对比证据保留在各 PR 的压测报告里，不放在本页。

页面上的每个数字都来自同一次实测。场景表格与页末逐字嵌入的完整报告，以当前生成器的格式呈现该次运行的实测数值，图表由 `bench/gen-svg.py` 渲染同一组数值，因此快照可追溯，不存在手抄数字。

## 如何运行压测

压测工具说明在 [`bench/README.md`](../bench/README.md)：server/backend 主机执行 `bash bench/server.sh`，client/load 主机执行 `bash bench/client.sh <SERVER_IP>`，运行产出三个留存的 JSON 文件。[`bench/reporting.md`](../bench/reporting.md) 记录报告生成（`bench/gen-report.sh`，单次或 `--compare` 模式）、SVG 图生成（`bench/gen-svg.py`）与构建身份记录器。压测运行必须串行：驱动程序启动前必须持有两台共享主机的独占 bench 锁，避免并发运行在同一批测试点上叠加负载。本页不重复上述文档内容。

## 测量模式

当前快照按 `master` 上的现行方法测量：

- 开启远程证明：egress 通过 attestation-agent Unix socket 提交证明，ingress 使用内置证明服务按 `hardware_only` 策略验证。
- HTTP 响应体 64 KiB。每轮运行同时测量两种 HTTP 连接模式（keep-alive 与无 keep-alive）以及 iperf3 TCP 吞吐。
- 每个场景的并发梯度为 1、8、16、32、64、128。
- 每个 workload/并发测试点都在全新启动的隧道/代理进程上测量，因此测试点的内存峰值就是该点自身开销，而不是早期测试点遗留的分配器高水位。
- 每个测试点取最强一轮（多轮中请求率或吞吐最高的一轮）。
- CPU 100% 等于一个逻辑核。下文表格中的 Egress 指被测网关/代理的服务端实例（TNG egress；HAProxy 主进程加工作进程；stunnel 服务端容器），Ingress 指其客户端实例（TNG ingress）。场景 A 采样入口实例；场景 B、C 采样出口实例。`raw` 参考没有代理进程，其资源列天然缺失。

## 实测快照

实测二进制：tng 2.12.0，ingress 与 egress 均构建自源码版本 `f069033f`。

TNG 提供三种不同的隧道配置，不同模式的数值相差数倍，因此下文每个标签都明确指明配置：

| 标签 | 配置 |
| --- | --- |
| `raw` | 直连，不经任何 TLS 代理（参考） |
| `stunnel` | stunnel TLS 隧道（参考） |
| `haproxy` | HAProxy TLS 终结代理（参考） |
| `nginx stream (TLS)` | nginx stream 模块 L4 TLS 代理（参考） |
| `nginx http (TLS)` | nginx http 模块 L7 TLS 反向代理，对后端使用 HTTP/1.1 keep-alive（参考） |
| `rats-tls` | TNG rats-tls 非多路复用：每条客户端 TCP 连接对应一条到 egress 的 TLS 连接 |
| `rats-tls+mux` | TNG rats-tls 多路复用：多条客户端连接共享一条到 egress 的 HTTP/2 CONNECT 隧道 |
| `ohttp` | TNG ohttp：Oblivious HTTP（RFC 9458）密封请求/响应信封，ingress 通过明文 HTTP POST 到 egress |

### 场景 A - TCP / iperf3 吞吐

![场景 A：TCP 吞吐、入口 CPU 与入口内存随 iperf3 并发流数的变化](performance/scenario_a.svg)

每个非 raw 单元格括号内是相对同一并发度下 `raw` 基线的百分比变化。场景 A 未测量 ohttp 与 `nginx http (TLS)`：nginx http 模块是 L7 反向代理，raw TCP 的 iperf3 流量没有 L7 形态。

| Streams | Workload | Throughput (Gbps) | Ingress CPU % | Ingress Mem (GB) |
| --- | --- | --- | --- | --- |
| 1 | raw | 15.71 | - | - |
| 1 | stunnel | 10.41 (-34%) | 81.4 | 0.007 |
| 1 | haproxy | 10.01 (-36%) | 55.1 | 0.088 |
| 1 | nginx stream (TLS) | 11.76 (-25%) | 72.3 | 0.046 |
| 1 | rats-tls | 9.07 (-42%) | 39.8 | 0.047 |
| 1 | rats-tls+mux | 9.56 (-39%) | 94.5 | 0.052 |
| 8 | raw | 15.72 | - | - |
| 8 | stunnel | 14.20 (-10%) | 229.4 | 0.008 |
| 8 | haproxy | 15.73 (+0%) | 116.8 | 0.087 |
| 8 | nginx stream (TLS) | 15.74 (+0%) | 107.4 | 0.046 |
| 8 | rats-tls | 15.74 (+0%) | 81.5 | 0.054 |
| 8 | rats-tls+mux | 12.04 (-23%) | 139.3 | 0.076 |
| 16 | raw | 15.73 | - | - |
| 16 | stunnel | 13.52 (-14%) | 237.4 | 0.009 |
| 16 | haproxy | 15.76 (+0%) | 108.9 | 0.088 |
| 16 | nginx stream (TLS) | 4.31 (-73%) | 23.7 | 0.047 |
| 16 | rats-tls | 15.79 (+0%) | 90.1 | 0.060 |
| 16 | rats-tls+mux | 10.58 (-33%) | 115.5 | 0.107 |
| 32 | raw | 4.24 | - | - |
| 32 | stunnel | 4.38 (+3%) | 52.4 | 0.009 |
| 32 | haproxy | 4.40 (+4%) | 29.2 | 0.089 |
| 32 | nginx stream (TLS) | 4.40 (+4%) | 26.2 | 0.049 |
| 32 | rats-tls | 4.41 (+4%) | 21.9 | 0.076 |
| 32 | rats-tls+mux | 4.40 (+4%) | 48.5 | 0.155 |
| 64 | raw | 4.25 | - | - |
| 64 | stunnel | 4.55 (+7%) | 55.5 | 0.011 |
| 64 | haproxy | 4.56 (+7%) | 31.2 | 0.091 |
| 64 | nginx stream (TLS) | 4.56 (+7%) | 28.9 | 0.051 |
| 64 | rats-tls | 4.57 (+8%) | 24.2 | 0.114 |
| 64 | rats-tls+mux | 4.60 (+8%) | 41.5 | 0.244 |
| 128 | raw | 4.25 | - | - |
| 128 | stunnel | 4.63 (+9%) | 62.9 | 0.016 |
| 128 | haproxy | 4.70 (+11%) | 32.9 | 0.097 |
| 128 | nginx stream (TLS) | 4.64 (+9%) | 31.7 | 0.058 |
| 128 | rats-tls | 4.69 (+10%) | 29.0 | 0.151 |
| 128 | rats-tls+mux | 4.85 (+14%) | 43.2 | 0.381 |

### 场景 B - HTTP / wrk，64 KiB 响应体，keep-alive

![场景 B：RPS、p95 延迟、出口 CPU 与出口内存随 keep-alive 并发连接数的变化](performance/scenario_b.svg)

wrk 为每个客户端维持一条持久 TCP+TLS 连接，证明开销被复用该连接的请求摊薄。

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Egress CPU % | Egress Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 2.31 | 4602 | 230 | 204 | 266 | 446 | 800 | 100.0 | - | - | - |
| 1 | stunnel | 1.62 (-30%) | 3219 (-30%) | 317 (+38%) | 302 (+48%) | 355 (+33%) | 377 (-15%) | 570 (-29%) | 100.0 (+0%) | - | 24.6 | 6.8 |
| 1 | haproxy | 1.77 (-23%) | 3518 (-24%) | 289 (+26%) | 277 (+36%) | 326 (+23%) | 344 (-23%) | 411 (-49%) | 100.0 (+0%) | - | 23.3 | 124.1 |
| 1 | nginx stream (TLS) | 1.67 (-28%) | 3323 (-28%) | 307 (+33%) | 292 (+43%) | 345 (+30%) | 366 (-18%) | 690 (-14%) | 100.0 (+0%) | - | 23.1 | 46.7 |
| 1 | nginx http (TLS) | 1.54 (-33%) | 3059 (-34%) | 332 (+44%) | 320 (+57%) | 365 (+37%) | 385 (-14%) | 593 (-26%) | 100.0 (+0%) | - | 31.1 | 48.8 |
| 1 | rats-tls | 1.30 (-44%) | 2593 (-44%) | 511 (+122%) | 362 (+77%) | 433 (+63%) | 790 (+77%) | 1380 (+72%) | 100.0 (+0%) | - | 15.7 | 39.9 |
| 1 | rats-tls+mux | 0.77 (-67%) | 1525 (-67%) | 698 (+203%) | 645 (+216%) | 716 (+169%) | 741 (+66%) | 1460 (+82%) | 100.0 (+0%) | - | 34.8 | 39.9 |
| 1 | ohttp | 0.73 (-68%) | 1456 (-68%) | 698 (+203%) | 678 (+232%) | 750 (+182%) | 776 (+74%) | 850 (+6%) | 100.0 (+0%) | - | 46.1 | 40.8 |
| 8 | raw | 13.04 | 26601 | 778 | 258 | 485 | 2214 | 15920 | 100.0 | - | - | - |
| 8 | stunnel | 6.66 (-49%) | 13260 (-50%) | 627 (-19%) | 564 (+119%) | 836 (+72%) | 955 (-57%) | 2009 (-87%) | 100.0 (+0%) | - | 125.9 | 7.4 |
| 8 | haproxy | 6.96 (-47%) | 14148 (-47%) | 572 (-26%) | 526 (+104%) | 779 (+61%) | 894 (-60%) | 1400 (-91%) | 100.0 (+0%) | - | 111.4 | 126.4 |
| 8 | nginx stream (TLS) | 7.20 (-45%) | 14754 (-45%) | 553 (-29%) | 511 (+98%) | 727 (+50%) | 825 (-63%) | 1270 (-92%) | 100.0 (+0%) | - | 92.1 | 47.3 |
| 8 | nginx http (TLS) | 6.77 (-48%) | 13496 (-49%) | 599 (-23%) | 560 (+117%) | 783 (+61%) | 880 (-60%) | 1280 (-92%) | 100.0 (+0%) | - | 140.3 | 49.4 |
| 8 | rats-tls | 7.28 (-44%) | 14869 (-44%) | 544 (-30%) | 522 (+102%) | 670 (+38%) | 725 (-67%) | 980 (-94%) | 100.0 (+0%) | - | 91.3 | 41.5 |
| 8 | rats-tls+mux | 4.20 (-68%) | 8374 (-69%) | 1460 (+88%) | 880 (+241%) | 1230 (+154%) | 2967 (+34%) | 20250 (+27%) | 100.0 (+0%) | - | 89.3 | 46.8 |
| 8 | ohttp | 3.45 (-74%) | 6880 (-74%) | 1160 (+49%) | 1100 (+326%) | 1540 (+218%) | 1701 (-23%) | 2110 (-87%) | 100.0 (+0%) | - | 176.7 | 46.2 |
| 16 | raw | 14.64 | 29800 | 25390 | 328 | 121100 | 163939 | 198220 | 100.0 | - | - | - |
| 16 | stunnel | 6.07 (-59%) | 12088 (-59%) | 1420 (-94%) | 1130 (+245%) | 2520 (-98%) | 3127 (-98%) | 4920 (-98%) | 100.0 (+0%) | - | 199.0 | 8.3 |
| 16 | haproxy | 8.88 (-39%) | 18068 (-39%) | 910 (-96%) | 796 (+143%) | 1380 (-99%) | 1699 (-99%) | 2930 (-99%) | 100.0 (+0%) | - | 143.7 | 119.0 |
| 16 | nginx stream (TLS) | 9.76 (-33%) | 19913 (-33%) | 808 (-97%) | 740 (+126%) | 1160 (-99%) | 1341 (-99%) | 2140 (-99%) | 100.0 (+0%) | - | 126.9 | 48.3 |
| 16 | nginx http (TLS) | 8.80 (-40%) | 17900 (-40%) | 910 (-96%) | 817 (+149%) | 1310 (-99%) | 1549 (-99%) | 2490 (-99%) | 100.0 (+0%) | - | 178.9 | 49.8 |
| 16 | rats-tls | 9.12 (-38%) | 18678 (-37%) | 860 (-97%) | 825 (+152%) | 1150 (-99%) | 1249 (-99%) | 1680 (-99%) | 100.0 (+0%) | - | 101.7 | 43.3 |
| 16 | rats-tls+mux | 5.87 (-60%) | 11688 (-61%) | 1560 (-94%) | 1310 (+299%) | 1810 (-99%) | 2184 (-99%) | 10110 (-95%) | 100.0 (+0%) | - | 100.7 | 59.3 |
| 16 | ohttp | 4.36 (-70%) | 8686 (-71%) | 1840 (-93%) | 1720 (+424%) | 2700 (-98%) | 3026 (-98%) | 3760 (-98%) | 100.0 (+0%) | - | 209.1 | 52.2 |
| 32 | raw | 14.64 | 29807 | 32390 | 668 | 139830 | 173346 | 200140 | 100.0 | - | - | - |
| 32 | stunnel | 5.59 (-62%) | 11139 (-63%) | 3150 (-90%) | 2620 (+292%) | 5360 (-96%) | 6632 (-96%) | 12720 (-94%) | 100.0 (+0%) | - | 169.4 | 9.7 |
| 32 | haproxy | 9.92 (-32%) | 20251 (-32%) | 1790 (-94%) | 1320 (+98%) | 3200 (-98%) | 4613 (-97%) | 9150 (-95%) | 100.0 (+0%) | - | 163.1 | 117.8 |
| 32 | nginx stream (TLS) | 11.52 (-21%) | 23453 (-21%) | 1420 (-96%) | 1200 (+80%) | 2220 (-98%) | 2812 (-98%) | 5200 (-97%) | 100.0 (+0%) | - | 146.8 | 49.7 |
| 32 | nginx http (TLS) | 10.48 (-28%) | 21301 (-29%) | 1560 (-95%) | 1320 (+98%) | 2600 (-98%) | 3270 (-98%) | 5260 (-97%) | 100.0 (+0%) | - | 189.5 | 50.4 |
| 32 | rats-tls | 9.84 (-33%) | 20115 (-33%) | 1600 (-95%) | 1510 (+126%) | 2280 (-98%) | 2491 (-99%) | 4110 (-98%) | 100.0 (+0%) | - | 106.1 | 49.1 |
| 32 | rats-tls+mux | 6.64 (-55%) | 13229 (-56%) | 2720 (-92%) | 2310 (+246%) | 3420 (-98%) | 4015 (-98%) | 19150 (-90%) | 100.0 (+0%) | - | 99.7 | 83.4 |
| 32 | ohttp | 5.24 (-64%) | 10446 (-65%) | 3060 (-91%) | 2880 (+331%) | 4430 (-97%) | 5025 (-97%) | 6480 (-97%) | 100.0 (+0%) | - | 238.9 | 62.8 |
| 64 | raw | 4.78 | 9513 | 7970 | 7450 | 10140 | 11190 | 62420 | 100.0 | - | - | - |
| 64 | stunnel | 5.30 (+11%) | 10562 (+11%) | 6330 (-21%) | 5760 (-23%) | 10110 (-0%) | 11849 (+6%) | 18980 (-70%) | 100.0 (+0%) | - | 74.3 | 12.3 |
| 64 | haproxy | 5.60 (+17%) | 11151 (+17%) | 5930 (-26%) | 5600 (-25%) | 11510 (+14%) | 13237 (+18%) | 15880 (-75%) | 100.0 (+0%) | - | 60.5 | 120.7 |
| 64 | nginx stream (TLS) | 5.43 (+14%) | 10825 (+14%) | 6050 (-24%) | 5860 (-21%) | 11520 (+14%) | 13207 (+18%) | 15650 (-75%) | 100.0 (+0%) | - | 50.8 | 52.5 |
| 64 | nginx http (TLS) | 5.16 (+8%) | 10278 (+8%) | 6330 (-21%) | 6140 (-18%) | 11770 (+16%) | 13438 (+20%) | 15730 (-75%) | 100.0 (+0%) | - | 70.3 | 51.5 |
| 64 | rats-tls | 8.08 (+69%) | 16548 (+74%) | 4120 (-48%) | 3130 (-58%) | 8310 (-18%) | 10222 (-9%) | 13520 (-78%) | 100.0 (+0%) | - | 52.2 | 52.1 |
| 64 | rats-tls+mux | 5.93 (+24%) | 11809 (+24%) | 5430 (-32%) | 4980 (-33%) | 8160 (-20%) | 8280 (-26%) | 9350 (-85%) | 100.0 (+0%) | - | 101.5 | 93.2 |
| 64 | ohttp | 5.57 (+17%) | 11105 (+17%) | 5780 (-27%) | 5460 (-27%) | 8260 (-19%) | 9429 (-16%) | 12210 (-80%) | 100.0 (+0%) | - | 191.5 | 78.8 |
| 128 | raw | 5.50 | 10948 | 13160 | 10970 | 25090 | 29726 | 41190 | 100.0 | - | - | - |
| 128 | stunnel | 4.67 (-15%) | 9308 (-15%) | 14540 (+10%) | 12500 (+14%) | 26870 (+7%) | 30850 (+4%) | 39050 (-5%) | 100.0 (+0%) | - | 72.9 | 16.8 |
| 128 | haproxy | 5.59 (+2%) | 11136 (+2%) | 12250 (-7%) | 10820 (-1%) | 25280 (+1%) | 29684 (-0%) | 37070 (-10%) | 100.0 (+0%) | - | 61.3 | 122.3 |
| 128 | nginx stream (TLS) | 5.36 (-3%) | 10684 (-2%) | 12630 (-4%) | 11060 (+1%) | 25810 (+3%) | 30134 (+1%) | 37050 (-10%) | 100.0 (+0%) | - | 49.9 | 56.9 |
| 128 | nginx http (TLS) | 5.34 (-3%) | 10630 (-3%) | 12660 (-4%) | 10900 (-1%) | 25470 (+2%) | 30110 (+1%) | 36510 (-11%) | 100.0 (+0%) | - | 66.9 | 54.2 |
| 128 | rats-tls | 5.43 (-1%) | 10823 (-1%) | 12480 (-5%) | 10090 (-8%) | 25450 (+1%) | 29534 (-1%) | 36990 (-10%) | 100.0 (+0%) | - | 54.2 | 59.6 |
| 128 | rats-tls+mux | 5.61 (+2%) | 11174 (+2%) | 11420 (-13%) | 11180 (+2%) | 16040 (-36%) | 21205 (-29%) | 23050 (-44%) | 100.0 (+0%) | - | 92.1 | 111.9 |
| 128 | ohttp | 5.72 (+4%) | 11384 (+4%) | 11330 (-14%) | 10610 (-3%) | 16670 (-34%) | 19388 (-35%) | 26970 (-35%) | 100.0 (+0%) | - | 199.9 | 99.9 |

### 场景 C - HTTP / wrk，64 KiB 响应体，无 keep-alive

![场景 C：RPS、p95 延迟、出口 CPU 与出口内存随短连接并发度的变化](performance/scenario_c.svg)

wrk 发送 `Connection: close`，每个请求都要支付新建 TCP 连接与完整 TLS 握手（对三种 TNG 配置还包括证明与验证）。

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Egress CPU % | Egress Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 1.64 | 3261 | 214 | 209 | 246 | 259 | 289 | 100.0 | - | - | - |
| 1 | stunnel | 0.25 (-85%) | 492 (-85%) | 1970 (+821%) | 1960 (+838%) | 2070 (+741%) | 2110 (+715%) | 2240 (+675%) | 100.0 (+0%) | - | 46.8 | 6.9 |
| 1 | haproxy | 0.33 (-80%) | 665 (-80%) | 1430 (+568%) | 1420 (+579%) | 1500 (+510%) | 1530 (+491%) | 1730 (+499%) | 100.0 (+0%) | - | 43.1 | 127.5 |
| 1 | nginx stream (TLS) | 0.33 (-80%) | 656 (-80%) | 1490 (+596%) | 1480 (+608%) | 1580 (+542%) | 1631 (+530%) | 1770 (+512%) | 100.0 (+0%) | - | 39.9 | 47.0 |
| 1 | nginx http (TLS) | 0.32 (-80%) | 643 (-80%) | 1520 (+610%) | 1500 (+618%) | 1620 (+559%) | 1675 (+547%) | 1830 (+533%) | 100.0 (+0%) | - | 38.9 | 49.1 |
| 1 | rats-tls | 0.50 (-70%) | 992 (-70%) | 970 (+353%) | 970 (+364%) | 1030 (+319%) | 1062 (+310%) | 1130 (+291%) | 100.0 (+0%) | - | 42.3 | 41.7 |
| 1 | rats-tls+mux | 0.48 (-71%) | 946 (-71%) | 1030 (+381%) | 990 (+374%) | 1120 (+355%) | 1208 (+366%) | 1650 (+471%) | 100.0 (+0%) | - | 62.6 | 41.2 |
| 1 | ohttp | 0.53 (-68%) | 1048 (-68%) | 930 (+335%) | 920 (+340%) | 990 (+302%) | 1018 (+293%) | 1110 (+284%) | 100.0 (+0%) | - | 53.8 | 40.5 |
| 8 | raw | 8.08 | 16506 | 341 | 321 | 449 | 506 | 682 | 100.0 | - | - | - |
| 8 | stunnel | 0.81 (-90%) | 1612 (-90%) | 4920 (+1343%) | 4770 (+1386%) | 6190 (+1279%) | 6678 (+1220%) | 7970 (+1069%) | 100.0 (+0%) | - | 228.8 | 7.8 |
| 8 | haproxy | 1.36 (-83%) | 2702 (-84%) | 2910 (+753%) | 2810 (+775%) | 3750 (+735%) | 4116 (+713%) | 4960 (+627%) | 100.0 (+0%) | - | 193.7 | 117.7 |
| 8 | nginx stream (TLS) | 1.20 (-85%) | 2391 (-86%) | 3300 (+868%) | 3170 (+888%) | 4390 (+878%) | 4810 (+851%) | 5720 (+739%) | 100.0 (+0%) | - | 202.6 | 48.2 |
| 8 | nginx http (TLS) | 1.20 (-85%) | 2397 (-85%) | 3290 (+865%) | 3180 (+891%) | 4330 (+864%) | 4735 (+836%) | 5610 (+723%) | 100.0 (+0%) | - | 191.9 | 49.8 |
| 8 | rats-tls | 2.10 (-74%) | 4192 (-75%) | 1870 (+448%) | 1810 (+464%) | 2270 (+406%) | 2491 (+392%) | 3120 (+357%) | 100.0 (+0%) | - | 201.5 | 42.2 |
| 8 | rats-tls+mux | 2.25 (-72%) | 4473 (-73%) | 1760 (+416%) | 1720 (+436%) | 2130 (+374%) | 2271 (+349%) | 2720 (+299%) | 100.0 (+0%) | - | 167.4 | 43.1 |
| 8 | ohttp | 2.50 (-69%) | 4983 (-70%) | 1570 (+360%) | 1480 (+361%) | 2090 (+365%) | 2335 (+361%) | 2870 (+321%) | 100.0 (+0%) | - | 202.4 | 44.2 |
| 16 | raw | 11.92 | 24384 | 453 | 414 | 646 | 759 | 1090 | 100.0 | - | - | - |
| 16 | stunnel | 0.86 (-93%) | 1713 (-93%) | 9290 (+1951%) | 9030 (+2081%) | 12310 (+1806%) | 13405 (+1666%) | 15740 (+1344%) | 100.0 (+0%) | - | 262.3 | 8.8 |
| 16 | haproxy | 1.61 (-86%) | 3207 (-87%) | 4960 (+995%) | 4590 (+1009%) | 7160 (+1008%) | 8313 (+995%) | 11130 (+921%) | 100.0 (+0%) | - | 224.1 | 118.3 |
| 16 | nginx stream (TLS) | 1.46 (-88%) | 2902 (-88%) | 5470 (+1108%) | 5210 (+1158%) | 7780 (+1104%) | 8726 (+1050%) | 10870 (+897%) | 100.0 (+0%) | - | 250.4 | 48.5 |
| 16 | nginx http (TLS) | 1.47 (-88%) | 2928 (-88%) | 5410 (+1094%) | 5160 (+1146%) | 7710 (+1093%) | 8628 (+1037%) | 10590 (+872%) | 100.0 (+0%) | - | 239.7 | 50.4 |
| 16 | rats-tls | 2.43 (-80%) | 4841 (-80%) | 3250 (+617%) | 3170 (+666%) | 4150 (+542%) | 4556 (+500%) | 5800 (+432%) | 100.0 (+0%) | - | 220.8 | 44.7 |
| 16 | rats-tls+mux | 3.11 (-74%) | 6205 (-75%) | 2530 (+458%) | 2470 (+497%) | 3200 (+395%) | 3453 (+355%) | 4070 (+273%) | 100.0 (+0%) | - | 180.0 | 54.6 |
| 16 | ohttp | 3.15 (-74%) | 6272 (-74%) | 2510 (+454%) | 2380 (+475%) | 3470 (+437%) | 3899 (+414%) | 4930 (+352%) | 100.0 (+0%) | - | 232.3 | 47.2 |
| 32 | raw | 14.56 | 29676 | 4710 | 602 | 1160 | 1846 | 154640 | 100.0 | - | - | - |
| 32 | stunnel | 0.85 (-94%) | 1695 (-94%) | 18810 (+299%) | 18360 (+2950%) | 25500 (+2098%) | 27779 (+1405%) | 33310 (-78%) | 100.0 (+0%) | - | 263.2 | 10.8 |
| 32 | haproxy | 1.72 (-88%) | 3417 (-88%) | 9340 (+98%) | 8460 (+1305%) | 14200 (+1124%) | 17226 (+833%) | 22310 (-86%) | 100.0 (+0%) | - | 236.7 | 119.6 |
| 32 | nginx stream (TLS) | 1.60 (-89%) | 3193 (-89%) | 10010 (+113%) | 9230 (+1433%) | 15090 (+1201%) | 17772 (+863%) | 22980 (-85%) | 100.0 (+0%) | - | 259.4 | 49.6 |
| 32 | nginx http (TLS) | 1.63 (-89%) | 3245 (-89%) | 9820 (+108%) | 9150 (+1420%) | 14650 (+1163%) | 16946 (+818%) | 22090 (-86%) | 100.0 (+0%) | - | 256.8 | 50.8 |
| 32 | rats-tls | 2.55 (-82%) | 5073 (-83%) | 6220 (+32%) | 6160 (+923%) | 7900 (+581%) | 8542 (+363%) | 10200 (-93%) | 100.0 (+0%) | - | 225.9 | 49.7 |
| 32 | rats-tls+mux | 3.81 (-74%) | 7592 (-74%) | 4140 (-12%) | 4040 (+571%) | 5380 (+364%) | 5857 (+217%) | 6820 (-96%) | 100.0 (+0%) | - | 190.5 | 54.0 |
| 32 | ohttp | 3.47 (-76%) | 6910 (-77%) | 4580 (-3%) | 4410 (+633%) | 6150 (+430%) | 6816 (+269%) | 8370 (-95%) | 100.0 (+0%) | - | 246.7 | 50.6 |
| 64 | raw | 14.56 | 29670 | 16840 | 702 | 74070 | 141266 | 195060 | 100.0 | - | - | - |
| 64 | stunnel | 0.88 (-94%) | 1761 (-94%) | 36180 (+115%) | 35320 (+4931%) | 49220 (-34%) | 53616 (-62%) | 63330 (-68%) | 100.0 (+0%) | - | 287.7 | 14.3 |
| 64 | haproxy | 1.86 (-87%) | 3702 (-88%) | 17090 (+1%) | 16450 (+2243%) | 23940 (-68%) | 27167 (-81%) | 34380 (-82%) | 100.0 (+0%) | - | 252.4 | 121.8 |
| 64 | nginx stream (TLS) | 1.78 (-88%) | 3542 (-88%) | 17930 (+6%) | 16850 (+2300%) | 26310 (-64%) | 29855 (-79%) | 37490 (-81%) | 100.0 (+0%) | - | 270.0 | 51.5 |
| 64 | nginx http (TLS) | 1.81 (-88%) | 3608 (-88%) | 17600 (+5%) | 16920 (+2310%) | 25170 (-66%) | 28311 (-80%) | 36010 (-82%) | 100.0 (+0%) | - | 269.8 | 51.6 |
| 64 | rats-tls | 2.50 (-83%) | 4975 (-83%) | 12720 (-24%) | 12650 (+1702%) | 16219 (-78%) | 17385 (-88%) | 19900 (-90%) | 100.0 (+0%) | - | 216.3 | 74.5 |
| 64 | rats-tls+mux | 4.32 (-70%) | 8600 (-71%) | 7320 (-57%) | 7120 (+914%) | 9600 (-87%) | 10459 (-93%) | 12190 (-94%) | 100.0 (+0%) | - | 184.6 | 88.2 |
| 64 | ohttp | 3.58 (-75%) | 7140 (-76%) | 8900 (-47%) | 8650 (+1132%) | 11870 (-84%) | 13029 (-91%) | 15600 (-92%) | 100.0 (+0%) | - | 250.1 | 55.3 |
| 128 | raw | 14.56 | 29693 | 8290 | 2110 | 3700 | 32294 | 175190 | 100.0 | - | - | - |
| 128 | stunnel | 0.89 (-94%) | 1767 (-94%) | 72090 (+770%) | 70670 (+3249%) | 95330 (+2476%) | 103395 (+220%) | 122620 (-30%) | 100.0 (+0%) | - | 306.5 | 20.2 |
| 128 | haproxy | 1.94 (-87%) | 3859 (-87%) | 32680 (+294%) | 32330 (+1432%) | 41380 (+1018%) | 44734 (+39%) | 54280 (-69%) | 100.0 (+0%) | - | 263.2 | 126.9 |
| 128 | nginx stream (TLS) | 1.89 (-87%) | 3773 (-87%) | 33490 (+304%) | 33130 (+1470%) | 42660 (+1053%) | 46284 (+43%) | 53700 (-69%) | 100.0 (+0%) | - | 279.4 | 51.9 |
| 128 | nginx http (TLS) | 1.90 (-87%) | 3792 (-87%) | 33340 (+302%) | 32920 (+1460%) | 41580 (+1024%) | 45163 (+40%) | 53170 (-70%) | 100.0 (+0%) | - | 276.9 | 52.1 |
| 128 | rats-tls | 2.53 (-83%) | 5044 (-83%) | 25230 (+204%) | 24890 (+1080%) | 32680 (+783%) | 35378 (+10%) | 41410 (-76%) | 100.0 (+0%) | - | 216.2 | 88.2 |
| 128 | rats-tls+mux | 4.67 (-68%) | 9298 (-69%) | 13580 (+64%) | 13250 (+528%) | 17620 (+376%) | 19093 (-41%) | 22080 (-87%) | 100.0 (+0%) | - | 177.5 | 221.1 |
| 128 | ohttp | 3.71 (-75%) | 7392 (-75%) | 17240 (+108%) | 16850 (+699%) | 23390 (+532%) | 25683 (-20%) | 30390 (-83%) | 100.0 (+0%) | - | 248.0 | 67.4 |

## 更新规则

性能 PR 在最终阶段于同一 PR 内重新生成本页及 [`docs/performance/`](performance/) 下的三张图：表格与嵌入报告取最终实测矩阵实验臂的 `bash bench/gen-report.sh <server-info> <client-info> <results>` 单次模式输出，图取同一输入下 `python3 bench/gen-svg.py` 的输出。快照始终保持当前版本的单次运行视图，对比表格不放进本页。该规则已写入 [`bench/performance-pr-requirements.md`](../bench/performance-pr-requirements.md)。

## 完整单次报告

<details>
<summary>Full single-run benchmark report (tng 2.12.0, source revision f069033ff41157d7567e553cf116adedeb097432)</summary>

---

# TNG Two-Host Benchmark Report

## Benchmark setup

1. **Test Environment**

<details>
<summary>Full test environment</summary>

| Item | Value |
| --- | --- |
| Client host | client/load host |
| Client kernel | Linux 5.10.134-19.8.al8.x86_64 #1 SMP Fri Jul 17 15:13:51 CST 2026 x86_64 x86_64 x86_64 GNU/Linux |
| Client CPU | 06/cf (4 vCPU) |
| Client memory | 14825640 kB |
| Server host | server/backend host |
| Server kernel | Linux 5.10.134-19.8.al8.x86_64 #1 SMP Fri Jul 17 15:13:51 CST 2026 x86_64 x86_64 x86_64 GNU/Linux |
| Server CPU | 06/cf (4 vCPU) |
| Server memory | 14825632 kB |
| Client TNG | tng 2.12.0 |
| Client TNG source revision | f069033ff41157d7567e553cf116adedeb097432 |
| Server TNG | tng 2.12.0 |
| Server TNG source revision | f069033ff41157d7567e553cf116adedeb097432 |
| Container runtime | podman version 4.9.4-rhel |
| Link | eth0: client/load host &lt;-&gt; server/backend host |

</details>


2. **Test Conditions**

<details>
<summary>Full test conditions</summary>

| Item | Value |
| --- | --- |
| TNG ingress/egress mode | mapping |
| Remote attestation | enabled (no_ra=false) |
| Attest (egress/server) | aa_type=uds, aa_addr=unix:///run/confidential-containers/attestation-agent/attestation-agent.sock |
| Verify (ingress/client) | as_type=builtin, attestation_policy=hardware_only |
| Load containers | --network host |
| iperf3 streams | 1,8,16,32,64,128 |
| iperf3 duration / rounds / len | 15s / 3 / 131072 bytes |
| wrk connections | 1,8,16,32,64,128 |
| wrk duration / rounds / threads | 15s / 3 / auto |
| HTTP body size | 64 KiB |
| HTTP scenarios measured | keep-alive (B) + no keep-alive (C) |
| Result per point | strongest of N rounds (highest request rate) |
| Client parameter: attest_aa_addr | unix:///run/confidential-containers/attestation-agent/attestation-agent.sock |
| Client parameter: attest_aa_type | uds |
| Client parameter: http_body_kb | 64 |
| Client parameter: iperf_duration | 15 |
| Client parameter: iperf_len | 131072 |
| Client parameter: iperf_rounds | 3 |
| Client parameter: iperf_streams | 1,8,16,32,64,128 |
| Client parameter: mux_max_streams | unset |
| Client parameter: no_ra | false |
| Client parameter: ra_mode | 1 |
| Client parameter: server_ip | [redacted endpoint] |
| Client parameter: tng_mode | mapping |
| Client parameter: verify_as_type | builtin |
| Client parameter: verify_attestation_policy | hardware_only |
| Client parameter: wrk_conns | 1,8,16,32,64,128 |
| Client parameter: wrk_duration | 15 |
| Client parameter: wrk_rounds | 3 |
| Client parameter: wrk_threads | auto |
| Client parameter: wrk_warmup | 1 |
| Client configuration: config SHA-256 | bb2e2b194f11f6dc309e43d93e61ad62b499b278b754fc1bbe4e5b6fe3a58473 |
| Server parameter: attest_aa_addr | unix:///run/confidential-containers/attestation-agent/attestation-agent.sock |
| Server parameter: attest_aa_type | uds |
| Server parameter: http_body_kb | 64 |
| Server parameter: iperf_duration | 15 |
| Server parameter: iperf_len | 131072 |
| Server parameter: iperf_rounds | 3 |
| Server parameter: iperf_streams | 1,8,16,32,64,128 |
| Server parameter: mux_max_streams | unset |
| Server parameter: no_ra | false |
| Server parameter: ra_mode | 1 |
| Server parameter: server_ip | [redacted endpoint] |
| Server parameter: tng_mode | mapping |
| Server parameter: verify_as_type | builtin |
| Server parameter: verify_attestation_policy | hardware_only |
| Server parameter: wrk_conns | 1,8,16,32,64,128 |
| Server parameter: wrk_duration | 15 |
| Server parameter: wrk_rounds | 3 |
| Server parameter: wrk_threads | auto |
| Server parameter: wrk_warmup | 1 |
| Server configuration: config SHA-256 | 5c0c6fde7659a421bff24fa67e495debacaaa9f5b81297a579017af7b36defad |

</details>


3. **Test Tool Versions**

<details>
<summary>Full test tool versions</summary>

| Tool | Image (resolved) | Source | Version | Digest |
| --- | --- | --- | --- | --- |
| Client iperf3 | mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest | mirror | iperf 3.21 (cJSON 1.7.15) | sha256:02d3da1562e94beeb935d50df7231da9bb3cfe0e37b7c21fe64e0babec67c3c9 |
| Client nginx | mirrors-ssl.aliyuncs.com/library/nginx:stable-alpine | mirror | nginx version: nginx/1.30.6 | sha256:effd88ccefa855aa6417d1af45fdfadcd808b5a8923bff507d8be3c7ca145bb7 |
| Client wrk | mirrors-ssl.aliyuncs.com/ghcr.io/william-yeh/wrk:latest | mirror | wrk  [epoll] Copyright (C) 2012 Will Glozer | sha256:8aeaa2c883aa571ccf25eb618cfe75700f06f6947a885d549f7a4d524276bb41 |
| Client stunnel | mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest | mirror | stunnel 5.82 on x86_64-alpine-linux-musl platform | sha256:5659c54dbabcd7aeff70f28f956ee8baf816cdb206f26f5bf54de352de27bca9 |
| Client haproxy | mirrors-ssl.aliyuncs.com/library/haproxy:latest | mirror | HAProxy version 3.4.7-8872a26 2026/10/14 - https://haproxy.org/ | sha256:f859857d1fc551d2c9a80500ae322b00455c0ca506c0eaad52ee88083b55484b |
| Server iperf3 | mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest | mirror | iperf 3.21 (cJSON 1.7.15) | sha256:02d3da1562e94beeb935d50df7231da9bb3cfe0e37b7c21fe64e0babec67c3c9 |
| Server nginx | mirrors-ssl.aliyuncs.com/library/nginx:stable-alpine | mirror | nginx version: nginx/1.30.6 | sha256:effd88ccefa855aa6417d1af45fdfadcd808b5a8923bff507d8be3c7ca145bb7 |
| Server wrk |  |  |  |  |
| Server stunnel | mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest | mirror | stunnel 5.82 on x86_64-alpine-linux-musl platform | sha256:5659c54dbabcd7aeff70f28f956ee8baf816cdb206f26f5bf54de352de27bca9 |
| Server haproxy | mirrors-ssl.aliyuncs.com/library/haproxy:latest | mirror | HAProxy version 3.4.7-8872a26 2026/10/14 - https://haproxy.org/ | sha256:f859857d1fc551d2c9a80500ae322b00455c0ca506c0eaad52ee88083b55484b |

</details>

4. **Test Methodology**

<details>
<summary>Test methodology and metric definitions</summary>

**Topology and tunnel modes**

- Two hosts communicate over eth0: a client/load host runs TNG ingress and load generators; a server/backend host runs TNG egress, iperf3, nginx and TLS-proxy reference backends.
- TNG uses five mapping entries (ingress 50001–50005, egress 40001–40005). Load tools use host-network containers; TNG runs as a host executable. Protocol modes and attestation settings are recorded in Test Conditions.

**Workloads and run parameters**

- Scenario A measures TCP throughput with iperf3 parallel streams (`-P`). Scenario B measures HTTP/wrk persistent connections; Scenario C sends `Connection: close` for fresh client connections. Actual concurrency, body size, duration, warmup and round counts appear in Test Conditions.
- Each workload/concurrency point runs the recorded number of rounds; the cell takes the strongest round (highest request rate) with all of its metrics, so a round that catches a cold-start race cannot pollute the cell. CPU samples use the final round and memory samples span every measured round, as described below. Keep-alive and no-keep-alive are separate scenarios, not interchangeable workloads.

**HTTP latency and success metrics**

- wrk runs with `--latency`: p50/p90/p99 come from its reported distribution; p95 is obtained by the Lua `latency:percentile(95)` callback. Mean is wrk's Thread Stats average.
- Success rate is `(completed requests - non-2xx) / (completed requests + socket errors)`. Unchanged success rates are classified as stable, not improved. Any decline must still be investigated even within the display tolerance.

**Resource sampling and units**

- CPU columns are one-second pidstat windows averaged over the final measured round. Memory columns are the peak RSS under load: `/proc/<pid>/status` VmRSS, summed over the sampled PID set at 1 Hz in parallel with every measured round, reported as the maximum of those samples. Windowed RSS averages mixed the load ramp into the plateau and were bistable run-to-run; the peak answers how much memory serving the workload needs.
- Every workload with a proxy or tunnel process (TNG ingress/egress pair, stunnel, HAProxy, nginx) is measured on a freshly restarted process set: before each cell's warmup and measured rounds the harness stops that workload's processes, verifies the old PIDs and listen ports are released, relaunches the same binary or container with the same config, and waits for the listening ports to be ready. Samplers find processes by listen port, so they always measure the post-restart PIDs. Each cell's memory peak is therefore that cell's own cost, not allocator high-water carried from earlier cells of the pass. Raw reference rows have no proxy process and nothing to restart.
- TCP Ingress CPU/Mem columns sample the ingress instance: the client-side instance of the measured gateway/tunnel (TNG ingress for the TNG workloads). The legacy `Ingress Mem (GB)` label stores the peak VmRSS KiB divided by 1024² (GiB).
- HTTP Egress CPU/Mem columns sample the egress instance: the server-side instance of the measured gateway/proxy (TNG egress, HAProxy, or the stunnel or nginx server container), via `pidstat -u -p <PIDs> 1 <duration>` Average rows for CPU. HAProxy sums master and workers; nginx sums every process holding the proxy's listen port (master + all workers, found via `ss`). CPU sums threads/processes (100% = one logical core); the peak RSS sums the same PID set and is converted from KiB to MiB.
- The HTTP Ingress CPU % column samples the client-side TNG ingress process with the same pidstat method; datasets whose driver did not record it render '-' in the column and exclude it from the counts.
- Raw reference rows have no tunnel process, so their resource fields are structurally uncollected.

**Comparison and classification**

- Before/after rows compare identical workload and concurrency keys. Parenthesized values compare with the displayed baseline-run raw row; colored markers and classification counts compare with the before row. The exact thresholds and counting scope remain visible beside each result table.
- Classification is based on unrounded recorded metrics. Count (%) measures metric-cell frequency, not statistical confidence or importance. Reference-run drift is reported separately; attribution and acceptance decisions require review.

</details>


## Results

### Scenario A - iperf3 (TCP throughput)

<details>
<summary>Full Scenario A results</summary>

| Streams | Workload | Throughput (Gbps) | Ingress CPU % | Ingress Mem (GB) |
| --- | --- | --- | --- | --- |
| 1 | raw | 15.71 | - | - |
| 1 | stunnel | 10.41 (-34%) | 81.4 | 0.007 |
| 1 | haproxy | 10.01 (-36%) | 55.1 | 0.088 |
| 1 | nginx stream (TLS) | 11.76 (-25%) | 72.3 | 0.046 |
| 1 | rats-tls | 9.07 (-42%) | 39.8 | 0.047 |
| 1 | rats-tls+mux | 9.56 (-39%) | 94.5 | 0.052 |
| 8 | raw | 15.72 | - | - |
| 8 | stunnel | 14.20 (-10%) | 229.4 | 0.008 |
| 8 | haproxy | 15.73 (+0%) | 116.8 | 0.087 |
| 8 | nginx stream (TLS) | 15.74 (+0%) | 107.4 | 0.046 |
| 8 | rats-tls | 15.74 (+0%) | 81.5 | 0.054 |
| 8 | rats-tls+mux | 12.04 (-23%) | 139.3 | 0.076 |
| 16 | raw | 15.73 | - | - |
| 16 | stunnel | 13.52 (-14%) | 237.4 | 0.009 |
| 16 | haproxy | 15.76 (+0%) | 108.9 | 0.088 |
| 16 | nginx stream (TLS) | 4.31 (-73%) | 23.7 | 0.047 |
| 16 | rats-tls | 15.79 (+0%) | 90.1 | 0.060 |
| 16 | rats-tls+mux | 10.58 (-33%) | 115.5 | 0.107 |
| 32 | raw | 4.24 | - | - |
| 32 | stunnel | 4.38 (+3%) | 52.4 | 0.009 |
| 32 | haproxy | 4.40 (+4%) | 29.2 | 0.089 |
| 32 | nginx stream (TLS) | 4.40 (+4%) | 26.2 | 0.049 |
| 32 | rats-tls | 4.41 (+4%) | 21.9 | 0.076 |
| 32 | rats-tls+mux | 4.40 (+4%) | 48.5 | 0.155 |
| 64 | raw | 4.25 | - | - |
| 64 | stunnel | 4.55 (+7%) | 55.5 | 0.011 |
| 64 | haproxy | 4.56 (+7%) | 31.2 | 0.091 |
| 64 | nginx stream (TLS) | 4.56 (+7%) | 28.9 | 0.051 |
| 64 | rats-tls | 4.57 (+8%) | 24.2 | 0.114 |
| 64 | rats-tls+mux | 4.60 (+8%) | 41.5 | 0.244 |
| 128 | raw | 4.25 | - | - |
| 128 | stunnel | 4.63 (+9%) | 62.9 | 0.016 |
| 128 | haproxy | 4.70 (+11%) | 32.9 | 0.097 |
| 128 | nginx stream (TLS) | 4.64 (+9%) | 31.7 | 0.058 |
| 128 | rats-tls | 4.69 (+10%) | 29.0 | 0.151 |
| 128 | rats-tls+mux | 4.85 (+14%) | 43.2 | 0.381 |

</details>


### Scenario B - HTTP / wrk (64 KiB body, keep-alive)

<details>
<summary>Full scenario results</summary>

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Egress CPU % | Egress Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 2.31 | 4602 | 230 | 204 | 266 | 446 | 800 | 100.0 | - | - | - |
| 1 | stunnel | 1.62 (-30%) | 3219 (-30%) | 317 (+38%) | 302 (+48%) | 355 (+33%) | 377 (-15%) | 570 (-29%) | 100.0 (+0%) | - | 24.6 | 6.8 |
| 1 | haproxy | 1.77 (-23%) | 3518 (-24%) | 289 (+26%) | 277 (+36%) | 326 (+23%) | 344 (-23%) | 411 (-49%) | 100.0 (+0%) | - | 23.3 | 124.1 |
| 1 | nginx stream (TLS) | 1.67 (-28%) | 3323 (-28%) | 307 (+33%) | 292 (+43%) | 345 (+30%) | 366 (-18%) | 690 (-14%) | 100.0 (+0%) | - | 23.1 | 46.7 |
| 1 | nginx http (TLS) | 1.54 (-33%) | 3059 (-34%) | 332 (+44%) | 320 (+57%) | 365 (+37%) | 385 (-14%) | 593 (-26%) | 100.0 (+0%) | - | 31.1 | 48.8 |
| 1 | rats-tls | 1.30 (-44%) | 2593 (-44%) | 511 (+122%) | 362 (+77%) | 433 (+63%) | 790 (+77%) | 1380 (+72%) | 100.0 (+0%) | - | 15.7 | 39.9 |
| 1 | rats-tls+mux | 0.77 (-67%) | 1525 (-67%) | 698 (+203%) | 645 (+216%) | 716 (+169%) | 741 (+66%) | 1460 (+82%) | 100.0 (+0%) | - | 34.8 | 39.9 |
| 1 | ohttp | 0.73 (-68%) | 1456 (-68%) | 698 (+203%) | 678 (+232%) | 750 (+182%) | 776 (+74%) | 850 (+6%) | 100.0 (+0%) | - | 46.1 | 40.8 |
| 8 | raw | 13.04 | 26601 | 778 | 258 | 485 | 2214 | 15920 | 100.0 | - | - | - |
| 8 | stunnel | 6.66 (-49%) | 13260 (-50%) | 627 (-19%) | 564 (+119%) | 836 (+72%) | 955 (-57%) | 2009 (-87%) | 100.0 (+0%) | - | 125.9 | 7.4 |
| 8 | haproxy | 6.96 (-47%) | 14148 (-47%) | 572 (-26%) | 526 (+104%) | 779 (+61%) | 894 (-60%) | 1400 (-91%) | 100.0 (+0%) | - | 111.4 | 126.4 |
| 8 | nginx stream (TLS) | 7.20 (-45%) | 14754 (-45%) | 553 (-29%) | 511 (+98%) | 727 (+50%) | 825 (-63%) | 1270 (-92%) | 100.0 (+0%) | - | 92.1 | 47.3 |
| 8 | nginx http (TLS) | 6.77 (-48%) | 13496 (-49%) | 599 (-23%) | 560 (+117%) | 783 (+61%) | 880 (-60%) | 1280 (-92%) | 100.0 (+0%) | - | 140.3 | 49.4 |
| 8 | rats-tls | 7.28 (-44%) | 14869 (-44%) | 544 (-30%) | 522 (+102%) | 670 (+38%) | 725 (-67%) | 980 (-94%) | 100.0 (+0%) | - | 91.3 | 41.5 |
| 8 | rats-tls+mux | 4.20 (-68%) | 8374 (-69%) | 1460 (+88%) | 880 (+241%) | 1230 (+154%) | 2967 (+34%) | 20250 (+27%) | 100.0 (+0%) | - | 89.3 | 46.8 |
| 8 | ohttp | 3.45 (-74%) | 6880 (-74%) | 1160 (+49%) | 1100 (+326%) | 1540 (+218%) | 1701 (-23%) | 2110 (-87%) | 100.0 (+0%) | - | 176.7 | 46.2 |
| 16 | raw | 14.64 | 29800 | 25390 | 328 | 121100 | 163939 | 198220 | 100.0 | - | - | - |
| 16 | stunnel | 6.07 (-59%) | 12088 (-59%) | 1420 (-94%) | 1130 (+245%) | 2520 (-98%) | 3127 (-98%) | 4920 (-98%) | 100.0 (+0%) | - | 199.0 | 8.3 |
| 16 | haproxy | 8.88 (-39%) | 18068 (-39%) | 910 (-96%) | 796 (+143%) | 1380 (-99%) | 1699 (-99%) | 2930 (-99%) | 100.0 (+0%) | - | 143.7 | 119.0 |
| 16 | nginx stream (TLS) | 9.76 (-33%) | 19913 (-33%) | 808 (-97%) | 740 (+126%) | 1160 (-99%) | 1341 (-99%) | 2140 (-99%) | 100.0 (+0%) | - | 126.9 | 48.3 |
| 16 | nginx http (TLS) | 8.80 (-40%) | 17900 (-40%) | 910 (-96%) | 817 (+149%) | 1310 (-99%) | 1549 (-99%) | 2490 (-99%) | 100.0 (+0%) | - | 178.9 | 49.8 |
| 16 | rats-tls | 9.12 (-38%) | 18678 (-37%) | 860 (-97%) | 825 (+152%) | 1150 (-99%) | 1249 (-99%) | 1680 (-99%) | 100.0 (+0%) | - | 101.7 | 43.3 |
| 16 | rats-tls+mux | 5.87 (-60%) | 11688 (-61%) | 1560 (-94%) | 1310 (+299%) | 1810 (-99%) | 2184 (-99%) | 10110 (-95%) | 100.0 (+0%) | - | 100.7 | 59.3 |
| 16 | ohttp | 4.36 (-70%) | 8686 (-71%) | 1840 (-93%) | 1720 (+424%) | 2700 (-98%) | 3026 (-98%) | 3760 (-98%) | 100.0 (+0%) | - | 209.1 | 52.2 |
| 32 | raw | 14.64 | 29807 | 32390 | 668 | 139830 | 173346 | 200140 | 100.0 | - | - | - |
| 32 | stunnel | 5.59 (-62%) | 11139 (-63%) | 3150 (-90%) | 2620 (+292%) | 5360 (-96%) | 6632 (-96%) | 12720 (-94%) | 100.0 (+0%) | - | 169.4 | 9.7 |
| 32 | haproxy | 9.92 (-32%) | 20251 (-32%) | 1790 (-94%) | 1320 (+98%) | 3200 (-98%) | 4613 (-97%) | 9150 (-95%) | 100.0 (+0%) | - | 163.1 | 117.8 |
| 32 | nginx stream (TLS) | 11.52 (-21%) | 23453 (-21%) | 1420 (-96%) | 1200 (+80%) | 2220 (-98%) | 2812 (-98%) | 5200 (-97%) | 100.0 (+0%) | - | 146.8 | 49.7 |
| 32 | nginx http (TLS) | 10.48 (-28%) | 21301 (-29%) | 1560 (-95%) | 1320 (+98%) | 2600 (-98%) | 3270 (-98%) | 5260 (-97%) | 100.0 (+0%) | - | 189.5 | 50.4 |
| 32 | rats-tls | 9.84 (-33%) | 20115 (-33%) | 1600 (-95%) | 1510 (+126%) | 2280 (-98%) | 2491 (-99%) | 4110 (-98%) | 100.0 (+0%) | - | 106.1 | 49.1 |
| 32 | rats-tls+mux | 6.64 (-55%) | 13229 (-56%) | 2720 (-92%) | 2310 (+246%) | 3420 (-98%) | 4015 (-98%) | 19150 (-90%) | 100.0 (+0%) | - | 99.7 | 83.4 |
| 32 | ohttp | 5.24 (-64%) | 10446 (-65%) | 3060 (-91%) | 2880 (+331%) | 4430 (-97%) | 5025 (-97%) | 6480 (-97%) | 100.0 (+0%) | - | 238.9 | 62.8 |
| 64 | raw | 4.78 | 9513 | 7970 | 7450 | 10140 | 11190 | 62420 | 100.0 | - | - | - |
| 64 | stunnel | 5.30 (+11%) | 10562 (+11%) | 6330 (-21%) | 5760 (-23%) | 10110 (-0%) | 11849 (+6%) | 18980 (-70%) | 100.0 (+0%) | - | 74.3 | 12.3 |
| 64 | haproxy | 5.60 (+17%) | 11151 (+17%) | 5930 (-26%) | 5600 (-25%) | 11510 (+14%) | 13237 (+18%) | 15880 (-75%) | 100.0 (+0%) | - | 60.5 | 120.7 |
| 64 | nginx stream (TLS) | 5.43 (+14%) | 10825 (+14%) | 6050 (-24%) | 5860 (-21%) | 11520 (+14%) | 13207 (+18%) | 15650 (-75%) | 100.0 (+0%) | - | 50.8 | 52.5 |
| 64 | nginx http (TLS) | 5.16 (+8%) | 10278 (+8%) | 6330 (-21%) | 6140 (-18%) | 11770 (+16%) | 13438 (+20%) | 15730 (-75%) | 100.0 (+0%) | - | 70.3 | 51.5 |
| 64 | rats-tls | 8.08 (+69%) | 16548 (+74%) | 4120 (-48%) | 3130 (-58%) | 8310 (-18%) | 10222 (-9%) | 13520 (-78%) | 100.0 (+0%) | - | 52.2 | 52.1 |
| 64 | rats-tls+mux | 5.93 (+24%) | 11809 (+24%) | 5430 (-32%) | 4980 (-33%) | 8160 (-20%) | 8280 (-26%) | 9350 (-85%) | 100.0 (+0%) | - | 101.5 | 93.2 |
| 64 | ohttp | 5.57 (+17%) | 11105 (+17%) | 5780 (-27%) | 5460 (-27%) | 8260 (-19%) | 9429 (-16%) | 12210 (-80%) | 100.0 (+0%) | - | 191.5 | 78.8 |
| 128 | raw | 5.50 | 10948 | 13160 | 10970 | 25090 | 29726 | 41190 | 100.0 | - | - | - |
| 128 | stunnel | 4.67 (-15%) | 9308 (-15%) | 14540 (+10%) | 12500 (+14%) | 26870 (+7%) | 30850 (+4%) | 39050 (-5%) | 100.0 (+0%) | - | 72.9 | 16.8 |
| 128 | haproxy | 5.59 (+2%) | 11136 (+2%) | 12250 (-7%) | 10820 (-1%) | 25280 (+1%) | 29684 (-0%) | 37070 (-10%) | 100.0 (+0%) | - | 61.3 | 122.3 |
| 128 | nginx stream (TLS) | 5.36 (-3%) | 10684 (-2%) | 12630 (-4%) | 11060 (+1%) | 25810 (+3%) | 30134 (+1%) | 37050 (-10%) | 100.0 (+0%) | - | 49.9 | 56.9 |
| 128 | nginx http (TLS) | 5.34 (-3%) | 10630 (-3%) | 12660 (-4%) | 10900 (-1%) | 25470 (+2%) | 30110 (+1%) | 36510 (-11%) | 100.0 (+0%) | - | 66.9 | 54.2 |
| 128 | rats-tls | 5.43 (-1%) | 10823 (-1%) | 12480 (-5%) | 10090 (-8%) | 25450 (+1%) | 29534 (-1%) | 36990 (-10%) | 100.0 (+0%) | - | 54.2 | 59.6 |
| 128 | rats-tls+mux | 5.61 (+2%) | 11174 (+2%) | 11420 (-13%) | 11180 (+2%) | 16040 (-36%) | 21205 (-29%) | 23050 (-44%) | 100.0 (+0%) | - | 92.1 | 111.9 |
| 128 | ohttp | 5.72 (+4%) | 11384 (+4%) | 11330 (-14%) | 10610 (-3%) | 16670 (-34%) | 19388 (-35%) | 26970 (-35%) | 100.0 (+0%) | - | 199.9 | 99.9 |

</details>


### Scenario C - HTTP / wrk (64 KiB body, no keep-alive)

<details>
<summary>Full scenario results</summary>

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Egress CPU % | Egress Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 1.64 | 3261 | 214 | 209 | 246 | 259 | 289 | 100.0 | - | - | - |
| 1 | stunnel | 0.25 (-85%) | 492 (-85%) | 1970 (+821%) | 1960 (+838%) | 2070 (+741%) | 2110 (+715%) | 2240 (+675%) | 100.0 (+0%) | - | 46.8 | 6.9 |
| 1 | haproxy | 0.33 (-80%) | 665 (-80%) | 1430 (+568%) | 1420 (+579%) | 1500 (+510%) | 1530 (+491%) | 1730 (+499%) | 100.0 (+0%) | - | 43.1 | 127.5 |
| 1 | nginx stream (TLS) | 0.33 (-80%) | 656 (-80%) | 1490 (+596%) | 1480 (+608%) | 1580 (+542%) | 1631 (+530%) | 1770 (+512%) | 100.0 (+0%) | - | 39.9 | 47.0 |
| 1 | nginx http (TLS) | 0.32 (-80%) | 643 (-80%) | 1520 (+610%) | 1500 (+618%) | 1620 (+559%) | 1675 (+547%) | 1830 (+533%) | 100.0 (+0%) | - | 38.9 | 49.1 |
| 1 | rats-tls | 0.50 (-70%) | 992 (-70%) | 970 (+353%) | 970 (+364%) | 1030 (+319%) | 1062 (+310%) | 1130 (+291%) | 100.0 (+0%) | - | 42.3 | 41.7 |
| 1 | rats-tls+mux | 0.48 (-71%) | 946 (-71%) | 1030 (+381%) | 990 (+374%) | 1120 (+355%) | 1208 (+366%) | 1650 (+471%) | 100.0 (+0%) | - | 62.6 | 41.2 |
| 1 | ohttp | 0.53 (-68%) | 1048 (-68%) | 930 (+335%) | 920 (+340%) | 990 (+302%) | 1018 (+293%) | 1110 (+284%) | 100.0 (+0%) | - | 53.8 | 40.5 |
| 8 | raw | 8.08 | 16506 | 341 | 321 | 449 | 506 | 682 | 100.0 | - | - | - |
| 8 | stunnel | 0.81 (-90%) | 1612 (-90%) | 4920 (+1343%) | 4770 (+1386%) | 6190 (+1279%) | 6678 (+1220%) | 7970 (+1069%) | 100.0 (+0%) | - | 228.8 | 7.8 |
| 8 | haproxy | 1.36 (-83%) | 2702 (-84%) | 2910 (+753%) | 2810 (+775%) | 3750 (+735%) | 4116 (+713%) | 4960 (+627%) | 100.0 (+0%) | - | 193.7 | 117.7 |
| 8 | nginx stream (TLS) | 1.20 (-85%) | 2391 (-86%) | 3300 (+868%) | 3170 (+888%) | 4390 (+878%) | 4810 (+851%) | 5720 (+739%) | 100.0 (+0%) | - | 202.6 | 48.2 |
| 8 | nginx http (TLS) | 1.20 (-85%) | 2397 (-85%) | 3290 (+865%) | 3180 (+891%) | 4330 (+864%) | 4735 (+836%) | 5610 (+723%) | 100.0 (+0%) | - | 191.9 | 49.8 |
| 8 | rats-tls | 2.10 (-74%) | 4192 (-75%) | 1870 (+448%) | 1810 (+464%) | 2270 (+406%) | 2491 (+392%) | 3120 (+357%) | 100.0 (+0%) | - | 201.5 | 42.2 |
| 8 | rats-tls+mux | 2.25 (-72%) | 4473 (-73%) | 1760 (+416%) | 1720 (+436%) | 2130 (+374%) | 2271 (+349%) | 2720 (+299%) | 100.0 (+0%) | - | 167.4 | 43.1 |
| 8 | ohttp | 2.50 (-69%) | 4983 (-70%) | 1570 (+360%) | 1480 (+361%) | 2090 (+365%) | 2335 (+361%) | 2870 (+321%) | 100.0 (+0%) | - | 202.4 | 44.2 |
| 16 | raw | 11.92 | 24384 | 453 | 414 | 646 | 759 | 1090 | 100.0 | - | - | - |
| 16 | stunnel | 0.86 (-93%) | 1713 (-93%) | 9290 (+1951%) | 9030 (+2081%) | 12310 (+1806%) | 13405 (+1666%) | 15740 (+1344%) | 100.0 (+0%) | - | 262.3 | 8.8 |
| 16 | haproxy | 1.61 (-86%) | 3207 (-87%) | 4960 (+995%) | 4590 (+1009%) | 7160 (+1008%) | 8313 (+995%) | 11130 (+921%) | 100.0 (+0%) | - | 224.1 | 118.3 |
| 16 | nginx stream (TLS) | 1.46 (-88%) | 2902 (-88%) | 5470 (+1108%) | 5210 (+1158%) | 7780 (+1104%) | 8726 (+1050%) | 10870 (+897%) | 100.0 (+0%) | - | 250.4 | 48.5 |
| 16 | nginx http (TLS) | 1.47 (-88%) | 2928 (-88%) | 5410 (+1094%) | 5160 (+1146%) | 7710 (+1093%) | 8628 (+1037%) | 10590 (+872%) | 100.0 (+0%) | - | 239.7 | 50.4 |
| 16 | rats-tls | 2.43 (-80%) | 4841 (-80%) | 3250 (+617%) | 3170 (+666%) | 4150 (+542%) | 4556 (+500%) | 5800 (+432%) | 100.0 (+0%) | - | 220.8 | 44.7 |
| 16 | rats-tls+mux | 3.11 (-74%) | 6205 (-75%) | 2530 (+458%) | 2470 (+497%) | 3200 (+395%) | 3453 (+355%) | 4070 (+273%) | 100.0 (+0%) | - | 180.0 | 54.6 |
| 16 | ohttp | 3.15 (-74%) | 6272 (-74%) | 2510 (+454%) | 2380 (+475%) | 3470 (+437%) | 3899 (+414%) | 4930 (+352%) | 100.0 (+0%) | - | 232.3 | 47.2 |
| 32 | raw | 14.56 | 29676 | 4710 | 602 | 1160 | 1846 | 154640 | 100.0 | - | - | - |
| 32 | stunnel | 0.85 (-94%) | 1695 (-94%) | 18810 (+299%) | 18360 (+2950%) | 25500 (+2098%) | 27779 (+1405%) | 33310 (-78%) | 100.0 (+0%) | - | 263.2 | 10.8 |
| 32 | haproxy | 1.72 (-88%) | 3417 (-88%) | 9340 (+98%) | 8460 (+1305%) | 14200 (+1124%) | 17226 (+833%) | 22310 (-86%) | 100.0 (+0%) | - | 236.7 | 119.6 |
| 32 | nginx stream (TLS) | 1.60 (-89%) | 3193 (-89%) | 10010 (+113%) | 9230 (+1433%) | 15090 (+1201%) | 17772 (+863%) | 22980 (-85%) | 100.0 (+0%) | - | 259.4 | 49.6 |
| 32 | nginx http (TLS) | 1.63 (-89%) | 3245 (-89%) | 9820 (+108%) | 9150 (+1420%) | 14650 (+1163%) | 16946 (+818%) | 22090 (-86%) | 100.0 (+0%) | - | 256.8 | 50.8 |
| 32 | rats-tls | 2.55 (-82%) | 5073 (-83%) | 6220 (+32%) | 6160 (+923%) | 7900 (+581%) | 8542 (+363%) | 10200 (-93%) | 100.0 (+0%) | - | 225.9 | 49.7 |
| 32 | rats-tls+mux | 3.81 (-74%) | 7592 (-74%) | 4140 (-12%) | 4040 (+571%) | 5380 (+364%) | 5857 (+217%) | 6820 (-96%) | 100.0 (+0%) | - | 190.5 | 54.0 |
| 32 | ohttp | 3.47 (-76%) | 6910 (-77%) | 4580 (-3%) | 4410 (+633%) | 6150 (+430%) | 6816 (+269%) | 8370 (-95%) | 100.0 (+0%) | - | 246.7 | 50.6 |
| 64 | raw | 14.56 | 29670 | 16840 | 702 | 74070 | 141266 | 195060 | 100.0 | - | - | - |
| 64 | stunnel | 0.88 (-94%) | 1761 (-94%) | 36180 (+115%) | 35320 (+4931%) | 49220 (-34%) | 53616 (-62%) | 63330 (-68%) | 100.0 (+0%) | - | 287.7 | 14.3 |
| 64 | haproxy | 1.86 (-87%) | 3702 (-88%) | 17090 (+1%) | 16450 (+2243%) | 23940 (-68%) | 27167 (-81%) | 34380 (-82%) | 100.0 (+0%) | - | 252.4 | 121.8 |
| 64 | nginx stream (TLS) | 1.78 (-88%) | 3542 (-88%) | 17930 (+6%) | 16850 (+2300%) | 26310 (-64%) | 29855 (-79%) | 37490 (-81%) | 100.0 (+0%) | - | 270.0 | 51.5 |
| 64 | nginx http (TLS) | 1.81 (-88%) | 3608 (-88%) | 17600 (+5%) | 16920 (+2310%) | 25170 (-66%) | 28311 (-80%) | 36010 (-82%) | 100.0 (+0%) | - | 269.8 | 51.6 |
| 64 | rats-tls | 2.50 (-83%) | 4975 (-83%) | 12720 (-24%) | 12650 (+1702%) | 16219 (-78%) | 17385 (-88%) | 19900 (-90%) | 100.0 (+0%) | - | 216.3 | 74.5 |
| 64 | rats-tls+mux | 4.32 (-70%) | 8600 (-71%) | 7320 (-57%) | 7120 (+914%) | 9600 (-87%) | 10459 (-93%) | 12190 (-94%) | 100.0 (+0%) | - | 184.6 | 88.2 |
| 64 | ohttp | 3.58 (-75%) | 7140 (-76%) | 8900 (-47%) | 8650 (+1132%) | 11870 (-84%) | 13029 (-91%) | 15600 (-92%) | 100.0 (+0%) | - | 250.1 | 55.3 |
| 128 | raw | 14.56 | 29693 | 8290 | 2110 | 3700 | 32294 | 175190 | 100.0 | - | - | - |
| 128 | stunnel | 0.89 (-94%) | 1767 (-94%) | 72090 (+770%) | 70670 (+3249%) | 95330 (+2476%) | 103395 (+220%) | 122620 (-30%) | 100.0 (+0%) | - | 306.5 | 20.2 |
| 128 | haproxy | 1.94 (-87%) | 3859 (-87%) | 32680 (+294%) | 32330 (+1432%) | 41380 (+1018%) | 44734 (+39%) | 54280 (-69%) | 100.0 (+0%) | - | 263.2 | 126.9 |
| 128 | nginx stream (TLS) | 1.89 (-87%) | 3773 (-87%) | 33490 (+304%) | 33130 (+1470%) | 42660 (+1053%) | 46284 (+43%) | 53700 (-69%) | 100.0 (+0%) | - | 279.4 | 51.9 |
| 128 | nginx http (TLS) | 1.90 (-87%) | 3792 (-87%) | 33340 (+302%) | 32920 (+1460%) | 41580 (+1024%) | 45163 (+40%) | 53170 (-70%) | 100.0 (+0%) | - | 276.9 | 52.1 |
| 128 | rats-tls | 2.53 (-83%) | 5044 (-83%) | 25230 (+204%) | 24890 (+1080%) | 32680 (+783%) | 35378 (+10%) | 41410 (-76%) | 100.0 (+0%) | - | 216.2 | 88.2 |
| 128 | rats-tls+mux | 4.67 (-68%) | 9298 (-69%) | 13580 (+64%) | 13250 (+528%) | 17620 (+376%) | 19093 (-41%) | 22080 (-87%) | 100.0 (+0%) | - | 177.5 | 221.1 |
| 128 | ohttp | 3.71 (-75%) | 7392 (-75%) | 17240 (+108%) | 16850 (+699%) | 23390 (+532%) | 25683 (-20%) | 30390 (-83%) | 100.0 (+0%) | - | 248.0 | 67.4 |

</details>


Note: vs-raw percent change is in parentheses after each non-raw value, measured against the raw baseline of the same scenario. For throughput/RPS a negative value means lower than raw; for latency a positive value means slower than raw. At high concurrency the raw baseline's mean/p90/p99 are skewed by tail-latency spikes, so TNG rows can show large negative changes there, this does not establish the cause of the tail spikes or comparative stability.

</details>
