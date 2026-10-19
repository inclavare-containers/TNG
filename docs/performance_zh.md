# TNG 性能快照

> 本页记录当前 TNG 版本的跟踪式性能快照，每次性能变更合入后重新生成。页面展示单次运行的数据，不做前后对比。

## 本页是什么

本页在标准双主机压测方法下跟踪当前开发版本的实测性能：三个场景（iperf3 TCP 吞吐、HTTP keep-alive、HTTP 无 keep-alive），每个场景一张表，一行一个 workload、一列一个指标，并为每个场景配一张图。页面始终描述当前版本：性能变更合入时，其 PR 会用新的最终实测结果重新生成本页（见[更新规则](#更新规则)一节）。单个变更的前后对比证据保留在各 PR 的压测报告里，不放在本页。

页面上的每个数字都来自留存的运行产物。表格与图由报告生成器和图表生成器从同一份 `bench-results.json` 生成，页面末尾逐字嵌入完整的脚本生成报告，因此快照可追溯到原始数据，不存在手抄表格。

## 如何运行压测

压测工具说明在 [`bench/README.md`](../bench/README.md)：server/backend 主机执行 `bash bench/server.sh`，client/load 主机执行 `bash bench/client.sh <SERVER_IP>`，运行产出三个留存的 JSON 文件。[`bench/reporting.md`](../bench/reporting.md) 记录报告生成（`bench/gen-report.sh`，单次或 `--compare` 模式）、SVG 图生成（`bench/gen-svg.py`）与构建身份记录器。压测运行必须串行：驱动程序启动前必须持有两台共享主机的独占 bench 锁，避免并发运行在同一批测试点上叠加负载。本页不重复上述文档内容。

## 测量模式

当前快照按 `master` 上的现行方法测量：

- 开启远程证明：egress 通过 attestation-agent Unix socket 提交证明，ingress 使用内置证明服务按 `hardware_only` 策略验证。
- HTTP 响应体 64 KiB。每轮运行同时测量两种 HTTP 连接模式（keep-alive 与无 keep-alive）以及 iperf3 TCP 吞吐。
- 每个场景的并发梯度为 1、8、16、32、64、128。
- 每个 workload/并发测试点都在全新启动的隧道/代理进程上测量，因此测试点的内存峰值就是该点自身开销，而不是早期测试点遗留的分配器高水位。
- 每个测试点取最强一轮（多轮中请求率或吞吐最高的一轮）。
- CPU 100% 等于一个逻辑核。场景 A 采样客户端隧道进程；场景 B、C 采样服务端代理组件（TNG 取 egress 进程；HAProxy 主进程加工作进程求和；stunnel 取服务端进程）。`raw` 参考没有代理进程，其资源列天然缺失。

## 实测快照

实测二进制：tng 2.11.0，ingress 与 egress 均构建自源码版本 `7d460bd081ae956b062a2f9f328836858e3c9602`，其 Rust 内容与 PR #264 合入后的 `master` 一致。

TNG 提供三种不同的隧道配置，不同模式的数值相差数倍，因此下文每个标签都明确指明配置：

| 标签 | 配置 |
| --- | --- |
| `raw` | 直连，不经任何 TLS 代理（参考） |
| `stunnel` | stunnel TLS 隧道（参考） |
| `haproxy` | HAProxy TLS 终结代理（参考） |
| `rats-tls` | TNG rats-tls 非多路复用：每条客户端 TCP 连接对应一条到 egress 的 TLS 连接 |
| `rats-tls+mux` | TNG rats-tls 多路复用：多条客户端连接共享一条到 egress 的 HTTP/2 CONNECT 隧道 |
| `ohttp` | TNG ohttp：Oblivious HTTP（RFC 9458）密封请求/响应信封，ingress 通过明文 HTTP POST 到 egress |

### 场景 A - TCP / iperf3 吞吐

![场景 A：TCP 吞吐、客户端隧道 CPU 与隧道内存随 iperf3 并发流数的变化](performance/scenario_a.svg)

每个非 raw 单元格括号内是相对同一并发度下 `raw` 基线的百分比变化。场景 A 未测量 ohttp。

| Streams | Workload | Throughput (Gbps) | Tunnel CPU % | Tunnel Mem (GB) |
| --- | --- | --- | --- | --- |
| 1 | raw | 15.98 | - | - |
| 1 | stunnel | 10.82 (-32%) | 68.0 | 0.007 |
| 1 | haproxy | 11.23 (-30%) | 69.0 | 0.086 |
| 1 | rats-tls | 10.57 (-34%) | 49.0 | 0.044 |
| 1 | rats-tls+mux | 9.93 (-38%) | 96.5 | 0.047 |
| 8 | raw | 16.19 | - | - |
| 8 | stunnel | 13.89 (-14%) | 217.0 | 0.008 |
| 8 | haproxy | 16.34 (+1%) | 119.5 | 0.087 |
| 8 | rats-tls | 16.34 (+1%) | 83.5 | 0.052 |
| 8 | rats-tls+mux | 11.43 (-29%) | 123.5 | 0.074 |
| 16 | raw | 16.23 | - | - |
| 16 | stunnel | 14.10 (-13%) | 238.0 | 0.008 |
| 16 | haproxy | 16.30 (+0%) | 124.0 | 0.088 |
| 16 | rats-tls | 16.59 (+2%) | 91.5 | 0.058 |
| 16 | rats-tls+mux | 11.25 (-31%) | 116.0 | 0.101 |
| 32 | raw | 16.31 | - | - |
| 32 | stunnel | 15.46 (-5%) | 233.8 | 0.010 |
| 32 | haproxy | 16.37 (+0%) | 126.0 | 0.089 |
| 32 | rats-tls | 17.09 (+5%) | 99.0 | 0.070 |
| 32 | rats-tls+mux | 10.07 (-38%) | 95.0 | 0.147 |
| 64 | raw | 16.43 | - | - |
| 64 | stunnel | 16.88 (+3%) | 243.0 | 0.012 |
| 64 | haproxy | 15.87 (-3%) | 120.5 | 0.092 |
| 64 | rats-tls | 17.88 (+9%) | 111.5 | 0.089 |
| 64 | rats-tls+mux | 9.97 (-39%) | 85.5 | 0.235 |
| 128 | raw | 16.60 | - | - |
| 128 | stunnel | 16.71 (+1%) | 254.0 | 0.017 |
| 128 | haproxy | 15.20 (-8%) | 119.0 | 0.097 |
| 128 | rats-tls | 17.83 (+7%) | 127.5 | 0.128 |
| 128 | rats-tls+mux | 11.85 (-29%) | 93.5 | 0.379 |

### 场景 B - HTTP / wrk，64 KiB 响应体，keep-alive

![场景 B：RPS、p99 延迟与服务端代理 CPU 随 keep-alive 并发连接数的变化](performance/scenario_b.svg)

wrk 为每个客户端维持一条持久 TCP+TLS 连接，证明开销被复用该连接的请求摊薄。

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Server CPU % | Server Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 2.34 | 4654 | 223 | 203 | 257 | 377 | 736 | 100.0 | - | - | - |
| 1 | stunnel | 1.60 (-32%) | 3196 (-31%) | 320 (+43%) | 305 (+50%) | 356 (+39%) | 376 (-0%) | 687 (-7%) | 100.0 (+0%) | - | 24.7 | 6.9 |
| 1 | haproxy | 1.77 (-24%) | 3522 (-24%) | 285 (+28%) | 277 (+36%) | 326 (+27%) | 343 (-9%) | 396 (-46%) | 100.0 (+0%) | - | 22.7 | 115.2 |
| 1 | rats-tls | 1.35 (-42%) | 2684 (-42%) | 375 (+68%) | 357 (+76%) | 424 (+65%) | 487 (+29%) | 823 (+12%) | 100.0 (+0%) | - | 15.7 | 47.4 |
| 1 | rats-tls+mux | 0.77 (-67%) | 1529 (-67%) | 727 (+226%) | 641 (+216%) | 714 (+178%) | 745 (+98%) | 3380 (+359%) | 100.0 (+0%) | - | 34.7 | 46.4 |
| 1 | ohttp | 0.65 (-72%) | 1298 (-72%) | 769 (+245%) | 764 (+276%) | 835 (+225%) | 858 (+128%) | 910 (+24%) | 100.0 (+0%) | - | 52.3 | 47.0 |
| 8 | raw | 12.96 | 26480 | 728 | 259 | 460 | 1616 | 14430 | 100.0 | - | - | - |
| 8 | stunnel | 6.73 (-48%) | 13406 (-49%) | 605 (-17%) | 554 (+114%) | 817 (+78%) | 931 (-42%) | 1420 (-90%) | 100.0 (+0%) | - | 126.0 | 7.5 |
| 8 | haproxy | 6.88 (-47%) | 13975 (-47%) | 567 (-22%) | 527 (+103%) | 792 (+72%) | 919 (-43%) | 1270 (-91%) | 100.0 (+0%) | - | 111.3 | 116.6 |
| 8 | rats-tls | 7.28 (-44%) | 14897 (-44%) | 538 (-26%) | 521 (+101%) | 671 (+46%) | 725 (-55%) | 920 (-94%) | 100.0 (+0%) | - | 91.0 | 48.0 |
| 8 | rats-tls+mux | 4.28 (-67%) | 8524 (-68%) | 1070 (+47%) | 890 (+244%) | 1170 (+154%) | 1615 (-0%) | 5400 (-63%) | 100.0 (+0%) | - | 89.3 | 51.1 |
| 8 | ohttp | 3.14 (-76%) | 6258 (-76%) | 1250 (+72%) | 1210 (+367%) | 1600 (+248%) | 1696 (+5%) | 1930 (-87%) | 100.0 (+0%) | - | 172.0 | 55.2 |
| 16 | raw | 14.96 | 30552 | 23450 | 325 | 114000 | 160257 | 197310 | 100.0 | - | - | - |
| 16 | stunnel | 6.88 (-54%) | 14067 (-54%) | 1200 (-95%) | 990 (+205%) | 2040 (-98%) | 2628 (-98%) | 4080 (-98%) | 100.0 (+0%) | - | 176.7 | 8.2 |
| 16 | haproxy | 8.88 (-41%) | 18079 (-41%) | 890 (-96%) | 798 (+146%) | 1360 (-99%) | 1637 (-99%) | 2650 (-99%) | 100.0 (+0%) | - | 143.7 | 116.3 |
| 16 | rats-tls | 9.12 (-39%) | 18677 (-39%) | 836 (-96%) | 810 (+149%) | 1140 (-99%) | 1241 (-99%) | 1520 (-99%) | 100.0 (+0%) | - | 102.3 | 50.4 |
| 16 | rats-tls+mux | 5.78 (-61%) | 11523 (-62%) | 1510 (-94%) | 1300 (+300%) | 1790 (-98%) | 2064 (-99%) | 8890 (-95%) | 100.0 (+0%) | - | 100.3 | 58.1 |
| 16 | ohttp | 4.02 (-73%) | 8001 (-74%) | 2000 (-91%) | 1840 (+466%) | 2940 (-97%) | 3227 (-98%) | 4200 (-98%) | 100.0 (+0%) | - | 203.7 | 62.1 |
| 32 | raw | 14.96 | 30559 | 31830 | 630 | 138800 | 173022 | 200500 | 100.0 | - | - | - |
| 32 | stunnel | 5.05 (-66%) | 10060 (-67%) | 3440 (-89%) | 2960 (+370%) | 5440 (-96%) | 6445 (-96%) | 11380 (-94%) | 100.0 (+0%) | - | 157.3 | 9.6 |
| 32 | haproxy | 9.92 (-34%) | 20184 (-34%) | 1880 (-94%) | 1310 (+108%) | 3340 (-98%) | 5002 (-97%) | 11250 (-94%) | 100.0 (+0%) | - | 161.0 | 117.2 |
| 32 | rats-tls | 10.00 (-33%) | 20325 (-33%) | 1610 (-95%) | 1490 (+137%) | 2240 (-98%) | 2463 (-99%) | 5020 (-97%) | 100.0 (+0%) | - | 105.0 | 51.4 |
| 32 | rats-tls+mux | 6.80 (-55%) | 13546 (-56%) | 2400 (-92%) | 2240 (+256%) | 3210 (-98%) | 3633 (-98%) | 6320 (-97%) | 100.0 (+0%) | - | 102.3 | 66.2 |
| 32 | ohttp | 4.93 (-67%) | 9820 (-68%) | 3250 (-90%) | 3030 (+381%) | 4810 (-97%) | 5466 (-97%) | 6840 (-97%) | 100.0 (+0%) | - | 235.7 | 74.6 |
| 64 | raw | 14.96 | 30525 | 16890 | 1760 | 66350 | 138234 | 195940 | 100.0 | - | - | - |
| 64 | stunnel | 5.84 (-61%) | 11624 (-62%) | 5950 (-65%) | 5000 (+184%) | 9400 (-86%) | 11510 (-92%) | 23750 (-88%) | 100.0 (+0%) | - | 233.7 | 12.3 |
| 64 | haproxy | 10.64 (-29%) | 21784 (-29%) | 3550 (-79%) | 2270 (+29%) | 7630 (-89%) | 10724 (-92%) | 18160 (-91%) | 100.0 (+0%) | - | 173.0 | 118.3 |
| 64 | rats-tls | 11.28 (-25%) | 23046 (-25%) | 2760 (-84%) | 2570 (+46%) | 4210 (-94%) | 4806 (-97%) | 7220 (-96%) | 100.0 (+0%) | - | 116.7 | 56.6 |
| 64 | rats-tls+mux | 7.04 (-53%) | 14303 (-53%) | 4710 (-72%) | 4250 (+141%) | 6460 (-90%) | 7448 (-95%) | 22170 (-89%) | 100.0 (+0%) | - | 99.0 | 61.1 |
| 64 | ohttp | 5.49 (-63%) | 10931 (-64%) | 5830 (-65%) | 5490 (+212%) | 8260 (-88%) | 9413 (-93%) | 11790 (-94%) | 100.0 (+0%) | - | 257.0 | 88.4 |
| 128 | raw | 15.04 | 30591 | 10750 | 3720 | 7160 | 55183 | 182950 | 100.0 | - | - | - |
| 128 | stunnel | 7.04 (-53%) | 14408 (-53%) | 10700 (-0%) | 8180 (+120%) | 17950 (+151%) | 24024 (-56%) | 81330 (-56%) | 100.0 (+0%) | - | 233.3 | 17.1 |
| 128 | haproxy | 11.04 (-27%) | 22539 (-26%) | 6590 (-39%) | 4200 (+13%) | 14840 (+107%) | 19453 (-65%) | 28690 (-84%) | 100.0 (+0%) | - | 177.0 | 122.2 |
| 128 | rats-tls | 12.40 (-18%) | 25321 (-17%) | 5050 (-53%) | 4640 (+25%) | 7610 (+6%) | 8694 (-84%) | 12870 (-93%) | 100.0 (+0%) | - | 127.3 | 66.1 |
| 128 | rats-tls+mux | 6.85 (-54%) | 13645 (-55%) | 9270 (-14%) | 8980 (+141%) | 13260 (+85%) | 14678 (-73%) | 17510 (-90%) | 100.0 (+0%) | - | 88.3 | 69.0 |
| 128 | ohttp | 5.77 (-62%) | 11496 (-62%) | 11040 (+3%) | 10480 (+182%) | 15330 (+114%) | 17288 (-69%) | 21590 (-88%) | 100.0 (+0%) | - | 266.7 | 120.9 |

### 场景 C - HTTP / wrk，64 KiB 响应体，无 keep-alive

![场景 C：RPS、p99 延迟与服务端代理 CPU 随短连接并发度的变化](performance/scenario_c.svg)

wrk 发送 `Connection: close`，每个请求都要支付新建 TCP 连接与完整 TLS 握手（对三种 TNG 配置还包括证明与验证）。

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Server CPU % | Server Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 1.62 | 3221 | 213 | 212 | 249 | 262 | 290 | 100.0 | - | - | - |
| 1 | stunnel | 0.25 (-85%) | 489 (-85%) | 1980 (+830%) | 1970 (+829%) | 2090 (+739%) | 2124 (+711%) | 2200 (+659%) | 100.0 (+0%) | - | 46.0 | 6.9 |
| 1 | haproxy | 0.33 (-80%) | 666 (-79%) | 1430 (+571%) | 1420 (+570%) | 1510 (+506%) | 1537 (+487%) | 1610 (+455%) | 100.0 (+0%) | - | 42.7 | 116.4 |
| 1 | rats-tls | 0.50 (-69%) | 1002 (-69%) | 960 (+351%) | 960 (+353%) | 1020 (+310%) | 1048 (+300%) | 1100 (+279%) | 100.0 (+0%) | - | 41.0 | 47.9 |
| 1 | rats-tls+mux | 0.48 (-70%) | 953 (-70%) | 1010 (+374%) | 990 (+367%) | 1120 (+350%) | 1197 (+357%) | 1550 (+434%) | 100.0 (+0%) | - | 62.0 | 46.8 |
| 1 | ohttp | 0.50 (-69%) | 1006 (-69%) | 960 (+351%) | 960 (+353%) | 1020 (+310%) | 1046 (+299%) | 1100 (+279%) | 100.0 (+0%) | - | 64.7 | 47.6 |
| 8 | raw | 8.08 | 16472 | 340 | 323 | 450 | 505 | 666 | 100.0 | - | - | - |
| 8 | stunnel | 0.81 (-90%) | 1622 (-90%) | 4880 (+1335%) | 4740 (+1367%) | 6170 (+1271%) | 6582 (+1203%) | 7590 (+1040%) | 100.0 (+0%) | - | 226.9 | 7.7 |
| 8 | haproxy | 1.37 (-83%) | 2720 (-83%) | 2880 (+747%) | 2790 (+764%) | 3710 (+724%) | 4041 (+700%) | 4810 (+622%) | 100.0 (+0%) | - | 193.3 | 117.7 |
| 8 | rats-tls | 2.11 (-74%) | 4194 (-75%) | 1860 (+447%) | 1810 (+460%) | 2270 (+404%) | 2459 (+387%) | 2970 (+346%) | 100.0 (+0%) | - | 193.7 | 48.3 |
| 8 | rats-tls+mux | 2.28 (-72%) | 4536 (-72%) | 1720 (+406%) | 1690 (+423%) | 2120 (+371%) | 2254 (+346%) | 2620 (+293%) | 100.0 (+0%) | - | 164.3 | 49.4 |
| 8 | ohttp | 2.34 (-71%) | 4662 (-72%) | 1680 (+394%) | 1610 (+398%) | 2190 (+387%) | 2373 (+370%) | 2850 (+328%) | 100.0 (+0%) | - | 198.7 | 59.5 |
| 16 | raw | 11.76 | 24013 | 462 | 412 | 653 | 775 | 1180 | 100.0 | - | - | - |
| 16 | stunnel | 0.87 (-93%) | 1739 (-93%) | 9130 (+1876%) | 8880 (+2055%) | 12120 (+1756%) | 13183 (+1601%) | 15340 (+1200%) | 100.0 (+0%) | - | 259.3 | 8.6 |
| 16 | haproxy | 1.62 (-86%) | 3232 (-87%) | 4900 (+961%) | 4530 (+1000%) | 7000 (+972%) | 8230 (+962%) | 10550 (+794%) | 100.0 (+0%) | - | 225.0 | 118.1 |
| 16 | rats-tls | 2.46 (-79%) | 4908 (-80%) | 3200 (+593%) | 3140 (+662%) | 4070 (+523%) | 4442 (+473%) | 5320 (+351%) | 100.0 (+0%) | - | 218.3 | 50.7 |
| 16 | rats-tls+mux | 3.13 (-73%) | 6241 (-74%) | 2510 (+443%) | 2460 (+497%) | 3190 (+389%) | 3417 (+341%) | 3890 (+230%) | 100.0 (+0%) | - | 181.3 | 52.4 |
| 16 | ohttp | 2.91 (-75%) | 5801 (-76%) | 2650 (+474%) | 2510 (+509%) | 3760 (+476%) | 4200 (+442%) | 5150 (+336%) | 100.0 (+0%) | - | 228.0 | 61.2 |
| 32 | raw | 14.64 | 29905 | 1370 | 636 | 1120 | 1369 | 2680 | 100.0 | - | - | - |
| 32 | stunnel | 0.85 (-94%) | 1692 (-94%) | 18780 (+1271%) | 18220 (+2765%) | 25800 (+2204%) | 28393 (+1974%) | 34300 (+1180%) | 100.0 (+0%) | - | 253.0 | 10.3 |
| 32 | haproxy | 1.74 (-88%) | 3456 (-88%) | 9200 (+572%) | 8400 (+1221%) | 13850 (+1137%) | 16523 (+1107%) | 21680 (+709%) | 100.0 (+0%) | - | 237.7 | 118.7 |
| 32 | rats-tls | 2.54 (-83%) | 5064 (-83%) | 6220 (+354%) | 6200 (+875%) | 7950 (+610%) | 8483 (+520%) | 9900 (+269%) | 100.0 (+0%) | - | 223.6 | 51.5 |
| 32 | rats-tls+mux | 3.92 (-73%) | 7801 (-74%) | 4030 (+194%) | 3940 (+519%) | 5190 (+363%) | 5624 (+311%) | 6500 (+143%) | 100.0 (+0%) | - | 183.7 | 73.1 |
| 32 | ohttp | 3.43 (-77%) | 6833 (-77%) | 4560 (+233%) | 4300 (+576%) | 6550 (+485%) | 7309 (+434%) | 8820 (+229%) | 100.0 (+0%) | - | 257.3 | 69.1 |
| 64 | raw | 14.88 | 30374 | 13620 | 834 | 38040 | 123393 | 191950 | 100.0 | - | - | - |
| 64 | stunnel | 0.89 (-94%) | 1773 (-94%) | 35730 (+162%) | 34930 (+4088%) | 48980 (+29%) | 53662 (-57%) | 63210 (-67%) | 100.0 (+0%) | - | 272.7 | 13.4 |
| 64 | haproxy | 1.87 (-87%) | 3722 (-88%) | 16800 (+23%) | 16040 (+1823%) | 24220 (-36%) | 27523 (-78%) | 35240 (-82%) | 100.0 (+0%) | - | 250.7 | 120.7 |
| 64 | rats-tls | 2.53 (-83%) | 5032 (-83%) | 12570 (-8%) | 12460 (+1394%) | 16219 (-57%) | 17435 (-86%) | 19900 (-90%) | 100.0 (+0%) | - | 216.7 | 61.5 |
| 64 | rats-tls+mux | 4.25 (-71%) | 8462 (-72%) | 7430 (-45%) | 7210 (+765%) | 9740 (-74%) | 10601 (-91%) | 12580 (-93%) | 100.0 (+0%) | - | 178.7 | 94.9 |
| 64 | ohttp | 3.73 (-75%) | 7436 (-76%) | 8560 (-37%) | 8070 (+868%) | 12040 (-68%) | 13731 (-89%) | 17500 (-91%) | 100.0 (+0%) | - | 269.8 | 89.2 |
| 128 | raw | 14.88 | 30352 | 9450 | 1900 | 4260 | 66158 | 181260 | 100.0 | - | - | - |
| 128 | stunnel | 0.89 (-94%) | 1778 (-94%) | 70920 (+650%) | 69490 (+3557%) | 94980 (+2130%) | 102973 (+56%) | 119560 (-34%) | 100.0 (+0%) | - | 307.3 | 19.3 |
| 128 | haproxy | 1.95 (-87%) | 3880 (-87%) | 32009 (+239%) | 31860 (+1577%) | 41890 (+883%) | 45576 (-31%) | 53330 (-71%) | 100.0 (+0%) | - | 264.7 | 124.8 |
| 128 | rats-tls | 2.57 (-83%) | 5129 (-83%) | 24500 (+159%) | 24230 (+1175%) | 32000 (+651%) | 34380 (-48%) | 39240 (-78%) | 100.0 (+0%) | - | 215.0 | 98.2 |
| 128 | rats-tls+mux | 4.58 (-69%) | 9131 (-70%) | 13770 (+46%) | 13490 (+610%) | 18020 (+323%) | 19465 (-71%) | 22340 (-88%) | 100.0 (+0%) | - | 173.3 | 212.9 |
| 128 | ohttp | 3.79 (-75%) | 7538 (-75%) | 16780 (+78%) | 15900 (+737%) | 25250 (+493%) | 28381 (-57%) | 33960 (-81%) | 100.0 (+0%) | - | 273.7 | 122.6 |

## 更新规则

性能 PR 在最终阶段于同一 PR 内重新生成本页及 [`docs/performance/`](performance/) 下的三张图：表格与嵌入报告取最终实测矩阵实验臂的 `bash bench/gen-report.sh <server-info> <client-info> <results>` 单次模式输出，图取同一输入下 `python3 bench/gen-svg.py` 的输出。快照始终保持当前版本的单次运行视图，对比表格不放进本页。该规则已写入 [`bench/performance-pr-requirements.md`](../bench/performance-pr-requirements.md)。

## 完整单次报告

<details>
<summary>Full single-run benchmark report (tng 2.11.0, source revision 7d460bd081ae956b062a2f9f328836858e3c9602)</summary>

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
| Client TNG | tng 2.11.0 |
| Client TNG source revision | 7d460bd081ae956b062a2f9f328836858e3c9602 |
| Server TNG | tng 2.11.0 |
| Server TNG source revision | 7d460bd081ae956b062a2f9f328836858e3c9602 |
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
| iperf3 duration / rounds / len | 3s / 2 / 131072 bytes |
| wrk connections | 1,8,16,32,64,128 |
| wrk duration / rounds / threads | 3s / 2 / auto |
| HTTP body size | 64 KiB |
| HTTP scenarios measured | keep-alive (B) + no keep-alive (C) |
| Result per point | strongest of N rounds (highest request rate) |
| Client parameter: attest_aa_addr | unix:///run/confidential-containers/attestation-agent/attestation-agent.sock |
| Client parameter: attest_aa_type | uds |
| Client parameter: http_body_kb | 64 |
| Client parameter: iperf_duration | 3 |
| Client parameter: iperf_len | 131072 |
| Client parameter: iperf_rounds | 2 |
| Client parameter: iperf_streams | 1,8,16,32,64,128 |
| Client parameter: mux_max_streams | unset |
| Client parameter: no_ra | false |
| Client parameter: ra_mode | 1 |
| Client parameter: server_ip | [redacted endpoint] |
| Client parameter: tng_mode | mapping |
| Client parameter: verify_as_type | builtin |
| Client parameter: verify_attestation_policy | hardware_only |
| Client parameter: wrk_conns | 1,8,16,32,64,128 |
| Client parameter: wrk_duration | 3 |
| Client parameter: wrk_rounds | 2 |
| Client parameter: wrk_threads | auto |
| Client parameter: wrk_warmup | 1 |
| Client configuration: config SHA-256 | 4d5ffb74e717e2290ca240cf0cab54bb368773eec27b358aee15a60722894e32 |
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
| Server configuration: config SHA-256 | d8a2f1e69bf1f55cb20b058cb6f93b1bc897dfb134ff871138cef520cc685aed |

</details>


3. **Test Tool Versions**

<details>
<summary>Full test tool versions</summary>

| Tool | Image (resolved) | Source | Version | Digest |
| --- | --- | --- | --- | --- |
| Client iperf3 | mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest | mirror | iperf 3.21 (cJSON 1.7.15) | sha256:02d3da1562e94beeb935d50df7231da9bb3cfe0e37b7c21fe64e0babec67c3c9 |
| Client nginx |  |  |  |  |
| Client wrk | mirrors-ssl.aliyuncs.com/ghcr.io/william-yeh/wrk:latest | mirror | wrk  [epoll] Copyright (C) 2012 Will Glozer | sha256:8aeaa2c883aa571ccf25eb618cfe75700f06f6947a885d549f7a4d524276bb41 |
| Client stunnel | mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest | mirror | stunnel 5.82 on x86_64-alpine-linux-musl platform | sha256:5659c54dbabcd7aeff70f28f956ee8baf816cdb206f26f5bf54de352de27bca9 |
| Client haproxy | mirrors-ssl.aliyuncs.com/library/haproxy:latest | mirror | HAProxy version 3.4.7-8872a26 2026/10/14 - https://haproxy.org/ | sha256:9674b623e6c4b76f805a7bb408f828acdd8ce6f436852b529e17c96684cefd98 |
| Server iperf3 | mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest | mirror | iperf 3.21 (cJSON 1.7.15) | sha256:02d3da1562e94beeb935d50df7231da9bb3cfe0e37b7c21fe64e0babec67c3c9 |
| Server nginx | mirrors-ssl.aliyuncs.com/library/nginx:stable-alpine | mirror | nginx version: nginx/1.30.6 | sha256:072ab83a13f547635cefde2c5a8cbfb251454ba66bfbaf2ea5e2b057aa81bf10 |
| Server wrk |  |  |  |  |
| Server stunnel | mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest | mirror | stunnel 5.82 on x86_64-alpine-linux-musl platform | sha256:5659c54dbabcd7aeff70f28f956ee8baf816cdb206f26f5bf54de352de27bca9 |
| Server haproxy | mirrors-ssl.aliyuncs.com/library/haproxy:latest | mirror | HAProxy version 3.4.7-8872a26 2026/10/14 - https://haproxy.org/ | sha256:9674b623e6c4b76f805a7bb408f828acdd8ce6f436852b529e17c96684cefd98 |

</details>

4. **Test Methodology**

<details>
<summary>Test methodology and metric definitions</summary>

**Topology and tunnel modes**

- Two hosts communicate over eth0: a client/load host runs TNG ingress and load generators; a server/backend host runs TNG egress, iperf3, nginx and TLS-proxy reference backends.
- TNG uses five mapping entries (ingress 50001–50005, egress 40001–40005). Load tools use host-network containers; TNG runs as a host executable. Protocol modes and attestation settings are recorded in Test Conditions.

**Workloads and run parameters**

- Scenario A measures TCP throughput with iperf3 parallel streams (`-P`). Scenario B measures HTTP/wrk persistent connections; Scenario C sends `Connection: close` for fresh client connections. Actual concurrency, body size, duration, warmup and round counts appear in Test Conditions.
- Each workload/concurrency point runs the recorded number of rounds. Workload metrics are aggregated as medians of the rounds; CPU samples use the final round and memory samples span every measured round, as described below. Keep-alive and no-keep-alive are separate scenarios, not interchangeable workloads.

**HTTP latency and success metrics**

- wrk runs with `--latency`: p50/p90/p99 come from its reported distribution; p95 is obtained by the Lua `latency:percentile(95)` callback. Mean is wrk's Thread Stats average.
- Success rate is `(completed requests - non-2xx) / (completed requests + socket errors)`. Unchanged success rates are classified as stable, not improved. Any decline must still be investigated even within the display tolerance.

**Resource sampling and units**

- CPU columns are one-second pidstat windows averaged over the final measured round. Memory columns are the peak RSS under load: `/proc/<pid>/status` VmRSS, summed over the sampled PID set at 1 Hz in parallel with every measured round, reported as the maximum of those samples. Windowed RSS averages mixed the load ramp into the plateau and were bistable run-to-run; the peak answers how much memory serving the workload needs.
- Every workload with a proxy or tunnel process (TNG ingress/egress pair, stunnel, HAProxy) is measured on a freshly restarted process set: before each cell's warmup and measured rounds the harness stops that workload's processes, verifies the old PIDs and listen ports are released, relaunches the same binary or container with the same config, and waits for the listening ports to be ready. Samplers find processes by listen port, so they always measure the post-restart PIDs. Each cell's memory peak is therefore that cell's own cost, not allocator high-water carried from earlier cells of the pass. Raw reference rows have no proxy process and nothing to restart.
- TCP Tunnel CPU/Mem columns sample the client-side tunnel process. The legacy `Tunnel Mem (GB)` label stores the peak VmRSS KiB divided by 1024² (GiB).
- HTTP Server CPU/Mem columns sample the server-side tunnel component (`pidstat -u -p <PIDs> 1 <duration>` Average rows for CPU). TNG uses the egress process; HAProxy sums master and workers; stunnel uses its server process. CPU sums threads/processes (100% = one logical core); the peak RSS sums the same PID set and is converted from KiB to MiB.
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

| Streams | Workload | Throughput (Gbps) | Tunnel CPU % | Tunnel Mem (GB) |
| --- | --- | --- | --- | --- |
| 1 | raw | 15.98 | - | - |
| 1 | stunnel | 10.82 (-32%) | 68.0 | 0.007 |
| 1 | haproxy | 11.23 (-30%) | 69.0 | 0.086 |
| 1 | rats-tls | 10.57 (-34%) | 49.0 | 0.044 |
| 1 | rats-tls+mux | 9.93 (-38%) | 96.5 | 0.047 |
| 8 | raw | 16.19 | - | - |
| 8 | stunnel | 13.89 (-14%) | 217.0 | 0.008 |
| 8 | haproxy | 16.34 (+1%) | 119.5 | 0.087 |
| 8 | rats-tls | 16.34 (+1%) | 83.5 | 0.052 |
| 8 | rats-tls+mux | 11.43 (-29%) | 123.5 | 0.074 |
| 16 | raw | 16.23 | - | - |
| 16 | stunnel | 14.10 (-13%) | 238.0 | 0.008 |
| 16 | haproxy | 16.30 (+0%) | 124.0 | 0.088 |
| 16 | rats-tls | 16.59 (+2%) | 91.5 | 0.058 |
| 16 | rats-tls+mux | 11.25 (-31%) | 116.0 | 0.101 |
| 32 | raw | 16.31 | - | - |
| 32 | stunnel | 15.46 (-5%) | 233.8 | 0.010 |
| 32 | haproxy | 16.37 (+0%) | 126.0 | 0.089 |
| 32 | rats-tls | 17.09 (+5%) | 99.0 | 0.070 |
| 32 | rats-tls+mux | 10.07 (-38%) | 95.0 | 0.147 |
| 64 | raw | 16.43 | - | - |
| 64 | stunnel | 16.88 (+3%) | 243.0 | 0.012 |
| 64 | haproxy | 15.87 (-3%) | 120.5 | 0.092 |
| 64 | rats-tls | 17.88 (+9%) | 111.5 | 0.089 |
| 64 | rats-tls+mux | 9.97 (-39%) | 85.5 | 0.235 |
| 128 | raw | 16.60 | - | - |
| 128 | stunnel | 16.71 (+1%) | 254.0 | 0.017 |
| 128 | haproxy | 15.20 (-8%) | 119.0 | 0.097 |
| 128 | rats-tls | 17.83 (+7%) | 127.5 | 0.128 |
| 128 | rats-tls+mux | 11.85 (-29%) | 93.5 | 0.379 |

</details>


### Scenario B - HTTP / wrk (64 KiB body, keep-alive)

<details>
<summary>Full scenario results</summary>

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Server CPU % | Server Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 2.34 | 4654 | 223 | 203 | 257 | 377 | 736 | 100.0 | - | - | - |
| 1 | stunnel | 1.60 (-32%) | 3196 (-31%) | 320 (+43%) | 305 (+50%) | 356 (+39%) | 376 (-0%) | 687 (-7%) | 100.0 (+0%) | - | 24.7 | 6.9 |
| 1 | haproxy | 1.77 (-24%) | 3522 (-24%) | 285 (+28%) | 277 (+36%) | 326 (+27%) | 343 (-9%) | 396 (-46%) | 100.0 (+0%) | - | 22.7 | 115.2 |
| 1 | rats-tls | 1.35 (-42%) | 2684 (-42%) | 375 (+68%) | 357 (+76%) | 424 (+65%) | 487 (+29%) | 823 (+12%) | 100.0 (+0%) | - | 15.7 | 47.4 |
| 1 | rats-tls+mux | 0.77 (-67%) | 1529 (-67%) | 727 (+226%) | 641 (+216%) | 714 (+178%) | 745 (+98%) | 3380 (+359%) | 100.0 (+0%) | - | 34.7 | 46.4 |
| 1 | ohttp | 0.65 (-72%) | 1298 (-72%) | 769 (+245%) | 764 (+276%) | 835 (+225%) | 858 (+128%) | 910 (+24%) | 100.0 (+0%) | - | 52.3 | 47.0 |
| 8 | raw | 12.96 | 26480 | 728 | 259 | 460 | 1616 | 14430 | 100.0 | - | - | - |
| 8 | stunnel | 6.73 (-48%) | 13406 (-49%) | 605 (-17%) | 554 (+114%) | 817 (+78%) | 931 (-42%) | 1420 (-90%) | 100.0 (+0%) | - | 126.0 | 7.5 |
| 8 | haproxy | 6.88 (-47%) | 13975 (-47%) | 567 (-22%) | 527 (+103%) | 792 (+72%) | 919 (-43%) | 1270 (-91%) | 100.0 (+0%) | - | 111.3 | 116.6 |
| 8 | rats-tls | 7.28 (-44%) | 14897 (-44%) | 538 (-26%) | 521 (+101%) | 671 (+46%) | 725 (-55%) | 920 (-94%) | 100.0 (+0%) | - | 91.0 | 48.0 |
| 8 | rats-tls+mux | 4.28 (-67%) | 8524 (-68%) | 1070 (+47%) | 890 (+244%) | 1170 (+154%) | 1615 (-0%) | 5400 (-63%) | 100.0 (+0%) | - | 89.3 | 51.1 |
| 8 | ohttp | 3.14 (-76%) | 6258 (-76%) | 1250 (+72%) | 1210 (+367%) | 1600 (+248%) | 1696 (+5%) | 1930 (-87%) | 100.0 (+0%) | - | 172.0 | 55.2 |
| 16 | raw | 14.96 | 30552 | 23450 | 325 | 114000 | 160257 | 197310 | 100.0 | - | - | - |
| 16 | stunnel | 6.88 (-54%) | 14067 (-54%) | 1200 (-95%) | 990 (+205%) | 2040 (-98%) | 2628 (-98%) | 4080 (-98%) | 100.0 (+0%) | - | 176.7 | 8.2 |
| 16 | haproxy | 8.88 (-41%) | 18079 (-41%) | 890 (-96%) | 798 (+146%) | 1360 (-99%) | 1637 (-99%) | 2650 (-99%) | 100.0 (+0%) | - | 143.7 | 116.3 |
| 16 | rats-tls | 9.12 (-39%) | 18677 (-39%) | 836 (-96%) | 810 (+149%) | 1140 (-99%) | 1241 (-99%) | 1520 (-99%) | 100.0 (+0%) | - | 102.3 | 50.4 |
| 16 | rats-tls+mux | 5.78 (-61%) | 11523 (-62%) | 1510 (-94%) | 1300 (+300%) | 1790 (-98%) | 2064 (-99%) | 8890 (-95%) | 100.0 (+0%) | - | 100.3 | 58.1 |
| 16 | ohttp | 4.02 (-73%) | 8001 (-74%) | 2000 (-91%) | 1840 (+466%) | 2940 (-97%) | 3227 (-98%) | 4200 (-98%) | 100.0 (+0%) | - | 203.7 | 62.1 |
| 32 | raw | 14.96 | 30559 | 31830 | 630 | 138800 | 173022 | 200500 | 100.0 | - | - | - |
| 32 | stunnel | 5.05 (-66%) | 10060 (-67%) | 3440 (-89%) | 2960 (+370%) | 5440 (-96%) | 6445 (-96%) | 11380 (-94%) | 100.0 (+0%) | - | 157.3 | 9.6 |
| 32 | haproxy | 9.92 (-34%) | 20184 (-34%) | 1880 (-94%) | 1310 (+108%) | 3340 (-98%) | 5002 (-97%) | 11250 (-94%) | 100.0 (+0%) | - | 161.0 | 117.2 |
| 32 | rats-tls | 10.00 (-33%) | 20325 (-33%) | 1610 (-95%) | 1490 (+137%) | 2240 (-98%) | 2463 (-99%) | 5020 (-97%) | 100.0 (+0%) | - | 105.0 | 51.4 |
| 32 | rats-tls+mux | 6.80 (-55%) | 13546 (-56%) | 2400 (-92%) | 2240 (+256%) | 3210 (-98%) | 3633 (-98%) | 6320 (-97%) | 100.0 (+0%) | - | 102.3 | 66.2 |
| 32 | ohttp | 4.93 (-67%) | 9820 (-68%) | 3250 (-90%) | 3030 (+381%) | 4810 (-97%) | 5466 (-97%) | 6840 (-97%) | 100.0 (+0%) | - | 235.7 | 74.6 |
| 64 | raw | 14.96 | 30525 | 16890 | 1760 | 66350 | 138234 | 195940 | 100.0 | - | - | - |
| 64 | stunnel | 5.84 (-61%) | 11624 (-62%) | 5950 (-65%) | 5000 (+184%) | 9400 (-86%) | 11510 (-92%) | 23750 (-88%) | 100.0 (+0%) | - | 233.7 | 12.3 |
| 64 | haproxy | 10.64 (-29%) | 21784 (-29%) | 3550 (-79%) | 2270 (+29%) | 7630 (-89%) | 10724 (-92%) | 18160 (-91%) | 100.0 (+0%) | - | 173.0 | 118.3 |
| 64 | rats-tls | 11.28 (-25%) | 23046 (-25%) | 2760 (-84%) | 2570 (+46%) | 4210 (-94%) | 4806 (-97%) | 7220 (-96%) | 100.0 (+0%) | - | 116.7 | 56.6 |
| 64 | rats-tls+mux | 7.04 (-53%) | 14303 (-53%) | 4710 (-72%) | 4250 (+141%) | 6460 (-90%) | 7448 (-95%) | 22170 (-89%) | 100.0 (+0%) | - | 99.0 | 61.1 |
| 64 | ohttp | 5.49 (-63%) | 10931 (-64%) | 5830 (-65%) | 5490 (+212%) | 8260 (-88%) | 9413 (-93%) | 11790 (-94%) | 100.0 (+0%) | - | 257.0 | 88.4 |
| 128 | raw | 15.04 | 30591 | 10750 | 3720 | 7160 | 55183 | 182950 | 100.0 | - | - | - |
| 128 | stunnel | 7.04 (-53%) | 14408 (-53%) | 10700 (-0%) | 8180 (+120%) | 17950 (+151%) | 24024 (-56%) | 81330 (-56%) | 100.0 (+0%) | - | 233.3 | 17.1 |
| 128 | haproxy | 11.04 (-27%) | 22539 (-26%) | 6590 (-39%) | 4200 (+13%) | 14840 (+107%) | 19453 (-65%) | 28690 (-84%) | 100.0 (+0%) | - | 177.0 | 122.2 |
| 128 | rats-tls | 12.40 (-18%) | 25321 (-17%) | 5050 (-53%) | 4640 (+25%) | 7610 (+6%) | 8694 (-84%) | 12870 (-93%) | 100.0 (+0%) | - | 127.3 | 66.1 |
| 128 | rats-tls+mux | 6.85 (-54%) | 13645 (-55%) | 9270 (-14%) | 8980 (+141%) | 13260 (+85%) | 14678 (-73%) | 17510 (-90%) | 100.0 (+0%) | - | 88.3 | 69.0 |
| 128 | ohttp | 5.77 (-62%) | 11496 (-62%) | 11040 (+3%) | 10480 (+182%) | 15330 (+114%) | 17288 (-69%) | 21590 (-88%) | 100.0 (+0%) | - | 266.7 | 120.9 |

</details>


### Scenario C - HTTP / wrk (64 KiB body, no keep-alive)

<details>
<summary>Full scenario results</summary>

| Conns | Workload | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Ingress CPU % | Server CPU % | Server Mem (MiB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | raw | 1.62 | 3221 | 213 | 212 | 249 | 262 | 290 | 100.0 | - | - | - |
| 1 | stunnel | 0.25 (-85%) | 489 (-85%) | 1980 (+830%) | 1970 (+829%) | 2090 (+739%) | 2124 (+711%) | 2200 (+659%) | 100.0 (+0%) | - | 46.0 | 6.9 |
| 1 | haproxy | 0.33 (-80%) | 666 (-79%) | 1430 (+571%) | 1420 (+570%) | 1510 (+506%) | 1537 (+487%) | 1610 (+455%) | 100.0 (+0%) | - | 42.7 | 116.4 |
| 1 | rats-tls | 0.50 (-69%) | 1002 (-69%) | 960 (+351%) | 960 (+353%) | 1020 (+310%) | 1048 (+300%) | 1100 (+279%) | 100.0 (+0%) | - | 41.0 | 47.9 |
| 1 | rats-tls+mux | 0.48 (-70%) | 953 (-70%) | 1010 (+374%) | 990 (+367%) | 1120 (+350%) | 1197 (+357%) | 1550 (+434%) | 100.0 (+0%) | - | 62.0 | 46.8 |
| 1 | ohttp | 0.50 (-69%) | 1006 (-69%) | 960 (+351%) | 960 (+353%) | 1020 (+310%) | 1046 (+299%) | 1100 (+279%) | 100.0 (+0%) | - | 64.7 | 47.6 |
| 8 | raw | 8.08 | 16472 | 340 | 323 | 450 | 505 | 666 | 100.0 | - | - | - |
| 8 | stunnel | 0.81 (-90%) | 1622 (-90%) | 4880 (+1335%) | 4740 (+1367%) | 6170 (+1271%) | 6582 (+1203%) | 7590 (+1040%) | 100.0 (+0%) | - | 226.9 | 7.7 |
| 8 | haproxy | 1.37 (-83%) | 2720 (-83%) | 2880 (+747%) | 2790 (+764%) | 3710 (+724%) | 4041 (+700%) | 4810 (+622%) | 100.0 (+0%) | - | 193.3 | 117.7 |
| 8 | rats-tls | 2.11 (-74%) | 4194 (-75%) | 1860 (+447%) | 1810 (+460%) | 2270 (+404%) | 2459 (+387%) | 2970 (+346%) | 100.0 (+0%) | - | 193.7 | 48.3 |
| 8 | rats-tls+mux | 2.28 (-72%) | 4536 (-72%) | 1720 (+406%) | 1690 (+423%) | 2120 (+371%) | 2254 (+346%) | 2620 (+293%) | 100.0 (+0%) | - | 164.3 | 49.4 |
| 8 | ohttp | 2.34 (-71%) | 4662 (-72%) | 1680 (+394%) | 1610 (+398%) | 2190 (+387%) | 2373 (+370%) | 2850 (+328%) | 100.0 (+0%) | - | 198.7 | 59.5 |
| 16 | raw | 11.76 | 24013 | 462 | 412 | 653 | 775 | 1180 | 100.0 | - | - | - |
| 16 | stunnel | 0.87 (-93%) | 1739 (-93%) | 9130 (+1876%) | 8880 (+2055%) | 12120 (+1756%) | 13183 (+1601%) | 15340 (+1200%) | 100.0 (+0%) | - | 259.3 | 8.6 |
| 16 | haproxy | 1.62 (-86%) | 3232 (-87%) | 4900 (+961%) | 4530 (+1000%) | 7000 (+972%) | 8230 (+962%) | 10550 (+794%) | 100.0 (+0%) | - | 225.0 | 118.1 |
| 16 | rats-tls | 2.46 (-79%) | 4908 (-80%) | 3200 (+593%) | 3140 (+662%) | 4070 (+523%) | 4442 (+473%) | 5320 (+351%) | 100.0 (+0%) | - | 218.3 | 50.7 |
| 16 | rats-tls+mux | 3.13 (-73%) | 6241 (-74%) | 2510 (+443%) | 2460 (+497%) | 3190 (+389%) | 3417 (+341%) | 3890 (+230%) | 100.0 (+0%) | - | 181.3 | 52.4 |
| 16 | ohttp | 2.91 (-75%) | 5801 (-76%) | 2650 (+474%) | 2510 (+509%) | 3760 (+476%) | 4200 (+442%) | 5150 (+336%) | 100.0 (+0%) | - | 228.0 | 61.2 |
| 32 | raw | 14.64 | 29905 | 1370 | 636 | 1120 | 1369 | 2680 | 100.0 | - | - | - |
| 32 | stunnel | 0.85 (-94%) | 1692 (-94%) | 18780 (+1271%) | 18220 (+2765%) | 25800 (+2204%) | 28393 (+1974%) | 34300 (+1180%) | 100.0 (+0%) | - | 253.0 | 10.3 |
| 32 | haproxy | 1.74 (-88%) | 3456 (-88%) | 9200 (+572%) | 8400 (+1221%) | 13850 (+1137%) | 16523 (+1107%) | 21680 (+709%) | 100.0 (+0%) | - | 237.7 | 118.7 |
| 32 | rats-tls | 2.54 (-83%) | 5064 (-83%) | 6220 (+354%) | 6200 (+875%) | 7950 (+610%) | 8483 (+520%) | 9900 (+269%) | 100.0 (+0%) | - | 223.6 | 51.5 |
| 32 | rats-tls+mux | 3.92 (-73%) | 7801 (-74%) | 4030 (+194%) | 3940 (+519%) | 5190 (+363%) | 5624 (+311%) | 6500 (+143%) | 100.0 (+0%) | - | 183.7 | 73.1 |
| 32 | ohttp | 3.43 (-77%) | 6833 (-77%) | 4560 (+233%) | 4300 (+576%) | 6550 (+485%) | 7309 (+434%) | 8820 (+229%) | 100.0 (+0%) | - | 257.3 | 69.1 |
| 64 | raw | 14.88 | 30374 | 13620 | 834 | 38040 | 123393 | 191950 | 100.0 | - | - | - |
| 64 | stunnel | 0.89 (-94%) | 1773 (-94%) | 35730 (+162%) | 34930 (+4088%) | 48980 (+29%) | 53662 (-57%) | 63210 (-67%) | 100.0 (+0%) | - | 272.7 | 13.4 |
| 64 | haproxy | 1.87 (-87%) | 3722 (-88%) | 16800 (+23%) | 16040 (+1823%) | 24220 (-36%) | 27523 (-78%) | 35240 (-82%) | 100.0 (+0%) | - | 250.7 | 120.7 |
| 64 | rats-tls | 2.53 (-83%) | 5032 (-83%) | 12570 (-8%) | 12460 (+1394%) | 16219 (-57%) | 17435 (-86%) | 19900 (-90%) | 100.0 (+0%) | - | 216.7 | 61.5 |
| 64 | rats-tls+mux | 4.25 (-71%) | 8462 (-72%) | 7430 (-45%) | 7210 (+765%) | 9740 (-74%) | 10601 (-91%) | 12580 (-93%) | 100.0 (+0%) | - | 178.7 | 94.9 |
| 64 | ohttp | 3.73 (-75%) | 7436 (-76%) | 8560 (-37%) | 8070 (+868%) | 12040 (-68%) | 13731 (-89%) | 17500 (-91%) | 100.0 (+0%) | - | 269.8 | 89.2 |
| 128 | raw | 14.88 | 30352 | 9450 | 1900 | 4260 | 66158 | 181260 | 100.0 | - | - | - |
| 128 | stunnel | 0.89 (-94%) | 1778 (-94%) | 70920 (+650%) | 69490 (+3557%) | 94980 (+2130%) | 102973 (+56%) | 119560 (-34%) | 100.0 (+0%) | - | 307.3 | 19.3 |
| 128 | haproxy | 1.95 (-87%) | 3880 (-87%) | 32009 (+239%) | 31860 (+1577%) | 41890 (+883%) | 45576 (-31%) | 53330 (-71%) | 100.0 (+0%) | - | 264.7 | 124.8 |
| 128 | rats-tls | 2.57 (-83%) | 5129 (-83%) | 24500 (+159%) | 24230 (+1175%) | 32000 (+651%) | 34380 (-48%) | 39240 (-78%) | 100.0 (+0%) | - | 215.0 | 98.2 |
| 128 | rats-tls+mux | 4.58 (-69%) | 9131 (-70%) | 13770 (+46%) | 13490 (+610%) | 18020 (+323%) | 19465 (-71%) | 22340 (-88%) | 100.0 (+0%) | - | 173.3 | 212.9 |
| 128 | ohttp | 3.79 (-75%) | 7538 (-75%) | 16780 (+78%) | 15900 (+737%) | 25250 (+493%) | 28381 (-57%) | 33960 (-81%) | 100.0 (+0%) | - | 273.7 | 122.6 |

</details>


Note: vs-raw percent change is in parentheses after each non-raw value, measured against the raw baseline of the same scenario. For throughput/RPS a negative value means lower than raw; for latency a positive value means slower than raw. At high concurrency the raw baseline's mean/p90/p99 are skewed by tail-latency spikes, so TNG rows can show large negative changes there, this does not establish the cause of the tail spikes or comparative stability.

</details>
