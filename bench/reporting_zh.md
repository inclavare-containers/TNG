# 可复现的压测报告

## 构建与部署身份

在源码工作区用记录器执行实际构建：

```bash
python3 bench/record-build.py --source . --binary target/release/tng --build-command 'make bin-build'
```

它把完整 commit、脏源码指纹、实际构建命令/设置、构建时间、版本及二进制 SHA-256 写入 target/release/tng.build.json。构建期间源码变化会报错。构建产物/manifest 放在 Git 忽略目录；脏工作区的实际补丁及未跟踪源码也必须保存在 run 产物中，单独指纹无法重建源码。记录器无法证明任意传入命令确实重新编译了二进制，因此应使用项目真实构建目标并核对日志。

二进制与 manifest 成对部署，manifest 名称匹配部署二进制（tng 对应 tng.build.json）；两端 TNG_BIN 指向该程序。TNG_BUILD_MANIFEST 可指定其他 manifest 路径。一起部署 bench/client.sh、bench/server.sh、bench/lib/common.sh、bench/gen-report.sh、bench/report_support.py 并保持相对结构。manifest 缺失或部署文件校验和/版本不符，采集会在压测负载前失败。若设置 TNG_GIT，必须等于 manifest 中完整 SHA。不能用远端目录 HEAD 生成身份，也不能用今天 HEAD 补填旧 run。

按既有流程运行压测，两端 info JSON 带有核实后的构建身份及 run 元数据。将 server-info JSON 连同 client-info、results 带回控制端。完整原始日志和配置私有保留；报告展示配置校验和并对主机端点身份脱敏。发布前仍需检查自定义构建命令及其他元数据是否含敏感值。

## 生成对比报告

```bash
bash bench/gen-report.sh --compare base-server-info.json base-client-info.json base-results.json head-server-info.json head-client-info.json head-results.json comparison.md
```

文件自带开头的 --- 分隔线，贴到 PR 前文后时，分隔线前留空行。元数据差异默认展开，完整元数据、分组方法说明、完整场景表默认折叠。五档计数和单元格标记共用未舍入数据及分档函数，TNG 主表与参考/控制负载表各自明确统计范围。

校验失败返回非零且不覆盖旧输出，必须检查退出状态，不能误发旧文件。缺失字段、格式错误或不完整矩阵均报错。优化前为零导致相对百分比无定义时需调查，不能归为持平；不生成 N/A 统计行。成功率下降即使在显示容差内也单独列出。前后参数变化会直接展示，在排除混杂变化前不能把收益归因代码。

故意测试混合版本时加 --allow-mixed-versions，两端身份仍明确展示。历史数据没有可信 manifest 时，仅为检查初步证据可加 --allow-unverified，报告会醒目标明未验证，且不豁免指标完整性。这些选项不能编造数据或证明最终收益。

比较模式支持 --metrics m1,m2，把全部表格限制为部分或历史 run 实际采集的指标列（例如只记录 RPS 与 egress CPU 的消融驱动）；结果文件包含子集之外的已测列会被拒绝，仅在一侧 run 出现的模式仍需完整矩阵。两侧都未采集的模式报告为未测量。比较模式还支持 --deltas FILE，输出与五档标记同源的逐 workload 前后变化百分比附表，含并发维度的 min/max/mean 行；正文中的孤立增量简表必须引用该输出，不得手工重算。

单次报告保留原位置参数（server-info client-info results [output.md]），展示折叠完整数据，不生成前后档位计数表。

## 离线验证

```bash
python3 bench/test_report.py
bash -n bench/gen-report.sh bench/lib/common.sh bench/client.sh bench/server.sh
```

测试使用合成 JSON 及本地程序替身，覆盖分档边界/方向、计数总数、折叠结构、身份校验、错误/缺失测量、历史及混合版本选项、部署文件被修改等情况，不启动 TNG 压测或连接外部服务。

PR 文案要求见 performance-pr-requirements.md / performance-pr-requirements_zh.md。结论仍需评审：脚本不推断瓶颈原因、不证明统计显著性、不隔离组合优化贡献，也不决定 issue 是否关闭。
