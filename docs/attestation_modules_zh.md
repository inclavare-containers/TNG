# `modules` 证明策略

`modules` 是内置 AS 的一种证明策略类型，把校验表达为一条模块化规则列表：每个条目是对证据某一部分的具类型校验，覆盖启动度量（客户机固件、内核、UKI、容器镜像、模型）、GPU 评定或 TDX 平台姿态。证据来自阿里云 AAEL 事件的条目带 `com.alibabacloud.` 厂商前缀；两个度量家族保留无前缀写法作为永久别名。每个条目把预期值内联钉住，生成的校验规则直接用该常量比对证据。在 verify 侧 `as_type: "builtin"` 的 `attestation_policy` 字段配置；策略类型的选取与其他配置见[远程证明](remote_attestation_zh.md)。

## 策略形态

每个条目形如 `{"type": "<类型>", "value": <取值>}`。度量类条目的取值是钉住的摘要字符串；姿态类条目（`tdx`、`nvidia`）的取值是配置对象，`com.alibabacloud.gpu` 的取值是空对象。

扁平列表即单组：

```json
"attestation_policy": {
    "type": "modules",
    "modules": [
        { "type": "tdx",       "value": {} },
        { "type": "nvidia",    "value": {} },
        { "type": "tdx.ovmf",  "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" },
        { "type": "tdx.kernel","value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" },
        { "type": "com.alibabacloud.container.image.model-server", "value": "sha256:c5945b51138c975fe3f0315a17a469b87f009ceaa6fc69ba461c5811fbb781a0" },
        { "type": "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B",    "value": "c2d3b69b8fe371d95c80e3962669156810c0328c6165306b8decf843149184a9" }
    ]
}
```

同一组内、同一维度的条目是 AND。数组的数组给出多个组，每组是一条独立基线：每个维度在带有该维度条目的组中任一组整体通过即 affirming，不带该维度条目的组不约束该维度。组也是同一维度内跨模块绑定的手段：固件 A 只允许配内核 A 时，把 `{ovmf A, kernel A}` 设为一组、`{ovmf B, kernel B}` 设为另一组；OVMF A 混配 kernel B 的证据两组可执行类校验都不命中。

<details>
<summary>示例：两条可替代基线（嵌套多组）</summary>

```json
"attestation_policy": {
    "type": "modules",
    "modules": [
        [
            { "type": "tdx",       "value": {} },
            { "type": "tdx.ovmf",  "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" },
            { "type": "tdx.kernel","value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
        ],
        [
            { "type": "tdx",        "value": {} },
            { "type": "tdx.td-shim","value": "04caf4fb18079198bec7cfcf4883dc3ae93f8deae6fa99b4d3af9e27ef69d71e2d4774551edb334abd05f871041c52a5" },
            { "type": "tdx.kernel", "value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
        ]
    ]
}
```

第一组接受 OVMF 启动的虚机，第二组接受 td-shim 启动的机密容器。
</details>

省略 `modules` 字段或给空列表（`{"type": "modules"}`、`[]`、`[[]]`）都是一个空组：除硬件 TEE 识别外不设要求。

不写某类模块即对该部分证据不设要求；写了即 fail-closed：证据缺少被测值、或测得值与钉住的基线不符，评定即非 affirming，TNG 拒绝建隧道。

与策略无关的基线校验始终执行：quote 签名验证、事件日志对 quote RTMR 的重放、report-data 会话绑定（防旧 quote 重放），都是验证器的固有行为，不是策略可配置的项。

## 信任度维度归属

每类模块固定门控一个 AR4SI 信任度维度：

| 模块类型 | 维度 |
|---|---|
| `tdx.td-shim`、`tdx.ovmf`、`tdx.kernel`、`tdx.uki` | `executables` |
| `com.alibabacloud.container.image.<repo>` | `executables` |
| `com.alibabacloud.ai.model.<model-id>` | `executables` |
| `tdx` | `hardware` |
| `nvidia` | `hardware` |
| `com.alibabacloud.gpu` | `hardware` |

同一组内同一维度的条目彼此 AND，每个维度再在带有该维度条目的组之间 OR。没有条目的维度保持 affirming（2），`configuration` 与 `file_system` 没有对应模块类型，同样保持 affirming。因此度量条目失败只影响 `executables`，`hardware` 仍取 TEE 识别结果；姿态条目失败只影响 `hardware`，`executables` 仍为 affirming。

`hardware` 维度还额外门控在固定的 TEE 识别基线上，即与 `hardware_only` 相同的四条平台识别路径（TDX quote 头部的 Intel quoting-enclave tee type 与 vendor id、Hygon CSV 版本、TPM、通用 system attester）。姿态条目在识别之上叠加约束，不替代识别。`{"type": "tdx", "value": {}}` 这类条目同时要求平台被识别为 TDX 且姿态检查通过，因此在非 TDX 证据上 fail-closed。

空 modules 列表与 `hardware_only` 完全等价：`executables`、`configuration`、`file_system` 为 affirming，`hardware` 仅由 TEE 识别决定。

## 配置错误

以下情况在策略加载期即被拒绝，不会进入运行期：

- 条目 `type` 不在下述类型集合内（包括家族前缀拼错）；`com.alibabacloud.` 前缀只对 `container.image.`、`ai.model.` 与精确类型 `gpu` 合法，无前缀的 `gpu` 不是合法类型；
- 同一 `type` 在同一组内出现两次，同一家族的规范名与别名也算重复（不同组重复同一 `type` 合法，各组是独立基线）；
- 取值形态或格式不对：摘要长度不符或含大写十六进制（摘要一律小写 hex）、`com.alibabacloud.container.image.*` 取值缺 `sha256:` 前缀、度量类给了对象或姿态类给了字符串；
- 名字段（`<repo>`、`<model-id>`）含 `[A-Za-z0-9._/@:+-]` 之外的字符；
- `tdx`、`nvidia` 或 `com.alibabacloud.gpu` 配置对象里出现未知字段；`com.alibabacloud.gpu` 的取值必须是空对象 `{}`；
- `nvidia` 条目的 `min_count` 小于 1（要关闭 GPU 评定就不写该条目）；
- `tdx` 的 `collateral.min_tcb_date` 不是 `YYYY-MM-DD`；
- `modules` 策略同时提供非空 `reference_values` 列表：生成的规则拿证据与钉住的常量比对，从不读取参考值，因此加载期直接拒绝。空列表（`[]`）放行。只有 `inline`、`path`、`transparency_log` 三种策略接受非空列表，它们的规则会消费参考值。

## 模块类型

| 类型 | 取值形态 | 被测对象 |
|---|---|---|
| `tdx.td-shim` | 96 位小写 hex | quote 的 `mr_td`，td-shim 客户机固件启动的 TD |
| `tdx.ovmf` | 96 位小写 hex | quote 的 `mr_td`，OVMF 固件启动的 TD |
| `tdx.kernel` | 96 位小写 hex | UEFI 事件日志的 `td_payload` 事件（SHA-384） |
| `tdx.uki` | 96 位小写 hex | UEFI 事件日志的 UKI 启动应用事件（SHA-384） |
| `com.alibabacloud.container.image.<repo>` | `sha256:<64 位小写 hex>` | repo 尾段为 `<repo>` 的 AAEL `kangaroo/pull-image` 事件 |
| `com.alibabacloud.ai.model.<model-id>` | 64 位小写 hex | 该模型的 AAEL `pai/load-model` 事件 |
| `tdx` | 配置对象 | quote 属性位与事件日志（平台姿态） |
| `nvidia` | 配置对象 | 经评定的逐 GPU claims（标准 NVIDIA 验证） |
| `com.alibabacloud.gpu` | 空对象 `{}` | AAEL `gpu/attestation` 事件及其结果码 |

`container.image.<repo>` 与 `ai.model.<model-id>` 是各自 `com.alibabacloud.` 写法的永久别名，生成逐字节相同的策略。`com.alibabacloud.gpu` 没有无前缀别名。

`tdx.td-shim` 与 `tdx.ovmf` 钉的是同一个 quote 字段，按 TD 的实际启动固件选用。

### 客户机固件度量：`tdx.td-shim`、`tdx.ovmf`

```json
{ "type": "tdx.ovmf", "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" }
```

钉住 TD 的启动度量，即 TDX quote 的 `mr_td`：硬件在创建 TD 时按客户机固件构建的初始 TD 镜像算出的 SHA-384 摘要。

- 通过：quote 的 `mr_td` 等于钉住的值。
- 拒绝：`mr_td` 不符，或证据不是 TDX（取值缺失，fail-closed）。

### 内核度量：`tdx.kernel`

```json
{ "type": "tdx.kernel", "value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
```

钉住启动时被测度的内核度量：固件测度 TD payload（内核）blob 时在 UEFI 事件日志记录的 `td_payload` 事件，取其 SHA-384 摘要。日志里出现多条 `td_payload` 事件时，摘要必须一致，冲突即拒。

- 通过：存在 `td_payload` 事件且其 SHA-384 摘要等于钉住的值。
- 拒绝：摘要不符，或日志没有 `td_payload` 事件。

### UKI 度量：`tdx.uki`

```json
{ "type": "tdx.uki", "value": "5bee5bdf63538ba7aa5c60d4725193c88932aa17083276fe9d61e4963ab6f871cdf3b3dd5d99733169b8c87a5e8e62b3" }
```

钉住统一内核镜像（UKI）的度量：固件把 UKI 作为 EFI 启动应用测度并记为 boot-services-application 事件，条目匹配此类事件记录的 SHA-384 摘要。日志中每条 `EV_EFI_BOOT_SERVICES_APPLICATION` 事件都必须携带钉住的 SHA-384 摘要，且至少存在一条。条目没有 device path 选择器，因此假定只有一份启动应用基线：若部署还记录了摘要不同的其它启动应用，即 fail-closed。不走 UKI 启动的部署不会产生这类事件，对其配置本条目即 fail-closed；那种启动路径请用 `tdx.kernel`。

- 通过：每条 boot-services-application 事件都携带钉住的 SHA-384 摘要。
- 拒绝：任一此类事件的摘要不符，或日志没有该事件。

### 容器镜像：`com.alibabacloud.container.image.<repo>`

```json
{ "type": "com.alibabacloud.container.image.model-server", "value": "sha256:c5945b51138c975fe3f0315a17a469b87f009ceaa6fc69ba461c5811fbb781a0" }
```

无前缀的 `container.image.<repo>` 是永久别名。该条目与阿里云耦合：证据来自 AAEL `alibabacloud.com` 事件。钉住工作负载镜像的 OCI manifest digest。镜像 reference 的 repo 尾段等于 `<repo>` 的每条 `kangaroo/pull-image` AAEL 事件，其 `digest` 都必须等于条目钉住的 `sha256:` 常量。`<repo>` 是自由命名（即所钉镜像 reference 的 repo 尾段，路径最后一段，registry 主机、路径前缀、tag/digest 剥掉）；钉了没有对应 pull-image 事件的 repo 即拒绝。

- 通过：镜像被拉取过，且该 repo 的每次拉取都报告钉住的 digest。
- 拒绝：拉取到的镜像 digest 不符；或钉了 repo 却没有对应拉取事件（fail-closed，不是跳过）。

### 模型：`com.alibabacloud.ai.model.<model-id>`

```json
{ "type": "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B", "value": "c2d3b69b8fe371d95c80e3962669156810c0328c6165306b8decf843149184a9" }
```

无前缀的 `ai.model.<model-id>` 是永久别名。该条目与阿里云耦合：证据来自 AAEL `alibabacloud.com` 事件。钉住模型的完整性度量，64 位小写 hex。哈希按该模型的度量约定算出（例如对落盘模型算的 fs-verity digest）。`<model-id>` 与事件里的模型标识逐字匹配（建议 modelscope-id 风格）。每条 `alibabacloud.com` `pai/load-model` AAEL 事件的 `model-id` 必须等于钉住的 `<model-id>`、`hash` 字段必须等于钉住的 64-hex 常量；至少存在一条 load-model 事件，事件缺失即拒绝。model-id 参与校验而不只是哈希：出现其它模型的加载事件即 fail-closed。

- 通过：模型被加载过，且每次加载事件都指向钉住的模型并报告钉住的哈希。
- 拒绝：任一加载事件的 model-id 或哈希不符；或没有任何加载事件。

### 平台姿态：`tdx`

```json
{ "type": "tdx", "value": { "debug": "deny", "eventlog": "required" } }
```

写出该条目即对 TDX 证据设平台姿态要求。属性位与事件日志字段默认取最严选择，`{"type": "tdx", "value": {}}` 即 strict 姿态；`tcb` 与 `collateral` 门需显式配置，缺省时不设要求。没有总开关：不要姿态校验就不写这个条目。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `debug` | `"deny"` / `"allow"` | `"deny"` | `deny` 拒绝带 debug 属性的 TD |
| `sept_ve_disable` | `"require"` / `"allow"` | `"require"` | `require` 要求 SEPT #VE-disable 属性已置位，关闭 pending 页的 #VE 逃逸面 |
| `perfmon` | `"deny"` / `"allow"` | `"deny"` | `deny` 拒绝获准使用性能计数器的 TD |
| `service_td` | `"deny"` / `"allow"` | `"deny"` | `deny` 要求 Service TD 度量为全零或不存在（v4 quote 无此字段按不存在处理） |
| `tcb` | object | 缺省（不设 TCB 门） | TCB 状态/advisory 门，见下 |
| `collateral` | object | 缺省（不设 collateral 门） | TCB collateral 时效门，见下 |
| `eventlog` | `"required"` / `"optional"` | `"required"` | `required` 要求非空 UEFI 事件日志 |

`debug`、`sept_ve_disable`、`perfmon` 检查 quote TD attributes 里的属性位；`service_td` 检查 Service TD 度量；`allow` 即跳过对应检查。

`debug` 取 `deny` 时，即使其余检查全过，启动带 debug 属性的 TD 仍被拒绝（quote TD attributes 首字节为奇数，如以 `01` 开头）。其余字段取默认的正常生产 TD 通过 `{"type": "tdx", "value": {}}`。

**TCB 门（`tcb`）。** 需显式配置；缺省不设 TCB 要求，证据不带 TCB 评定的部署照常评定。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `min_status` | `"up_to_date"` / `"out_of_date"` | `"up_to_date"` | 可接受的最低 TCB 状态；`up_to_date` 还会拒绝 out-of-date 各档。配置该门后，Revoked 一律拒绝 |
| `reject_advisories` | string 列表 | `[]` | 平台自报受其影响的 advisory ID（如 `"INTEL-SA-00330"`）命中即拒 |
| `allow_advisories` | string 列表 | `[]` | 从 `reject_advisories` 中豁免的 ID |

**Collateral 门（`collateral`）。** 需显式配置；缺省不做 collateral 检查。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `allow_expired` | boolean | `false` | 是否接受已过期的 TCB collateral |
| `min_tcb_date` | string `YYYY-MM-DD` | 缺省 | 要求平台的 TCB 级别日期不早于该日，即不受该日及以前披露的 TCB 级漏洞影响 |
| `max_collateral_age_days` | int | 缺省 | 要求 collateral 的签发距评定不超过 N 天 |

```json
{ "type": "tdx", "value": {
    "tcb": { "min_status": "up_to_date", "reject_advisories": ["INTEL-SA-00001"], "allow_advisories": ["INTEL-SA-00002"] },
    "collateral": { "allow_expired": false, "min_tcb_date": "2026-06-01", "max_collateral_age_days": 30 }
} }
```

- 通过：非 debug 的生产 TD，各属性位符合配置，带事件日志；配置了门时，TCB 状态未被吊销、档次达标、advisory 列表避开被拒项，collateral 未过期且晚于 `min_tcb_date`。
- 拒绝：debug 开启；TCB 已吊销；命中 `reject_advisories` 且未被 `allow_advisories` 豁免；`allow_expired` 为 `false` 时 collateral 已过期。

### GPU 证明事件：`com.alibabacloud.gpu`

```json
{ "type": "com.alibabacloud.gpu", "value": {} }
```

该条目没有无前缀别名，取值必须是空对象 `{}`。它与阿里云耦合：证据是证明代理产生的 AAEL `alibabacloud.com` `gpu/attestation` 事件。事件日志里必须至少存在一条此类事件，且每条事件的两个结果码 `gpu-collect-evidence-result-code` 与 `gpu-attest-result-code` 都必须为 0。第一个码表示证据收集是否成功，第二个码表示 GPU 证明结果。事件日志重放保证这些码在启动后未被篡改，但码本身仍是客户机自报的。

- 通过：至少存在一条 AAEL `gpu/attestation` 事件，且其中每条事件的两个结果码都为 0。
- 拒绝：没有此类事件，或任一事件的收集码或证明码非 0。

要评定逐 GPU 的设备 claims 而不是客户机自报的结果码，请用 `nvidia`。

### GPU 评定：`nvidia`

不写该条目即完全不评 GPU。写了该条目，即评定验证器从证据携带的 GPU 材料推出的逐 GPU claims：身份、版本、CC 模式与度量，按下方字段比对。只透传原始 GPU 证明报告、未经逐 GPU 评定的证据会被拒绝；证据里没有的 GPU 过不了数量检查。因此该评定要求 attester 上行 GPU 证据；本来不采集 GPU 证据的部署会 fail-closed。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `require_cc_mode` | boolean | `true` | 每张被枚举的 GPU 必须报告已启用机密计算模式 |
| `require_report` | boolean | `true` | 每张 GPU 必须带有经评定的证明度量 |
| `min_count` | int | `1` | 至少枚举 N 张 GPU |
| `allow_uuids` | string 列表 | `[]`（不设白名单） | 允许的 GPU UUID，如 `"GPU-3f9c2a1b-88d4-4e17-9c2a-71f0d5a4b6e8"` |
| `allow_driver_versions` | string 列表 | `[]`（不设白名单） | 允许的驱动版本，如 `"570.148.05"` |
| `allow_vbios_versions` | string 列表 | `[]`（不设白名单） | 允许的 VBIOS 版本，如 `"96.00.f4.00.07"` |
| `measurement_digest` | 96 位小写 hex 列表 | `[]`（不设白名单） | 允许的逐 GPU 度量摘要（对该卡全部 measurements 的 SHA-384） |

白名单字段按整串精确匹配；空列表即不设限。检查只覆盖驱动枚举到的 GPU；未被枚举的卡不在其范围内。

```json
{ "type": "nvidia", "value": {
    "require_cc_mode": true,
    "min_count": 1,
    "allow_uuids": ["GPU-3f9c2a1b-88d4-4e17-9c2a-71f0d5a4b6e8"],
    "allow_driver_versions": ["570.148.05"],
    "allow_vbios_versions": ["96.00.f4.00.07"],
    "measurement_digest": ["7430ef5370b61ba48a61739b6ea4a038e6456924a0af6d3b757cbc4fe98b85a087ed4bca2df36543902377da0c673e8a"]
} }
```

- 通过：证据经评定出至少一张 GPU，处于 CC 模式，且 UUID、驱动版本、VBIOS 版本、度量摘要都在钉住的集合内。
- 拒绝：GPU 数量少于 `min_count`；某张卡不在任一白名单内；或证据中没有经评定的 GPU claims。

**当前强度上限。** 该评定比对的是经评定的设备 claims。GPU 证明报告的签名、GPU 证书链、驱动 RIM 文件的密码学校验属验证器侧后续工作；补齐之前，评定反映的是验证器解析报告时记录的 claims，而非报告本体的真实性。

## 从固定策略类型迁移

| 已删除类型 | `modules` 等价写法 |
|---|---|
| `hardware_with_reference_values` | 启动度量类条目（`tdx.td-shim`/`tdx.ovmf`、`tdx.kernel`、`tdx.uki`）把预期摘要直接钉在策略里；需要日志锚定基线则用 `transparency_log` |
| `hardware_strict_with_reference_values` | 同上，另加 `{"type": "tdx", "value": {"sept_ve_disable": "allow", "perfmon": "allow", "service_td": "allow"}}`，在 TDX 证据上对齐旧的 strict 姿态 |
| `hardware_strict_with_measurements` | `com.alibabacloud.ai.model.<model-id>` 与 `com.alibabacloud.container.image.<repo>` 条目把同样的基线内联钉住，另加 `sept_ve_disable`、`perfmon`、`service_td` 均设为 `allow` 的 `tdx` 条目，在 TDX 证据上对齐旧的 strict 姿态；独立的 `reference_values` 列表不再需要 |

保留的类型中，`hardware_only` 等价于 `{"type": "modules", "modules": []}`。在 TDX 证据上，把单个 `{"type": "tdx", "value": {}}` 条目的 `sept_ve_disable`、`perfmon`、`service_td` 三项都设为 `allow` 才与 `hardware_only_strict` 一致：`tdx` 的默认还会门控这三个属性，因此原样写该条目比 `hardware_only_strict` 更严。该等价关系只对 TDX 证据成立，因为 `tdx` 条目在其它平台上会 fail-closed。
