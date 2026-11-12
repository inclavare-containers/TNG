# `modules` 证明策略

`modules` 是内置 AS 的一种证明策略类型，把校验表达为一条模块化规则列表：每个条目是对证据某一部分的具类型校验，覆盖启动或工作负载度量（客户机固件、内核、UKI、根文件系统、容器镜像、模型）、GPU 评定、TDX 平台属性，或锚定在透明日志中的度量基线。容器镜像、模型与根文件系统类型以带 `com.alibabacloud.` 前缀的写法为规范拼写。容器镜像与模型的证据来自阿里云 AAEL 事件，`rootfs.cc` 读取 `td_payload_info` platform config flags 事件。度量与平台属性条目把预期值内联钉住，生成的校验规则直接用这些常量比对证据；`transparency_log` 条目则把基线锚定在透明日志中。在 verify 侧 `as_type: "builtin"` 的 `attestation_policy` 字段配置；策略类型的选取与其他配置见[远程证明](remote_attestation_zh.md)。

## 策略形态

每个条目形如 `{"type": "<类型>", "value": <取值>}`。度量类条目的取值是钉住的摘要字符串；`tdx` 与 `nvidia` 的取值是配置对象，`com.alibabacloud.gpu` 的取值是空对象，`transparency_log` 的取值是描述日志锚定基线的配置对象。

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

省略 `modules` 字段或给空列表（`{"type": "modules"}`、`[]`、`[[]]`）都是一个空组，不做任何断言：各维度保持默认值，`hardware` 在任何证据形态下都为 97（非 affirming）。要断言硬件识别，请写 `tdx` 条目或直接使用 `hardware_only` 策略。

不写某类模块即对该部分证据不设要求；写了即 fail-closed：证据缺少被测值、或测得值与钉住的基线不符，评定即非 affirming，TNG 拒绝建隧道。

与策略无关的基线校验始终执行：quote 签名验证、事件日志对 quote RTMR 的重放、report-data 会话绑定（防旧 quote 重放），都是验证器的固有行为，不是策略可配置的项。

## 信任度维度归属

每类模块门控一个或多个 AR4SI 信任度维度：

| 模块类型 | 维度 |
|---|---|
| `tdx.td-shim`、`tdx.ovmf`、`tdx.kernel`、`tdx.uki` | `executables` |
| `com.alibabacloud.container.image.<repo>` | `executables` |
| `com.alibabacloud.ai.model.<model-id>` | `executables` |
| `com.alibabacloud.rootfs.cc` | `file_system` |
| `transparency_log` | `publishedMeasurements` 中各类型的维度 |
| `tdx` | `hardware` |
| `nvidia` | `hardware` |
| `com.alibabacloud.gpu` | `hardware` |

没有条目的维度保持 affirming（2）。`configuration` 没有对应模块类型，始终如此。`hardware` 例外：策略里只要有条目，它就要求条目证据所属的平台被识别。modules 只识别 TDX（quote 头部 `tee_type` 为 `81000000`、`vendor_id` 为 `939a7233f79c4ca9940a0db3957f0607`），`hardware_only` 的 CSV、TPM、system 路径不适用。`tdx` 条目在识别之上追加属性检查，因此在非 TDX 证据上失败。

`transparency_log` 条目的维度由其 `publishedMeasurements` 中各类型决定；`fallbackPublishedMeasurements` 是其子集，不增加维度。条目失败只影响它门控的维度。

## 配置错误

以下情况在策略加载期即被拒绝，不会进入运行期：

- 条目 `type` 不在下述类型集合内（包括家族前缀拼错）；`com.alibabacloud.` 前缀只对 `container.image.`、`ai.model.`、`rootfs.cc` 与精确类型 `gpu` 合法，无前缀的 `gpu` 不是合法类型；
- 同一 `type` 在同一组内出现两次，同一家族的规范名与别名也算重复（不同组重复同一 `type` 合法，各组是独立基线）。`transparency_log` 是唯一例外：它可以在同一组内重复，以便多条日志锚定基线都必须通过；
- 取值形态或格式不对：摘要长度不符或含大写十六进制（摘要一律小写 hex）、`com.alibabacloud.container.image.*` 取值缺 `sha256:` 前缀、度量类给了对象，或 `tdx`/`nvidia` 给了字符串；
- `transparency_log` 条目的 `value` 不满足下方“透明日志”一节的字段约束。`fallbackServices` 单独出现会被接受，但没有效果；
- `tdx`、`nvidia` 或 `com.alibabacloud.gpu` 配置对象里出现未知字段；`com.alibabacloud.gpu` 的取值必须是空对象 `{}`；
- `nvidia` 条目的 `min_count` 小于 1（要关闭 GPU 评定就不写该条目）；
- `tdx` 的 `collateral.min_tcb_date` 不是 `YYYY-MM-DD`；
- `modules` 策略同时提供非空 `reference_values` 列表：生成的规则不读取参考值，因此加载期直接拒绝。空列表（`[]`）放行。只有 `inline`、`path` 两种策略接受非空列表，它们的规则会消费参考值。

## 模块类型

| 类型 | 别名 | 取值形态 | 被测对象 |
|---|---|---|---|
| `tdx.td-shim` | — | 96 位小写 hex | quote 的 `mr_td`，td-shim 客户机固件启动的 TD |
| `tdx.ovmf` | — | 96 位小写 hex | quote 的 `mr_td`，OVMF 固件启动的 TD |
| `tdx.kernel` | — | 96 位小写 hex | UEFI 事件日志的 `td_payload` 事件（SHA-384，记录在 RTMR1） |
| `tdx.uki` | — | 96 位小写 hex | UEFI 事件日志的 UKI 启动应用事件（SHA-384） |
| `com.alibabacloud.container.image.<repo>` | `container.image.<repo>` | `sha256:<64 位小写 hex>` | repo 尾段为 `<repo>` 的 AAEL `kangaroo/pull-image` 事件 |
| `com.alibabacloud.ai.model.<model-id>` | `ai.model.<model-id>` | 64 位小写 hex | 该模型的 AAEL `pai/load-model` 事件 |
| `com.alibabacloud.rootfs.cc` | `rootfs.cc` | 64 位小写 hex | UEFI 事件日志的 `td_payload_info` 事件，根文件系统的 dm-verity 根哈希 |
| `transparency_log` | — | 配置对象 | 记录在透明日志中的 ReleaseManifest（rekor-v1 或 artifact-server primary） |
| `tdx` | — | 配置对象 | quote 属性位与事件日志（平台属性检查） |
| `nvidia` | — | 配置对象 | 经评定的逐 GPU claims（标准 NVIDIA 验证） |
| `com.alibabacloud.gpu` | — | 空对象 `{}` | AAEL `gpu/attestation` 事件及其结果码 |

要查看一份配置生成的确切 Rego，运行 `tng tools policy export`（见 [TNG 工具](tools_zh.md#tng-tools-policy)）。

### 客户机固件度量：`tdx.td-shim`、`tdx.ovmf`

```json
{ "type": "tdx.ovmf", "value": "19de6c23abcb441c128f7070a95bb75fed723ae6e3276c80e44367b03d543d48ed3377a954d21b32f8c5bc474e068fe5" }
```

钉住 TD 的启动度量，也就是 TDX quote 里的 `mr_td`。这是 TD 创建时硬件对客户机固件构建出的初始 TD 镜像算出的 SHA-384 值。条目要求 quote 的 `mr_td` 等于钉住的值；字段缺失或值不相等都失败。`tdx.td-shim` 和 `tdx.ovmf` 读的是同一个字段，按 TD 的启动方式选一个。

### 内核度量：`tdx.kernel`

```json
{ "type": "tdx.kernel", "value": "1f709fa8a1171ebafcdd70b74d40c6225e8e671555379e082a5636e3981ad61f98441c0f3369a22e5a74c63b0ac2f265" }
```

钉住启动时的内核度量，也就是固件为 TD payload（内核）blob 记录的 SHA-384 摘要。条目读取 UEFI 事件日志里的 `td_payload` 事件。事件必须记在 RTMR1（寄存器索引 2），每个匹配事件都要带 SHA-384 摘要，这些事件里的 SHA-384 摘要必须全部相同。没有匹配事件、索引不是 2 或缺失、事件没有 SHA-384 摘要，或者摘要不一致，条目都失败。事件里声明的 blob 长度不参与校验。

### UKI 度量：`tdx.uki`

```json
{ "type": "tdx.uki", "value": "5bee5bdf63538ba7aa5c60d4725193c88932aa17083276fe9d61e4963ab6f871cdf3b3dd5d99733169b8c87a5e8e62b3" }
```

钉住统一内核镜像（UKI）的度量。固件把 UKI 当作 EFI 启动应用测度，记一条 `EV_EFI_BOOT_SERVICES_APPLICATION` 事件。条目要求至少有一条这样的事件。每条事件都要带 SHA-384 摘要，这些事件里的 SHA-384 摘要必须全部相同，且等于钉住的值。条目不看 device path，所以只适合只有一份启动应用的部署；日志里出现另一个摘要不同的启动应用，条目就失败。不用 UKI 启动的部署不会产生这类事件，配置这个条目会让它们失败，这类部署应该改用 `tdx.kernel`。

### 容器镜像：`com.alibabacloud.container.image.<repo>`

```json
{ "type": "com.alibabacloud.container.image.model-server", "value": "sha256:c5945b51138c975fe3f0315a17a469b87f009ceaa6fc69ba461c5811fbb781a0" }
```

该条目与阿里云耦合：证据来自 AAEL `alibabacloud.com` 事件。它钉住工作负载镜像的 OCI manifest digest。证据是事件类型为 `EV_EVENT_TAG` 的 AAEL `kangaroo/pull-image` 事件。条目看的是仓库名为 `<repo>` 的事件。至少要有这样一条事件，每条都带 `digest`，并且所有事件的 digest 相同，等于钉住的 `sha256:` 值。`<repo>` 是镜像 reference 的最后一段路径，去掉 registry 主机、路径前缀、tag 和 digest。只能使用 ASCII 字母、数字、`.`、`_`、`-`；包含 `/`、`@`、`:` 的名字不可能与 reference 匹配，会在策略加载时被拒绝。同一个类型写在 `transparency_log` 条目的 `publishedMeasurements` 或 `fallbackPublishedMeasurements` 中时，要与透明日志里的记录一致，通常就是同一个最后一段路径。没有匹配的拉取事件时，条目失败。

### 模型：`com.alibabacloud.ai.model.<model-id>`

```json
{ "type": "com.alibabacloud.ai.model.Qwen/Qwen3.8-27B", "value": "c2d3b69b8fe371d95c80e3962669156810c0328c6165306b8decf843149184a9" }
```

该条目与阿里云耦合：证据来自 AAEL `alibabacloud.com` 事件。它钉住模型的完整性度量哈希，64 位小写 hex。证据是事件类型为 `EV_EVENT_TAG` 的 AAEL `pai/load-model` 事件。`<model-id>` 要与事件里的模型标识逐字一致（建议用 modelscope-id 风格），可以包含 ASCII 字母、数字、`.`、`_`、`/`、`@`、`:`、`+`、`-`；其它字符在加载期即被拒绝。至少要有这样一条加载事件。每条事件都要带 `model-id` 和 `hash`；所有 `model-id` 都等于 `<model-id>`，所有 `hash` 都等于钉住的值。出现另一个模型的加载事件也会让条目失败。哈希怎么算由模型自己的度量约定决定，例如对落盘模型算 fs-verity digest。

### 根文件系统：`rootfs.cc`

```json
{ "type": "com.alibabacloud.rootfs.cc", "value": "44f6a7c111eb0d9f4dcbace76e784689dde3436c08bf7dda8d86d9f8c0b02230" }
```

该条目钉住机密容器根文件系统的 dm-verity hash tree 根哈希，64 位小写 hex，不带 `sha256:` 前缀。证据是 UEFI 事件日志里 `details.string` 以 `td_payload_info ` 开头的 `EV_PLATFORM_CONFIG_FLAGS` 事件。所有这类事件都必须记录在 RTMR1（寄存器索引 2）；索引不是 2 或缺失时条目失败。根哈希取自事件字符串里的 `dm-mod.create="verity-root,..."` 表：设备名必须是 `verity-root`，算法为 `sha256`，哈希为小写 hex。同一字符串里的其它 dm 设备不参与提取。不带 `verity-root` 表的事件被忽略，但至少要有一条事件带表，且提取出的所有根哈希必须相同并等于钉住的值。没有匹配事件、没有 `verity-root` 表，或者出现两个不同的根哈希，条目都失败。

在 `transparency_log` 条目的 `publishedMeasurements` 或 `fallbackPublishedMeasurements` 中写 `rootfs.cc`。带前缀的写法会在加载时被拒绝。

### TDX 平台属性：`tdx`

```json
{ "type": "tdx", "value": { "debug": "deny", "eventlog": "required" } }
```

加这个条目会检查 TDX quote 里的平台属性。每个字段不写时取最严格的值，所以 `{"type": "tdx", "value": {}}` 就是严格检查。`tcb` 和 `collateral` 需要显式配置，不写就不检查。条目没有开关，不想检查这些属性就不要加。

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

`debug` 取 `deny` 时，即使其余检查全过，启动带 debug 属性的 TD 仍被拒绝（quote TD attributes 首字节为奇数，如以 `01` 开头）。其余字段取默认值时，正常的生产 TD 通过 `{"type": "tdx", "value": {}}`。

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

开启对应检查时，debug TD、被吊销的 TCB、命中 `reject_advisories` 且未被 `allow_advisories` 豁免的 advisory，以及 `allow_expired` 为 `false` 时过期的 collateral，都会让条目失败。

### GPU 证明事件：`com.alibabacloud.gpu`

```json
{ "type": "com.alibabacloud.gpu", "value": {} }
```

该条目没有无前缀别名，取值必须是空对象 `{}`。它与阿里云耦合：证据是证明代理产生的 AAEL `alibabacloud.com` `gpu/attestation` 事件。事件日志里必须至少存在一条此类事件，且每条事件的两个结果码 `gpu-collect-evidence-result-code` 与 `gpu-attest-result-code` 都必须为 0。第一个码表示证据收集是否成功，第二个码表示 GPU 证明结果。事件日志重放保证这些码在启动后未被篡改，但码本身仍是客户机自报的。

要评定逐 GPU 的设备 claims 而不是客户机自报的结果码，请用 `nvidia`。

### GPU 评定：`nvidia`

不写该条目即完全不评 GPU。写了该条目，即评定验证器从证据携带的 GPU 材料推出的逐 GPU claims：身份、版本、CC 模式与度量，按下方字段比对。只透传原始 GPU 证明报告、未经逐 GPU 评定的证据会被拒绝；证据里没有的 GPU 过不了数量检查。因此该评定要求 attester 上行 GPU 证据；本来不采集 GPU 证据的部署会直接失败。

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

**当前强度上限。** 该评定比对的是经评定的设备 claims。GPU 证明报告的签名、GPU 证书链、驱动 RIM 文件的密码学校验属验证器侧后续工作；补齐之前，评定反映的是验证器解析报告时记录的 claims，而非报告本体的真实性。

### 透明日志：`transparency_log`

```json
{ "type": "transparency_log", "value": {
    "publishedMeasurements": ["tdx.td-shim", "container.image.cmaas-runtime"],
    "schemaVersion": "1.0.0",
    "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 2310520944 }]
} }
```

用这个条目把可信度量值放在透明日志记录的 ReleaseManifest 里，不必把摘要写进策略。appraisal 时，TNG 把当前证据里的度量值与日志里的基线比对，策略只负责指向那条日志记录。这是 `modules` 的条目类型；早期版本顶层 `attestation_policy.type = "transparency_log"` 的写法已不存在。

**加载期与 appraisal 期。** primary 为 `rekor-v1` 时，TNG 在策略加载时拉取并检查日志条目：按 `logIndex` 取出条目，校验签名 checkpoint、Merkle 包含证明与 Signed Entry Timestamp。省略 `rekorPublicKeyPem` 时使用 `rekor.sigstore.dev` / `rekor.openanolis.cn` 的知名公钥；其他日志必须提供自己的公钥。条目逐个拉取，因此包含多个 `rekor-v1` 条目的策略会为每个条目各做一次查询。primary 为 `artifact-server` 时，策略加载不访问网络，条目在 appraisal 时解析。

**校验内容。** 条目把当前 TDX 证据里的度量值与透明日志记录的基线比对。度量类型、任一取值或 `schemaVersion` 与基线不一致时，验证失败。`publishedMeasurements` 的顺序不影响结果。证据缺少任一配置的度量时，验证失败；TNG 不会拿少了这一项的基线与证据比对。发布者签名始终校验：配置了 `publisherPublicKeyPem` 就用它，否则用内置发布者公钥。

**fallback。** 可选的 fallback 只在 primary 返回 `fail` 时使用。`ok` 不会触发；`deny` 表示度量被撤销，是直接拒绝，不会回退。primary 因为缺少配置的度量而无法评定时，按 `fail` 处理，fallback 仍会被咨询。primary 失败且没有配置 fallback，条目拒绝。

**和 `tdx` 条目的关系。** 这个条目只检查度量，平台属性由独立的 `tdx` 条目检查。

**同一组里出现多次。** `transparency_log` 是唯一可以在同一组里重复出现的条目类型。同一组的多个条目必须全部通过；分在不同组的条目互为备选，任意一组通过即可。前者用于要求多条日志同时成立，后者用于接受多个版本中的任意一个。

```json
"modules": [
    { "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 100 }] } },
    { "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.openanolis.cn", "logIndex": 200 }] } }
]
```

```json
"modules": [
    [{ "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 100 }] } }],
    [{ "type": "transparency_log", "value": { "publishedMeasurements": ["container.image.cmaas-runtime"], "services": [{ "type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 200 }] } }]
]
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `publishedMeasurements` | string 列表 | — | （必填）非空度量类型列表；允许值为 `tdx.td-shim`、`tdx.kernel`、`rootfs.cc` 以及任意单段 `container.image.<repo>`，同一类型不得重复。容器镜像与 `rootfs.cc` 类型要和透明日志里记录的名字完全一致；`com.alibabacloud.` 别名与日志记录不一致，会在加载时被拒绝。顺序不影响结果 |
| `schemaVersion` | string | `"1.0.0"` | 必须等于日志 manifest 的 `schemaVersion` |
| `services` | 列表 | — | （必填）恰好一个 service，取 `rekor-v1` 或 `artifact-server` |
| `services[].type` | string | — | （必填）`"rekor-v1"` 或 `"artifact-server"` |
| `services[].logUrl` | string | — | （`rekor-v1` 必填）Rekor v1 日志基地址 |
| `services[].logIndex` | int | — | （`rekor-v1` 必填）要拉取并认证的 Rekor v1 条目索引；必须 `>= 0` |
| `services[].rekorPublicKeyPem` | string | 内建 | 可选的日志公钥 PEM（校验 checkpoint/SET）；省略时使用 `rekor.sigstore.dev` / `rekor.openanolis.cn` 的知名公钥，其他日志必须提供 |
| `services[].publisherPublicKeyPem` | string | 内建发布者公钥 | 覆盖 DSSE 签名校验所用的发布者公钥 |
| `services[].url` | string | — | （`artifact-server` 必填）Artifact-server 基地址 |
| `services[].logServices` | 列表 | — | （`artifact-server` 必填）非空的 `{"type": "rekor-v1", "url": "<rekor url>"}` 条目列表，各 URL 不得重复 |
| `fallbackPublishedMeasurements` | string 列表 | 缺省 | fallback 路径使用的度量类型；非空，且是 `publishedMeasurements` 的子集。只有该字段与 `fallbackServices` 同时设置时 fallback 才生效；只设置该字段而不设 `fallbackServices` 会被拒绝 |
| `fallbackServices` | 列表 | 缺省 | 非空的 `rekor-v1` service 列表；只能与 `artifact-server` primary 一起使用。只使用第一个条目，且 fallback 还需要 `fallbackPublishedMeasurements`，因此该字段单独设置不产生效果 |

**从顶层类型迁移。** 把旧策略的取值包进一个 `modules` 条目：`{"type": "modules", "modules": [{"type": "transparency_log", "value": <旧取值>}]}`。若需要旧的 non-debug 与事件日志检查，再加一个 `tdx` 条目（TDX 识别是自动的）；只有 `transparency_log` 条目时 `hardware` 退化为仅要求该识别。删除任何非空 `reference_values`，新策略会在加载期拒绝它。

## 从固定策略类型迁移

| 已删除类型 | `modules` 等价写法 |
|---|---|
| `transparency_log`（顶层 `attestation_policy.type`） | 用 `modules` 策略承载一个 `transparency_log` 条目；需要旧平台检查时再加 `tdx` 条目；删除任何非空 `reference_values` |
| `hardware_with_reference_values` | 启动度量类条目（`tdx.td-shim`/`tdx.ovmf`、`tdx.kernel`、`tdx.uki`）把预期摘要直接钉在策略里；需要日志锚定基线则用 `transparency_log` |
| `hardware_strict_with_reference_values` | 同上，另加 `{"type": "tdx", "value": {"sept_ve_disable": "allow", "perfmon": "allow", "service_td": "allow"}}`，在 TDX 证据上对齐旧的严格检查 |
| `hardware_strict_with_measurements` | `com.alibabacloud.ai.model.<model-id>` 与 `com.alibabacloud.container.image.<repo>` 条目把同样的基线内联钉住，另加 `sept_ve_disable`、`perfmon`、`service_td` 均设为 `allow` 的 `tdx` 条目，在 TDX 证据上对齐旧的严格检查；独立的 `reference_values` 列表不再需要 |

在 TDX 证据上，把单个 `{"type": "tdx", "value": {}}` 条目的 `sept_ve_disable`、`perfmon`、`service_td` 三项都设为 `allow` 才与 `hardware_only_strict` 一致：`tdx` 的默认还会门控这三个属性，因此原样写该条目比 `hardware_only_strict` 更严。该等价关系只对 TDX 证据成立，因为 `tdx` 条目在其它平台上会直接失败。空 modules 列表不等价于 `hardware_only`：它不做任何断言，`hardware` 保持非 affirming。
