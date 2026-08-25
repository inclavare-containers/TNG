# rats-cert

本 crate 从 [rats-rs](https://github.com/inclavare-containers/rats-rs/tree/eb6d630a7a44974c8dff34d418022354765e1262/rats-cert) 迁移而来，并集成进 TNG 工作区。

## 迁移说明

- 原始仓库：https://github.com/inclavare-containers/rats-rs
- 源码提交：`eb6d630a7a44974c8dff34d418022354765e1262`
- 原始路径：`rats-cert/`

## 策略配置

内建 Attestation Service（`as_type` = `"builtin"`）使用 OPA/Rego 策略对 evidence 进行 appraisal。策略变体由 `attestation_policy.type` 字段选择。除了内建的 `default`/`hardware_only`/`hardware_only_strict`/`hardware_with_reference_values`/`trust_all` 姿态之外，也支持 `inline`/`path` 自定义策略方式。
