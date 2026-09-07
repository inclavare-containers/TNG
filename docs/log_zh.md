# 日志配置

TNG 通过 `tracing` 生态输出日志。本文档说明 TNG 二进制的日志选项，以及 `tng-hook` 共享库如何与之协同记录日志。

## 输出格式

`--log-format <text|json>` 选择纯文本（默认）或 JSON Lines——每行一个 JSON 对象。环境变量 `TNG_LOG_FORMAT` 优先级高于命令行参数（取值为 `text` 或 `json`，大小写不敏感）。当日志由期望结构化记录的采集器收集时，推荐使用 JSON Lines。

## 日志文件

`--log-file <PATH>` 将 tracing 输出写入文件（追加模式）。未指定时，TNG 写入 stdout/stderr。

## 错误日志

`--log-error-file <PATH>`（环境变量 `TNG_LOG_ERROR_FILE`，优先级高于命令行参数）将 ERROR 级别日志单独写入一个文件。非错误日志（INFO、WARN、DEBUG）只写 `--log-file`；ERROR 级别只写错误文件，两者**互不重叠**（同一条日志不会出现在两个文件里）。这样可以直接扫 `error.log.tng` 快速定位问题，不用翻大量 INFO 日志。错误文件复用与主文件相同的滚动配置（无单独命令行参数）。`tng exec` 下，hook 的 ERROR 事件合并进同一个错误文件（见 [Hook 日志集中化](#hook-日志集中化)）。

## 滚动（按大小 + 份数）

`--log-rolling` 启用基于大小的滚动，需配合 `--log-file` 使用。

| 选项 | 环境变量（优先级更高） | 默认值 | 含义 |
|---|---|---|---|
| `--log-rolling` | `TNG_LOG_ROLLING`（`true`/`1`） | 关闭 | 启用滚动 |
| `--log-max-size <SIZE>` | `TNG_LOG_MAX_SIZE` | `64MB` | 触发轮转的单文件大小（`64MB`、`1GB`，或字节数） |
| `--log-max-backups <N>` | `TNG_LOG_MAX_BACKUPS` | `5` | 保留的轮转份数（`file.1` … `file.N`） |

环境变量优先级高于命令行参数。无效值会保持默认值并向日志流输出一条告警。`--log-max-size` 与 `--log-max-backups` 仅在滚动启用时生效；在未开启 `--log-rolling` 时设置二者会输出告警且不产生效果（默认值同样仅在滚动开启时生效）。

滚动使用 `tracing-rolling-file` crate，采用 Debian 命名风格：当前文件为 `file`，备份为 `file.1`、`file.2`、…、`file.N`（编号越小，备份越新）。仅支持按大小 + 保留份数裁剪——基于时间的裁剪（`MaxAge`）和 gzip 压缩 **不** 由该 crate 提供，TNG 也未暴露。

### 路径校验

请求启用滚动时，TNG 会校验 `--log-file` 路径。普通文件、指向普通文件的软链接、以及尚不存在的路径（TNG 会创建）都允许滚动。字符设备（如 `/dev/tty`、`/dev/null`）、块设备、FIFO、socket、目录会使滚动被禁用并输出告警，回退为普通追加——这类目标无法滚动。该告警在 tracing 初始化后经配置的日志接收端输出，因此出现在同一 JSON/文本日志流中，而非仅打到 stderr。

### 刷盘行为

主进程始终将 tracing 事件经 `tracing_appender::non_blocking`（一个异步 worker 通道，及时排空）输出。滚动只改变 worker 前端是否多一层缓冲：

- 滚动**关闭**：无滚动 appender 缓冲。日志行仅经非阻塞 worker 输出，及时排空。
- 滚动**开启**：`tracing-rolling-file` appender 在 worker 前端额外加一层约 8 KiB 的 `BufWriter`，累计约 8 KiB 或轮转时刷盘。对长驻服务（常见情况）不可见；仅极短生命周期的进程可能在退出前未刷出最后的部分缓冲。

`tng-hook` 路径不同：hook 把每条记录交给主 `tng exec` 进程，再由其投入与自身日志相同的 `non_blocking` worker（滚动开启时 worker 前端仍会加约 8 KiB 滚动 appender 缓冲；滚动关闭则跳过该层）。hook 日志绝不会阻塞宿主进程：当主侧处理跟不上时，hook 直接丢弃记录，而非拖慢数据面。

## Hook 日志集中化

`tng exec` 启动一个预加载了 `tng-hook` 共享库的子进程。主进程不让每个 hook 子进程各自打开日志文件，而是集中处理 hook 日志，让每条 hook 记录都合并进主进程持有的同一个 `--log-file` / `--log-error-file`。

hook 产生的 ERROR 进入错误文件，其余日志进入 info 文件。不留任何按进程拆分的日志文件，因此长时间运行且 hook 进程众多的部署不再有按进程滚动文件导致的 inode 耗尽风险。滚动由主进程集中管理，hook 自身不写任何滚动文件。

仅当日志路径是普通文件、指向普通文件的软链接、或尚不存在的路径（才能合并进主进程拥有的同一个滚动文件）时才集中化。info 流与 error 流分别判定。非普通路径（字符设备如 `/dev/null` 或 `/dev/tty`、FIFO、socket、目录）不集中化：hook 直接向该路径追加，无按进程文件。

集中化仅 Linux 可用；其他平台 hook 一律直接追加。

hook 记录与主进程使用相同的 JSON 或文本格式（由 `--log-format` 设定）。

## 示例（容器入口）

```bash
tng exec --config-file "$TNG_CONFIG" \
  --log-format json \
  --log-file /home/admin/logs/info.log.tng \
  --log-error-file /home/admin/logs/error.log.tng \
  --log-rolling --log-max-size 64MB --log-max-backups 5 \
  -- "$INFER_LAUNCHER"
```
