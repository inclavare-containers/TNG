# 日志配置

TNG 通过 `tracing` 生态输出日志。本文档说明 TNG 二进制的日志选项，以及 `tng-hook` 共享库如何与之协同记录日志。

## 输出格式

`--log-format <text|json>` 选择纯文本（默认）或 JSON Lines——每行一个 JSON 对象。环境变量 `TNG_LOG_FORMAT` 优先级高于命令行参数（取值为 `text` 或 `json`，大小写不敏感）。当日志由期望结构化记录的采集器收集时，推荐使用 JSON Lines。

## 日志文件

`--log-file <PATH>` 将 tracing 输出写入文件（追加模式）。未指定时，TNG 写入 stdout/stderr。

## 错误日志

`--log-error-file <PATH>`（环境变量 `TNG_LOG_ERROR_FILE`，优先级高于命令行参数）将 ERROR 级别日志单独写入一个文件。非错误日志（INFO、WARN、DEBUG）只写 `--log-file`；ERROR 级别只写错误文件——两者**互不重叠**（同一条日志不会出现在两个文件里）。这样可以直接扫 `error.log.tng` 快速定位问题，不用翻大量 INFO 日志。错误文件复用与主文件相同的滚动配置（无单独命令行参数）。开启滚动时，hook 的错误文件名为 `error.log.<pid>.tng`（与 info 文件同样的 PID 派生规则）。

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

`tng-hook` 路径不同：hook **同步**写入（无 `non_blocking` worker）。滚动开启时仍会加约 8 KiB 滚动 appender 缓冲（8 KiB 或轮转时刷盘）；滚动关闭时直接写入文件。

## `tng exec` 下 `tng-hook` 的日志行为

`tng exec` 启动一个预加载了 `tng-hook` 共享库的子进程。hook 与主进程一同记录日志：

- **滚动关闭（默认）：** hook 共享父进程的日志文件，并发追加。两者写出相同的 JSON/文本格式。
- **滚动开启：** hook 写入**自己的**文件，文件名由父进程路径在最后一个 `.`-扩展名前插入 `.<pid>` 得到，并独立轮转。父进程与 hook 从不共享文件，因此轮转不会丢失对方的数据。

命名规则：取父进程路径，在最后一个 `.`-扩展名之前插入 `.<pid>`。示例（pid 为 `12345`）：

| 父进程路径 | Hook 文件 |
|---|---|
| `info.log.tng` | `info.log.12345.tng` |
| `tng.log` | `tng.12345.log` |
| `tng`（无扩展名） | `tng.12345` |

因此 hook 的编号备份（如 `info.log.12345.tng.1`）绝不会与父进程的备份（`info.log.tng.1`）冲突。

滚动开启时 hook 与父进程使用相同的带缓冲 appender，刷盘行为一致（见 [刷盘行为](#刷盘行为)）。

## 示例（容器入口）

```bash
tng exec --config-file "$TNG_CONFIG" \
  --log-format json \
  --log-file /home/admin/logs/info.log.tng \
  --log-rolling --log-max-size 64MB --log-max-backups 5 \
  -- "$INFER_LAUNCHER"
```
