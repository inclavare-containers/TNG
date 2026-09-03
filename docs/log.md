# Log Configuration

TNG writes logs through the `tracing` ecosystem. This page covers the binary's log options and how the `tng-hook` shared library logs alongside it.

## Output format

`--log-format <text|json>` selects plain text (default) or JSON Lines — one JSON object per line. The environment variable `TNG_LOG_FORMAT` takes priority over the flag when set (`text` or `json`, case-insensitive). JSON Lines is recommended when logs are ingested by a collector that expects structured records.

## Log file

`--log-file <PATH>` writes tracing output to a file (appended). Without it, TNG writes to stdout/stderr.

## Rolling (size + count)

`--log-rolling` enables size-based rolling. It requires `--log-file`.

| Option | Env var (takes priority) | Default | Meaning |
|---|---|---|---|
| `--log-rolling` | `TNG_LOG_ROLLING` (`true`/`1`) | off | Enable rolling |
| `--log-max-size <SIZE>` | `TNG_LOG_MAX_SIZE` | `64MB` | Bytes per file before rotating (`64MB`, `1GB`, or a raw byte count) |
| `--log-max-backups <N>` | `TNG_LOG_MAX_BACKUPS` | `5` | Rotated backups to keep (`file.1` … `file.N`) |

Environment variables override the CLI flags. An invalid value keeps the default and emits a warning into the log stream. `--log-max-size` and `--log-max-backups` only take effect when rolling is enabled; setting either without `--log-rolling` emits a warning and has no effect (the defaults likewise only apply when rolling is on).

Rolling uses the `tracing-rolling-file` crate with Debian-style naming: the active file is `file`, and backups are `file.1`, `file.2`, …, `file.N` (newest backup has the lowest number). Only size and backup-count pruning are supported — age-based pruning (`MaxAge`) and gzip compression are **not** provided by the crate and are not exposed.

### Path validation

When rolling is requested, TNG checks the `--log-file` path. A regular file, a symlink to a regular file, or a not-yet-existing path (which TNG creates) all allow rolling. A character device (e.g. `/dev/tty`, `/dev/null`), a block device, a FIFO, a socket, or a directory disables rolling with a warning and falls back to plain append — rotating such targets is not meaningful. The warning is emitted through the configured log sink (after tracing is initialized), so it appears in the same JSON/text log stream rather than only on stderr.

### Flushing

The main process always funnels tracing events through `tracing_appender::non_blocking`, an async worker channel that drains promptly. Rolling only changes whether an extra buffer sits in front of that worker:

- Rolling **off**: no rolling-appender buffer. Lines reach the file with only the non-blocking worker in the path, which drains promptly.
- Rolling **on**: the `tracing-rolling-file` appender adds an ~8 KiB `BufWriter` in front of the worker. Lines flush at ~8 KiB fill or on rotation. For long-running services (the normal case) this is invisible; only a very short-lived process might not flush the final partial buffer before exit.

The `tng-hook` path is different: the hook writes **synchronously** (no `non_blocking` worker). Rolling on still adds the ~8 KiB rolling-appender buffer (flush at ~8 KiB or rotation); rolling off writes straight to the file.

## How `tng-hook` logs under `tng exec`

`tng exec` runs a child process with the `tng-hook` shared library preloaded. The hook reads its log config from environment variables injected by the parent:

| Env var | Source |
|---|---|
| `TNG_HOOK_LOG_FILE` | the parent's `--log-file` |
| `TNG_HOOK_LOG_FORMAT` | the parent's resolved format |
| `TNG_HOOK_LOG_ROLLING` / `TNG_HOOK_LOG_MAX_SIZE` / `TNG_HOOK_LOG_MAX_BACKUPS` | the parent's rolling config |

- **Rolling off (default):** the hook shares the parent's log file and appends concurrently. Both write the same JSON/text format.
- **Rolling on:** the hook writes its **own** file, named by inserting `.<pid>` before the last `.`-extension of the parent's path, and rolls it independently. The parent and the hook never share a file, so rotation cannot drop each other's data.

The naming rule: take the parent path and insert `.<pid>` immediately before the final `.`-extension. Examples (with pid `12345`):

| Parent path | Hook file |
|---|---|
| `info.log.tng` | `info.log.12345.tng` |
| `tng.log` | `tng.12345.log` |
| `tng` (no extension) | `tng.12345` |

The hook's numbered backups (e.g. `info.log.12345.tng.1`) therefore never collide with the parent's backups (`info.log.tng.1`).

The hook uses the same buffered appender as the parent when rolling is on, so the same flushing behavior applies (see [Flushing](#flushing)).

## Example (container entrypoint)

```bash
tng exec --config-file "$TNG_CONFIG" \
  --log-format json \
  --log-file /home/admin/logs/info.log.tng \
  --log-rolling --log-max-size 64MB --log-max-backups 5 \
  -- "$INFER_LAUNCHER"
```
