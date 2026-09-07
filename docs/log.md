# Log Configuration

TNG writes logs through the `tracing` ecosystem. This page covers the binary's log options and how the `tng-hook` shared library logs alongside it.

## Output format

`--log-format <text|json>` selects plain text (default) or JSON Lines — one JSON object per line. The environment variable `TNG_LOG_FORMAT` takes priority over the flag when set (`text` or `json`, case-insensitive). JSON Lines is recommended when logs are ingested by a collector that expects structured records.

## Log file

`--log-file <PATH>` writes tracing output to a file (appended). Without it, TNG writes to stdout/stderr.

## Error log

`--log-error-file <PATH>` (env `TNG_LOG_ERROR_FILE`, env takes priority) routes ERROR+ events to a separate file. Non-error events (INFO, WARN, DEBUG) go to `--log-file` only; ERROR+ events go to the error file only; the two are **disjoint** (an event never appears in both files). This lets you scan `error.log.tng` for problems without wading through verbose INFO logs. The error file reuses the same rolling config as the main file (no separate CLI). Under `tng exec`, the hook's ERROR events merge into the same error file (see [Hook log centralization](#hook-log-centralization)).

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

The `tng-hook` path is different: the hook hands each record to the main `tng exec` process, which funnels it into the same `non_blocking` worker as its own logs (rolling on still adds the ~8 KiB rolling-appender buffer in front of that worker; rolling off skips it). Hook logging never blocks the host process: if the main side falls behind, the hook drops records rather than stalling the data plane.

## Hook log centralization

`tng exec` runs a child process with the `tng-hook` shared library preloaded. Rather than each hooked child opening its own log file, the main process centralizes hook logging so every hook record merges into the same `--log-file` / `--log-error-file` the main process owns.

ERROR events from the hook land in the error file; everything else lands in the info file. There are no per-process log files, so a long-running deployment with many hook processes no longer risks inode exhaustion from per-process rolling files. Rolling is owned centrally by the main process; the hook writes no rolling files of its own.

Centralization applies only when the log path is a regular file, a symlink to a regular file, or a not-yet-existing path (so it can merge into the same rolling file the main process owns). The info and error streams are judged independently. A non-regular path (a character device such as `/dev/null` or `/dev/tty`, a FIFO, a socket, or a directory) is not centralized: the hook appends to that path directly, with no per-process file.

Centralization is Linux-only; on other platforms the hook always appends directly.

The hook records use the same JSON or text format as the main process (set by `--log-format`).

## Example (container entrypoint)

```bash
tng exec --config-file "$TNG_CONFIG" \
  --log-format json \
  --log-file /home/admin/logs/info.log.tng \
  --log-error-file /home/admin/logs/error.log.tng \
  --log-rolling --log-max-size 64MB --log-max-backups 5 \
  -- "$INFER_LAUNCHER"
```
