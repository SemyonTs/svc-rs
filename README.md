# svc-rs

**Supervisor for long‑running processes** – a lightweight, no‑std daemon‑style service manager inspired by daemontools and s6.

It runs as a single process, periodically scans a service directory (default `/etc/svc`), starts and restarts services respecting dependencies, logs their output, exposes a control socket, and shuts down cleanly.

---

## Overview

`svc-rs` is designed for minimalism and reliability:

- **Zero‑cost abstractions** – written in Rust without the standard library.
- **Single‑binary**, no external dependencies – uses only `libc`.
- **Process supervision** with automatic restart, backoff, and circuit‑breaker logic.
- **Dependency‑aware** startup and shutdown (hard & soft dependencies).
- **Per‑service logging** with rotation, or delegation to a custom `log/run` logger.
- **Control via UNIX socket** – list, start, stop, restart, signal, etc.
- **Security** – per‑service user/group, chroot, resource limits, nice.
- **Signal‑safe** using the self‑pipe trick.

---

## Command‑line Usage

```bash
svc-rs [SERVICE_ROOT]
```

If no argument is given, the supervisor looks for services in `/etc/svc`.  
The `SERVICE_ROOT` directory contains one subdirectory per service.

---

## Service Directory Structure

Each service is a directory under `SERVICE_ROOT`.  
The only required file is an executable `run`.

Additional files control behaviour:

| File / Directory           | Purpose |
|----------------------------|---------|
| `run`                      | **Required** – the main executable (must be executable, `X_OK`). |
| `down`                     | If present, the service is **not** auto‑started at boot. |
| `once`                     | If present, the service runs **once** and never restarts (flag is cleared after exit). |
| `depends`                  | List of dependencies, one per line. Lines starting with `?` are **soft**; others are **hard**. |
| `user` / `group`           | Username or numeric UID/GID to run the service as (and its `finish`, `log/run`, `check`). |
| `env`                      | Environment variables in `KEY=value` format (one per line; leading/trailing whitespace is stripped; lines starting with `#` are ignored). |
| `root`                     | If present, the service runs inside a **chroot** to its own directory. |
| `check`                    | Executable run by the `check` control command. |
| `finish`                   | Executable run after the main process exits; receives exit code and signal number as arguments. |
| `log/run`                  | If present, `stdout`/`stderr` of the main process are piped into this logger process (instead of direct file logging). |
| `rlimit_cpu` / `rlimit_as` / `rlimit_nofile` / `rlimit_fsize` / `rlimit_nproc` / `rlimit_core` | Set corresponding resource limits (one decimal number). |
| `nice`                     | Nice value (positive or negative integer) applied before executing `run`. |
| `status`                   | **Written by the supervisor** – current state, PID, uptime, restarts, etc. |

---

## Lifecycle of a Service

### Startup
1. The supervisor scans the service directory every 15 seconds (or on `SIGHUP`).
2. If a service is marked for auto‑start (`down` absent) and is not `once`, and all **hard** dependencies are running, it is started.
3. The `start_service()` function:
   - Reads `env`, user/group, checks `root`.
   - If `log/run` exists, it is forked first (in its own session), and its stdin becomes the main process’s stdout.
   - Otherwise two pipes are created (for stdout and stderr), and the read ends are kept for logging.
   - The main process is forked:
     - `setsid()` is called to create a new session.
     - If `root` exists, `chroot` to service directory + `chdir("/")`; otherwise `chdir` to service directory.
     - UID/GID are set if provided.
     - `stdin` is redirected to `/dev/null`, `stdout`/`stderr` to the appropriate pipes.
     - All file descriptors above 2 are closed.
     - Resource limits and nice are applied.
     - `execve("./run")` (or `"/run"` inside chroot).
4. The parent saves the PID, opens log files (if no `log/run`), and writes the `status` file.

### Restart Logic (Backoff & Circuit Breaker)
When the main process exits:
- If the service was stopped manually (`stopping = true`) or is `once`, it is not restarted.
- Otherwise, restarts are counted over a sliding window of **60 seconds**.
- If more than **5 restarts** occur in that window, the service enters `STATE_FAILED` and is **not restarted** until manually intervened (`start` or `up`).
- Otherwise a delay is applied:
  - < 5 restarts → 2 seconds
  - 5–19 restarts → 10 seconds
  - ≥ 20 restarts → 60 seconds
- After the delay, dependencies are re‑checked and the service is started again.

### Dependencies
- **Hard dependencies** (lines in `depends` without `?`) must be in `STATE_RUNNING`; otherwise the service is not started and is not restarted.
- **Soft dependencies** (prefixed with `?`) are ignored for startup checks.
- When a service stops (or crashes), all services that **hard‑depend** on it are stopped transitively (using an iterative propagation algorithm).
- On supervisor shutdown, services are stopped in **reverse dependency order**.

### Logging
- **Supervisor logs** are written to `/var/log/svc-rs.log` with rotation when size exceeds 1 MB.
- **Service logs** (if no `log/run`):
  - `stdout` → `<service>/log/current.out`
  - `stderr` → `<service>/log/current.err`
  - Rotation occurs when file size exceeds 1 MB; archives are renamed with timestamp and rotation counter.
- If `log/run` exists, it runs as a separate process and receives `stdout` of the main service on its `stdin`; the supervisor does no additional logging for that service.
- All file descriptors are marked `FD_CLOEXEC` to avoid leaks to child processes.

### The `finish` Script
If `finish` exists and is executable, it is forked after the main process exits. It receives two arguments:
1. the exit code (decimal)
2. the signal number that terminated the process (0 if normal exit)

It runs with the same environment, UID/GID, chroot, and resource limits as the main service.

### The `check` Script (Control Command)
The `check` command runs the `check` executable in the service’s environment. It waits for its completion and returns the exit code to the client.

---

## Control Socket

A UNIX socket is created at `<SERVICE_ROOT>/.control.sock`.  
Clients can connect and send commands (one line, arguments separated by spaces).

### Supported Commands

| Command                     | Description |
|-----------------------------|-------------|
| `list` or `stat`            | Show status of all active services. |
| `status <name>`             | Show detailed status of one service. |
| `start <name>`              | Start the service (sets `manual_start`, clears backoff delay). |
| `stop <name>`               | Stop the service and its hard dependencies. |
| `restart <name>`            | Stop then start the service (with `manual_start`). |
| `down <name>`               | Disable auto‑start (creates `down` file) and stop the service. |
| `up <name>`                 | Enable auto‑start (removes `down`) and allow restarts. |
| `once <name>`               | Set the `once` flag (creates `once` file). |
| `check <name>`              | Execute the service’s `check` script and return its exit code. |
| `reload`                    | Send `SIGHUP` to the supervisor, forcing a re‑scan of the service directory. |
| `signal <name> <signum>`    | Send an arbitrary signal number to the service’s process group. |
| `hup`, `term`, `kill`, `usr1`, `usr2`, `int`, `quit`, `alrm`, `cont` | Shortcuts – send the corresponding signal to the service. |

Responses are plain text prefixed with `OK:` or `ERROR:`.

---

## Signal Handling

- `SIGPIPE` is ignored.
- `SIGTERM`, `SIGINT`, `SIGHUP`, and `SIGCHLD` are caught.
- The **self‑pipe trick** is used: the signal handler writes the signal number into a pipe; the main loop reads it via `poll()`, ensuring race‑free processing.
- `SIGCHLD` does **not** trigger immediate reaping; instead the main loop calls `waitpid(-1, WNOHANG)` in every iteration.

---

## Resource Limits & Security

For each service, the supervisor applies the following **before** executing `run` (and also for `log/run`, `finish`, `check`):

- **Resource limits** – read from `rlimit_*` files and applied via `setrlimit()`.
- **Nice** – read from `nice` and applied via `nice()`.
- **User/Group** – if `user`/`group` are provided, `setgid`, `setgroups` (if gid != 0), and `setuid` are called.
- **chroot** – if `root` directory exists inside the service directory, `chroot()` is performed, then `chdir("/")`.

All child processes are spawned with `close_from(3)` to ensure no stray file descriptors are inherited.

---

## Shutdown

When the supervisor receives `SIGTERM` or `SIGINT`:

1. All services are stopped in reverse dependency order (SIGTERM sent to process groups).
2. It waits up to `SHUTDOWN_TIMEOUT_S` (5 seconds) for processes to exit, reaping and draining logs in the meantime.
3. Any remaining processes are killed with `SIGKILL`.
4. The control socket is removed, the supervisor log is closed, and the process exits with code 0.

---

## Internal Implementation Highlights

- **No heap allocation** – all data structures are statically sized arrays.
- **Non‑blocking I/O** – all pipes and the control socket are `O_NONBLOCK`; reading is performed until `EAGAIN`/`EWOULDBLOCK`.
- **Main event loop** – uses `poll()` with a 500 ms timeout to monitor:
  - the signal self‑pipe
  - the control socket
  - read ends of pipes from service processes
- **Owned file descriptors** – a zero‑cost RAII wrapper (`OwnedFd`) ensures file descriptors are closed on drop.
- **Portable errno** – works on Linux, macOS, and BSD variants.

---

## Limitations (Current Implementation)

- Maximum **256** services.
- Maximum **16** dependencies per service.
- Maximum **64** environment variables per service.
- Service names are limited to **63** characters.
- Path buffers are **1024** bytes.
- Poll array supports up to `MAX_SERVICES * 2 + 2` file descriptors.
- Resource limit values are parsed as decimal numbers only (no suffixes).

---

## License

`svc-rs` is licensed under the **Mozilla Public License 2.0** and is **Incompatible With Secondary Licenses**. 
See LICENSE and NOTICE before use.
Short notice text is embedded in the binary (`.license` section).

---

## Source Code

The source code is available at:  
[https://github.com/SemyonTs/svc-rs](https://github.com/SemyonTs/svc-rs)