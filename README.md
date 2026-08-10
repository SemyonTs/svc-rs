# svc-rs — A Simple Service Manager (Supervisor) for UNIX Systems

`svc-rs` is a lightweight service manager (supervisor) for UNIX-like systems, written in Rust. It starts and monitors processes, restarts them on failures, manages dependencies, handles logging, and accepts commands via a local UNIX socket.

---

## 1. Building

Install **Rust** and **Cargo**, then:

```bash
git clone https://github.com/SemyonTs/svc-rs.git
cd svc-rs
cargo build --release
```

The binary can be copied to `/usr/local/bin/` or anywhere in your `PATH`.

---

## 2. Running the Supervisor

The program runs as a background process (daemon). It takes a single argument: the **root service directory** (defaults to `/etc/svc`):

```bash
svc /etc/svc &
```

You can use `nohup` when launching if you don't want `svc` to terminate when the shell closes.

If no directory is specified, `/etc/svc` is used.  
The process will run until it receives `SIGTERM` or `SIGINT`.

---

## 3. Service Directory Structure

Each service is a subdirectory inside the root directory, e.g., `/etc/svc/myapp`.  
Inside the subdirectory, there **must** be an executable file named `run` — this is the main process.

**Additional optional files/directories:**

| File/Directory | Purpose |
|----------------|---------|
| `run`          | **Required** – script or binary that runs as the service. |
| `log/run`      | A script that receives the service's stdout/stderr on its `stdin` (logger). |
| `depends`      | List of dependencies (one name per line). Lines starting with `?` indicate soft dependencies (do not block startup). |
| `user`         | Username (or UID) to run the process as. |
| `group`        | Group name (or GID) for the process. |
| `down`         | If present, the service will **not** start automatically when the supervisor starts. |
| `once`         | Service runs **once** and will not be restarted after it exits. |
| `finish`       | Executed after the main process exits; receives two arguments: exit code and signal number. |
| `check`        | Executable for health checks (invoked by the `check` command). |

**Logs** are written to the `log/` subdirectory inside the service directory:
- `current.out` – standard output
- `current.err` – standard error

When logs reach 1 MB, they are rotated (a timestamp and rotation number are appended as a suffix).

---

## 4. Control via UNIX Socket

The program creates a control socket in the root directory:  
`<root>/.control.sock` (e.g., `/etc/svc/.control.sock`).  
Commands are sent through this socket (e.g., using `nc -U`).

#### Connecting and Sending Commands

```bash
nc -U /etc/svc/.control.sock
```

After connecting, type commands (each command must end with a newline).  
Example — show the status of all services:
```
list
```

#### Available Commands

| Command | Description |
|---------|-------------|
| `list` or `stat` | Show status of all active services. |
| `status <name>` | Show detailed status of a specific service. |
| `start <name>` | Manually start a service (if stopped). |
| `stop <name>` | Stop a service and **all services that depend on it** (recursively). |
| `restart <name>` | Restart a service (stop and start again). |
| `down <name>` | Disable auto-start (creates a `down` file in the service directory). |
| `up <name>` | Enable auto-start (removes the `down` file). |
| `once <name>` | Set the `once` flag (creates a `once` file). |
| `check <name>` | Run the `check` script and return its exit code. |
| `reload` | Rescan service directories (scheduled, but scanning happens automatically every 15 seconds anyway). |
| `signal <name> <signum>` | Send signal number `signum` to the service process (and its entire process group). |
| `hup <name>` | Send SIGHUP. |
| `term <name>` | Send SIGTERM. |
| `kill <name>` | Send SIGKILL. |
| `usr1 <name>`, `usr2 <name>` | Send SIGUSR1/SIGUSR2. |
| `int <name>` | Send SIGINT. |
| `quit <name>` | Send SIGQUIT. |
| `alrm <name>` | Send SIGALRM. |
| `cont <name>` | Send SIGCONT. |

All commands return a response prefixed with `OK:` or `ERROR:`.

#### Examples

```bash
echo "start nginx" | nc -U /etc/svc/.control.sock
echo "status nginx" | nc -U /etc/svc/.control.sock
echo "hup nginx" | nc -U /etc/svc/.control.sock   # reload configuration
```

---

## 5. Auto-start and Restart Policies

- On startup, the supervisor scans directories and starts all services that **do not** have a `down` file and are not marked with `once` (though `once` doesn't prevent the initial start; it only prevents restarts after exit).
- If a process exits (or crashes), the supervisor tracks restart frequency:
  - Maximum 5 restarts within 60 seconds;
  - If the limit is exceeded, the service enters the `failed` state and will no longer restart automatically.
- Backoff delays before restarts depend on the failure count: 2, 10, or 60 seconds.

---

## 6. Stopping the Supervisor

When receiving `SIGTERM` or `SIGINT`, the supervisor:
1. Sends `SIGTERM` to all services (and loggers), waiting up to 5 seconds for them to terminate.
2. If any processes haven't terminated, it sends `SIGKILL`.
3. Closes the control socket and exits.

---

## 7. Example: Creating a Simple Service

Create the directory `/etc/svc/myapp` and inside it a file `run` with the following content:

```bash
#!/bin/sh
while true; do
  echo "Hello, world!"
  sleep 10
done
```

Make it executable: `chmod +x /etc/svc/myapp/run`.  
Then start `svc /etc/svc` – the service will begin running, and logs will appear in `/etc/svc/myapp/log/current.out`.

To disable auto-start:

```bash
touch /etc/svc/myapp/down
echo "stop myapp" | nc -U /etc/svc/.control.sock
```

---

## Additional Notes

- The program is written with `no_std`, uses only `libc`, and is portable across UNIX-like systems.
- For control via the socket, `socat` or `nc` are convenient tools.
- Logs are rotated, but old files are not deleted automatically — monitor disk space manually.
- If you have questions, refer to the source code or contact the author.

---

**License:** MPL‑2.0. See LICENSE and NOTICE before use.