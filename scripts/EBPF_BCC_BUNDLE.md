# Akto eBPF bcc — tarball bundle (bare Linux)

This document is for **clients** who install the **dockerless** eBPF bundle (Go binary + module.cc + shell wrappers), distributed as a versioned **`.tar.gz`**.

Typical object names:

`akto-mirroring-module-<version>-<os>-<kernel>-<arch>.tar.gz`

---

## Prerequisites

- **Linux** on the target host (amd64 or arm64 matching the tarball you download).
- **Kernel / BPF**: eBPF expects bcc libraries and kernel headers to be present for your OS.  
- See link for installation 
https://github.com/iovisor/bcc/blob/master/INSTALL.md#amazon-linux-2---binary
- **Network**: reachability to the Kafka broker you configure in `.env`.

---

## Install

### 1. Download the archive

Use the HTTPS download URL Akto provides. Choose the build whose **arch** matches this machine (`amd64` vs `arm64`).

```bash
wget -O akto-mirroring-module-<version>-<os>-<kernel>-<arch>.tar.gz "<ARTIFACT_URL>"
```

(`curl -fL "<ARTIFACT_URL>" -o akto-mirroring-module-<version>-<os>-<kernel>-<arch>.tar.gz` works the same way.)

### 2. Unpack (default layout: `/ebpf`)

As **root** (paths in the archive are rooted at `ebpf/`):

```bash
sudo tar -xzf akto-mirroring-module-<version>-<os>-<kernel>-<arch>.tar.gz -C /
```

This creates **`/ebpf/`** including:

| Path | Role |
|------|------|
| `ebpf/ebpf-logging` | Main Go binary |
| `ebpf/kernel/module.cc` | C kernel code |
| `ebpf/ebpf-bcc-run.sh` | Supervisor loop |
| `ebpf/run-ebpf-bcc-host.sh` | Host entrypoint (sudo wrapper; **detached by default**) |
| `ebpf/uninstall-ebpf-bcc-host.sh` | Stops processes; leaves `${EBPF_ROOT}` on disk |
| `ebpf/.env` | Default environment (edit before production) |

If you install under a **different** directory, set **`EBPF_ROOT`** consistently (see below) and keep **`ebpf-bcc-run.sh`** and **`.env`** together under that directory.

### 3. Configure

Edit **`/ebpf/.env`** (or **`${EBPF_ROOT}/.env`**). At minimum set **`AKTO_KAFKA_BROKER_MAL`** to your broker (replace the `<kafka-ip>` placeholder in the shipped template).

Typical bare-metal defaults in that file:

- **`EBPF_ROOT=/ebpf`** — bundle root.
- **`HOST_MAPPING=/`** — host path prefix (use **`/host`** when running inside Docker with `-v /:/host`).
- **`ENABLE_LOGS=false`** / **`LOG_FILE=/ebpf/dump.log`** — shipped defaults; if you change **`EBPF_ROOT`**, set **`LOG_FILE`** under that directory (for example **`/opt/akto/ebpf/dump.log`**).

### 4. Run (detached by default)

`run-ebpf-bcc-host.sh` starts the supervisor under **`nohup`** and returns immediately. It writes **`${EBPF_ROOT}/ebpf-bcc-run.pid`**. **`nohup.out`** is not used. With **`ENABLE_LOGS=false`**, **`ebpf-bcc-run.sh`** attaches non-TTY stdout/stderr to **`LOG_FILE`** (see **`.env`** / **`MAX_LOG_SIZE`** for rotation).

```bash
sudo /ebpf/run-ebpf-bcc-host.sh
```

Follow logs:

- **`ebpf-bcc-run.sh`** shell output (memory lines, restarts) and collector when **`ENABLE_LOGS=false`** (bundle default): `tail -f /ebpf/dump.log` or override **`LOG_FILE`** in **`.env`**

Attach to the supervisor in the foreground (blocks this shell), for debugging:

```bash
sudo /ebpf/run-ebpf-bcc-host.sh -f
# or: sudo AKTO_FOREGROUND=true /ebpf/run-ebpf-bcc-host.sh
```

Or with a non-default install root:

```bash
sudo EBPF_ROOT=/opt/akto/ebpf /opt/akto/ebpf/run-ebpf-bcc-host.sh
```

Ensure **`EBPF_ROOT`** in the environment matches **`EBPF_ROOT`** in **`.env`** when you use a custom path.

### 5. Uninstall

Stops **`ebpf-bcc-run.sh`** / **`ebpf-logging`** for this install (using the pidfile when present, then matching processes). It does **not** remove **`EBPF_ROOT`**.

```bash
sudo /ebpf/uninstall-ebpf-bcc-host.sh -y
```

Custom root:

```bash
sudo EBPF_ROOT=/opt/akto/ebpf /opt/akto/ebpf/uninstall-ebpf-bcc-host.sh -y
```

Omit **`-y`** for an interactive confirmation (requires a TTY).
