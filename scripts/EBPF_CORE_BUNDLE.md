# Akto eBPF core — tarball bundle (bare Linux)

This document is for **clients** who install the **dockerless** eBPF core bundle (Go binary + BPF object + shell wrappers), distributed as a versioned **`.tar.gz`**.

Typical object names:

`akto-mirroring-module-ebpf-core-<version>-<amd64|arm64>.tar.gz`

---

## Prerequisites

- **Linux** on the target host (amd64 or arm64 matching the tarball you download).
- **Kernel / BPF**: CO-RE expects host BTF (typically `/sys/kernel/btf/vmlinux`) and sufficient privileges to load BPF (often root or the same capability set as your Kubernetes DaemonSet).
- **Network**: reachability to the Kafka broker you configure in `.env`.

---

## Install

### 1. Download the archive

Use the HTTPS download URL Akto provides. Choose the build whose **arch** matches this machine (`amd64` vs `arm64`).

```bash
wget -O akto-mirroring-module-ebpf-core-<version>-<arch>.tar.gz "<ARTIFACT_URL>"
```

(`curl -fL "<ARTIFACT_URL>" -o akto-mirroring-module-ebpf-core-<version>-<arch>.tar.gz` works the same way.)

### 2. Unpack (default layout: `/ebpf`)

As **root** (paths in the archive are rooted at `ebpf/`):

```bash
sudo tar -xzf akto-mirroring-module-ebpf-core-<version>-<arch>.tar.gz -C /
```

This creates **`/ebpf/`** including:

| Path | Role |
|------|------|
| `ebpf/ebpf-logging` | Main Go binary |
| `ebpf/kernel/module.bpf.o` | Compiled BPF object |
| `ebpf/ebpf-run.sh` | Supervisor loop |
| `ebpf/run-ebpf-core-host.sh` | Optional host entrypoint (sudo wrapper) |
| `ebpf/.env` | Default environment (edit before production) |

If you install under a **different** directory, set **`EBPF_ROOT`** consistently (see below) and keep **`ebpf-run.sh`** and **`.env`** together under that directory.

### 3. Configure

Edit **`/ebpf/.env`** (or **`${EBPF_ROOT}/.env`**). At minimum set **`AKTO_KAFKA_BROKER_MAL`** to your broker (replace the `<kafka-ip>` placeholder in the shipped template).

Typical bare-metal defaults in that file:

- **`EBPF_ROOT=/ebpf`** — bundle root.
- **`HOST_MAPPING=/`** — host path prefix (use **`/host`** when running inside Docker with `-v /:/host`).

### 4. Run

```bash
sudo /ebpf/run-ebpf-core-host.sh
```

Or with a non-default install root:

```bash
sudo EBPF_ROOT=/opt/akto/ebpf /opt/akto/ebpf/run-ebpf-core-host.sh
```

Ensure **`EBPF_ROOT`** in the environment matches **`EBPF_ROOT`** in **`.env`** when you use a custom path.
