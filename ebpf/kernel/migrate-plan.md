# CO-RE Migration Phase 1: Accept + Connect with IP/Role Tracking

## Context

Migrate connection tracking (accept/connect) from BCC to CO-RE/BTF. Write a **new file** `module.bpf.c` — don't modify the existing BCC `module.cc`. Scope is limited to:
- Detect new connections (accept + connect)
- Capture local IP, remote IP, ports
- Set role (client/server)
- Proper logging via `bpf_printk`
- Ring buffer events to userspace

Data capture (read/write/send/recv) will be a separate plan.

## What the kernel probes actually do today (and how to simplify)

| Current probe | Purpose | Needed for accept/connect? |
|---|---|---|
| `probe_ret_sock_alloc` | Captures `struct socket*` during accept to read IPs from kernel sock struct | **Not needed** — use `fexit/inet_csk_accept` instead, which returns fully-populated `struct sock*` |
| `probe_entry_tcp_connect` | Captures `struct sock*` during connect for same reason | **Not needed** — use `fentry/tcp_connect` which gets `struct sock*` as arg |
| `security_socket_sendmsg` | Marks write args as socket (vs stdout/pipe) | **Not needed** — data capture scope |
| `security_socket_recvmsg` | Marks read args as socket | **Not needed** — data capture scope |
| `setsockopt` | Marks args as socket | **Not needed** — data capture scope |
| `syscall__probe_entry_accept` | Saves sockaddr, filters by pid/comm | **Replaced** by `tp/syscalls/sys_enter_accept4` — used for filtering only |
| `syscall__probe_ret_accept` | Gets fd, calls `process_syscall_accept` | **Replaced** by `tp/syscalls/sys_exit_accept4` — gets fd, pairs with fexit sock data |
| `syscall__probe_entry_connect` | Saves sockaddr + fd | **Replaced** by `tp/syscalls/sys_enter_connect` |
| `syscall__probe_ret_connect` | Calls `process_syscall_accept(isConnect=true)` | **Replaced** by `tp/syscalls/sys_exit_connect` |

### Accept Lifecycle — TRACEPOINTS ONLY (no fexit needed!)

```
sys_enter_accept4 + sys_enter_accept (hook both)
    │ Confirmed available:
    │   syscalls:sys_enter_accept
    │   syscalls:sys_enter_accept4
    │   syscalls:sys_exit_accept
    │   syscalls:sys_exit_accept4
    │ bpf_get_current_comm() → check traced_comms / trace_all_flag
    │ saves sockaddr ptr → ACTIVE_ACCEPT_ARGS[pid_tgid]
    │
sys_exit_accept4 + sys_exit_accept (hook both)
    │ ret = new fd (ctx->ret)
    │ if ret < 0 → cleanup and return (accept failed)
    │ reads ACTIVE_ACCEPT_ARGS for sockaddr ptr
    │ bpf_probe_read_user the sockaddr buffer (kernel filled it during accept)
    │ extracts raddr, rport from sockaddr (AF_INET or AF_INET6)
    │ laddr: read from /proc or leave as 0 (see note below)
    │ creates conn_info with role=kRoleServer
    │ emits conn_event → EVENTS ring buffer
    └ stores ConnInfo → CONN_INFO_MAP
    └ cleans up ACTIVE_ACCEPT_ARGS
```

**Why no fexit needed for accept**: By `sys_exit_accept4` time, the kernel has
filled the userspace `sockaddr` buffer with the remote peer's IP/port. We can
`bpf_probe_read_user` it directly. No need to walk kernel sock structs.

**Caveat — local IP**: The sockaddr only contains the **remote** IP. For the local
IP we have two options:
  1. Use `fexit/inet_csk_accept` to read `skc_rcv_saddr` from the returned sock (adds 1 fexit probe)
  2. Accept `laddr=0` for now — the local IP is the pod IP which can be resolved from userspace

**Recommendation**: Use option 1 (`fexit/inet_csk_accept`) since we already need
local IP for the zero-IP fix. This adds back 1 fexit probe but eliminates the
sock_alloc + 3-probe dance.

### Accept Lifecycle — WITH fexit for local IP (recommended)

```
sys_enter_accept4 + sys_enter_accept (hook both)
    │ filter + save sockaddr ptr → ACTIVE_ACCEPT_ARGS[pid_tgid]
    │
inet_csk_accept (fexit)
    │ ret = newly accepted struct sock*, fully populated
    │ reads laddr (skc_rcv_saddr), lport (skc_num) via BPF_CORE_READ
    │ saves {laddr, lport} → ACTIVE_ACCEPT_SOCK[pid_tgid]
    │
sys_exit_accept4 + sys_exit_accept (hook both)
    │ ret = new fd
    │ if ret < 0 → cleanup and return
    │ reads sockaddr via bpf_probe_read_user → raddr, rport
    │ reads ACTIVE_ACCEPT_SOCK → laddr, lport
    │ creates conn_info with role=kRoleServer
    │ emits conn_event, stores in CONN_INFO_MAP
    └ cleans up both temp maps
```

**Why fexit here**: Only to get the **local IP**. The remote IP comes from
userspace sockaddr. If local IP is not needed, this fexit can be dropped
and accept becomes pure tracepoints (2 probes instead of 3+fexit).

### Connect Lifecycle (3 probes)

```
sys_enter_connect (tracepoint)
    │ bpf_get_current_comm() → check traced_comms / trace_all_flag
    │ saves fd, sockaddr ptr → ACTIVE_CONNECT_ARGS[pid_tgid]
    │
tcp_v4_connect (fexit — fires AFTER function returns)
    │ reads skc_rcv_saddr + skc_num from sock via BPF_CORE_READ
    │ saves LaddrInfo{ip, port} → ACTIVE_CONNECT_SOCK[pid_tgid]
    │ WRITE-ONLY — never reads ACTIVE_CONNECT_ARGS
    │
sys_exit_connect (tracepoint)
    │ reads BOTH maps
    │ reads raddr from userspace sockaddr (saved in ACTIVE_CONNECT_ARGS)
    │ reads laddr from kernel sock (saved in ACTIVE_CONNECT_SOCK)
    │ creates conn_info with role=kRoleClient
    │ emits conn_event → EVENTS ring buffer
    └ stores ConnInfo → CONN_INFO_MAP
    └ cleans up both maps
```

**Why fexit is needed for connect (cannot use tracepoints only)**:
- `sys_enter_connect` gives us remote IP from userspace sockaddr ✓
- But **local IP** is assigned by the kernel during `tcp_v4_connect` (route selection)
- No syscall tracepoint exposes the local IP — it's a kernel-internal decision
- So we need `fexit/tcp_v4_connect` to read `skc_rcv_saddr` after route selection

**Why `tcp_v4_connect` and not `tcp_connect`**:
- `tcp_v4_connect` → does `ip_route_connect` (selects source IP) + `inet_hash_connect` (selects source port)
- `tcp_connect` → called after, sends SYN. IP already set.
- `tcp_v4_connect` is more specific — matches exactly where IP selection happens

**Why fexit not fentry**: `fentry` fires before `tcp_v4_connect` executes —
`skc_rcv_saddr` is 0 at that point. `fexit` fires after the function returns,
when the kernel has selected source IP and source port.

**IPv6**: Need `fexit/tcp_v6_connect` for IPv6 connect calls. Same pattern.

### Comparison: Accept vs Connect

| | Accept | Connect |
|---|---|---|
| Remote IP source | userspace sockaddr (`bpf_probe_read_user`) | userspace sockaddr (saved at sys_enter) |
| Local IP source | kernel sock via fexit (`skc_rcv_saddr`) | kernel sock via fexit (`skc_rcv_saddr`) |
| fd source | `sys_exit_accept4` ret | `sys_enter_connect` arg |
| fexit target | `inet_csk_accept` | `tcp_v4_connect` / `tcp_v6_connect` |
| Role | `kRoleServer` | `kRoleClient` |
| Tracepoint-only possible? | YES (if laddr not needed) | NO (laddr requires fexit) |

## New File: `ebpf/kernel/module.bpf.c`

### Maps (9 total vs 17 in current code)

```c
// Connection tracking (persists for lifetime of connection)
CONN_INFO_MAP           BPF_MAP_TYPE_HASH    key: u64 (tgid_fd)    value: conn_info_t

// Temp storage — accept path (populated between fexit and sys_exit)
ACTIVE_ACCEPT_ARGS      BPF_MAP_TYPE_HASH    key: u64 (pid_tgid)   value: accept_args_t
ACTIVE_ACCEPT_SOCK      BPF_MAP_TYPE_HASH    key: u64 (pid_tgid)   value: accept_sock_info_t

// Temp storage — connect path
ACTIVE_CONNECT_ARGS     BPF_MAP_TYPE_HASH    key: u64 (pid_tgid)   value: connect_args_t
ACTIVE_CONNECT_SOCK     BPF_MAP_TYPE_HASH    key: u64 (pid_tgid)   value: laddr_info_t

// Events to userspace
SOCKET_CONTROL_EVENTS   BPF_MAP_TYPE_RINGBUF   conn open/close events

// PID/comm filtering
TRACED_PIDS             BPF_MAP_TYPE_HASH    key: u32 (pid)        value: u8
TRACED_COMMS            BPF_MAP_TYPE_HASH    key: char[16]         value: u8
TRACE_ALL_FLAG          BPF_MAP_TYPE_ARRAY   key: u32 (0)          value: u32
```

9 maps vs 17 in current code (no data capture maps, no percpu heap, no LRU bookkeeping).

### Probes (10 total vs 29 in current code)

```
# Accept — 4 tracepoints + 1 fexit
SEC("tp/syscalls/sys_enter_accept4")   → filter + save sockaddr
SEC("tp/syscalls/sys_enter_accept")    → same handler
SEC("fexit/inet_csk_accept")          → read LOCAL IP from returned sock* (only reason for fexit)
SEC("tp/syscalls/sys_exit_accept4")    → get fd, read REMOTE IP from sockaddr, pair with fexit laddr
SEC("tp/syscalls/sys_exit_accept")     → same handler

# Connect — 2 tracepoints + 2 fexit
SEC("tp/syscalls/sys_enter_connect")   → filter + save fd + sockaddr (has REMOTE IP)
SEC("fexit/tcp_v4_connect")           → read LOCAL IP from sock* (only reason for fexit)
SEC("fexit/tcp_v6_connect")           → same for IPv6
SEC("tp/syscalls/sys_exit_connect")    → pair remote from sockaddr + local from fexit

# Close — 1 tracepoint
SEC("tp/syscalls/sys_enter_close")     → delete conn_info_map entry, emit close event
```

**Summary of why fexit is used (3 probes)**:
All 3 fexit probes exist for ONE reason: **reading local IP** (`skc_rcv_saddr`).
The remote IP comes from userspace sockaddr in all cases.
If local IP is not needed, all 3 fexit probes can be dropped → pure tracepoints.

### Structs

```c
struct conn_info_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    u16 rport;
    u32 raddr;
    u32 laddr;
    u16 lport;
    u32 role;      // 0=unknown, 1=client, 2=server
};

struct conn_event_t {  // sent to userspace via ringbuf
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    u16 rport;
    u32 raddr;
    u32 laddr;
    u16 lport;
    u32 role;
    u32 event_type; // 0=open, 1=close
};

// Temp map value for accept path
struct accept_sock_info_t {
    u32 raddr;
    u32 laddr;
    u16 rport;
    u16 lport;
    u16 family;
};
```

### Logging

Every probe logs via `bpf_printk` (replaces `bpf_trace_printk` in CO-RE):
```c
bpf_printk("accept: pid=%d fd=%d role=server", tgid, fd);
bpf_printk("accept: local=%pI4:%d remote=%pI4:%d", &laddr, lport, &raddr, ntohs(rport));

bpf_printk("connect: pid=%d fd=%d role=client", tgid, fd);
bpf_printk("connect: remote=%pI4:%d", &raddr, ntohs(rport));
```

Note: `%pI4` works in `bpf_trace_printk` on 5.15+ for printing IPs in dotted format.

### Close tracking

```
SEC("tp/syscalls/sys_enter_close")  → delete conn_info_map entry, emit close event
```

## IPv6 Handling

`inet_csk_accept` is the common TCP accept path for both IPv4 and IPv6.
One `fexit/inet_csk_accept` covers both. Check `skc_family` to distinguish:
- `AF_INET` → read `skc_daddr` / `skc_rcv_saddr` (u32)
- `AF_INET6` → read `skc_v6_daddr` / `skc_v6_rcv_saddr` (struct in6_addr), use `s6_addr32[3]` for IPv4-mapped

For connect: `fexit/tcp_v4_connect` handles IPv4, `fexit/tcp_v6_connect` handles IPv6.

## Build

```bash
# ONE TIME: Generate vmlinux.h on the target AKS node (5.15.0-1114-azure)
# vmlinux.h is needed at COMPILE TIME for struct definitions
# /sys/kernel/btf/vmlinux is used at RUNTIME by the loader for CO-RE relocations
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Commit vmlinux.h to repo — it works across kernel versions via CO-RE

# Compile (on dev machine or CI)
clang -target bpf -D__TARGET_ARCH_x86 -g -O2 \
  -I. -c module.bpf.c -o module.bpf.o

# Verify on target
bpftool prog load module.bpf.o /sys/fs/bpf/test
```

## Test Plan

### Phase 1: Compile + Load
- `module.bpf.c` compiles with clang
- `bpftool prog load` passes verifier

### Phase 2: Accept path
- Start echo-server, curl localhost:8888
- `cat /sys/kernel/debug/tracing/trace_pipe` shows:
  ```
  accept: pid=X fd=8 role=server
  accept: local=10.244.0.227:8888 remote=127.0.0.6:XXXXX
  ```
- Verify IPv4 and IPv6 (::1) connections both work

### Phase 3: Connect path
- From echo-server pod, `curl http://external-service`
- Trace shows:
  ```
  connect: pid=X fd=Y role=client
  connect: remote=X.X.X.X:80
  ```

### Phase 4: Close + cleanup
- After connection closes, verify conn_info_map entry is removed
- No map leak under sustained traffic

## Files

| File | Purpose |
|---|---|
| `ebpf/kernel/module.bpf.c` | **NEW** — CO-RE BPF program |
| `ebpf/kernel/vmlinux.h` | **NEW** — generated BTF header |
| `ebpf/kernel/module.cc` | **UNCHANGED** — existing BCC code stays |
