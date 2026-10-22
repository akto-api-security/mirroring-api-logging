# SSL / TLS Data Capture — Trace & Debug Guide (OpenSSL / libssl, Python target)

> Audience: Claude, when helping debug why SSL (openssl/libssl) plaintext is or
> isn't being captured from a target process (focus: a **Python** process using
> the system `libssl`). Built by reading the kernel BPF source and the userspace
> attachment code directly — see **Source map** at the end for exact files/lines.
>
> Scope: OpenSSL/libssl uprobe path only. GoTLS and Node TLS exist in the same
> `module.cc` but are out of scope here (noted only where they share code).

---

## 0. TL;DR mental model

For a Python process doing HTTPS via the system OpenSSL:

1. Python calls `SSL_write(ssl, buf, num)` / `SSL_read(...)` in `libssl.so`
   (the `ssl` module → `_ssl` C extension → libssl). `buf` is **plaintext**.
2. We attach **uprobes** on `SSL_write`/`SSL_read` in `libssl.so`. The entry
   probe grabs the plaintext `buf` pointer and derives the socket `fd` from the
   `SSL*` struct by reading the `rbio->num` field at hardcoded offsets.
3. Entry probe marks the connection `ssl=true` in `conn_info_map` and stashes
   `{fd, buf}`. The **return** probe reads `PT_REGS_RC` (bytes actually
   read/written) and copies that many bytes of `buf` up to userspace via
   `socket_data_events`.
4. Separately, `connect()`/`accept()` kprobes must have already created the
   `conn_info_map[(tgid,fd)]` entry — **without it, the SSL data event is
   dropped** (see §4, the #1 failure mode).
5. Because the connection is marked `ssl=true`, the **plain** `read`/`write`
   syscall probes for that same fd are suppressed (they check `conn_info->ssl
   != ssl` and bail), so we get decrypted data exactly once instead of
   encrypted data twice.

So there are **two independent prerequisites** for SSL capture to work:
**(A)** the uprobe is attached to the right libssl with the right version
offsets, and **(B)** a `conn_info` entry already exists for that fd (created by
the syscall-level connect/accept kprobes). Most "SSL not captured" bugs are one
of these two.

---

## 1. The precise call order (OpenSSL SSL_write path)

Establishing the order explicitly, as requested. `SSL_read` is the mirror image
(direction flipped, `active_ssl_read_args_map` instead of write).

### 1a. Connection must be established first (syscall kprobes)

```
Python: socket() → connect(fd, addr)        [client; server side uses accept()]
   │
   ├─ syscall__probe_entry_connect        stores accept_args{fd,addr} in active_accept_args_map[pid_tgid]
   ├─ probe_entry_tcp_connect (kprobe)     captures struct sock* into accept_args.sock
   └─ syscall__probe_ret_connect
          └─ process_syscall_accept(isConnect=true)
                 - extracts raddr/rport/laddr/lport from sock
                 - conn_info.ssl = FALSE   ← starts non-SSL
                 - conn_info.role = kRoleClient
                 - key = gen_tgid_fd(tgid, fd) = (tgid<<32)|fd
                 - conn_info_map.update(key, conn_info)
                 - socket_open_events.perf_submit(...)   → userspace
```

This runs **regardless of SSL** — it is the plain syscall path (Level1 kprobes,
always attached). SSL capture is layered on top of it.

### 1b. SSL_write (entry) — grab plaintext + fd, mark ssl

```
Python: SSL_write(ssl, buf, num)     buf = PLAINTEXT, num = requested bytes
   │
   └─ probe_entry_SSL_write_<ver>       ver ∈ {1_0, 1_1, 3_0, 3_5}  (see §3)
          │  fd = get_fd(ssl, sslVersion, /*rw*/false)
          │       └─ reads *(ssl + SSL_rbio_offset) → rbio ptr
          │          reads *(rbio + RBIO_num_offset) → fd  (the socket fd)
          │
          └─ probe_entry_SSL_write_core(ctx, ssl, buf, num, fd)
                 - bufc = PT_REGS_PARM2(ctx)   ← re-reads buf ptr from arg2
                 - write_args = {fd, buf=bufc}
                 - active_ssl_write_args_map[pid_tgid] = write_args
                 - set_conn_as_ssl(tgid, fd):
                       key = gen_tgid_fd(tgid, fd)
                       conn_info = conn_info_map.lookup(key)
                       if conn_info == NULL: RETURN (silently)   ← failure mode #1
                       conn_info->ssl = true
```

Key point: the entry probe does **not** emit data. It only records the
buf pointer and fd, and flips `ssl=true`. If `conn_info` doesn't exist yet,
`set_conn_as_ssl` is a no-op — the connection is never marked ssl, and the
return probe below will then be dropped by the `ssl != ssl` guard.

### 1c. SSL_write (return) — emit plaintext

```
Python: (SSL_write returns num_bytes)
   │
   └─ probe_ret_SSL_write
          write_args = active_ssl_write_args_map.lookup(pid_tgid)
          if NULL: return                      (entry probe didn't fire / different thread)
          process_syscall_data(ctx, write_args, id, is_send=true, ssl=true, compute_meta=true)
             │
             ├─ bytes_exchanged = PT_REGS_RC(ctx)   ← actual bytes written (return value)
             │     if <= 0: return                  (SSL_ERROR_WANT_READ/WRITE, retries, etc.)
             ├─ key = gen_tgid_fd(tgid, write_args.fd)
             ├─ conn_info = conn_info_map.lookup(key)
             │     if NULL: return                  ← failure mode #1 (conn dropped/rotated)
             ├─ if (conn_info->ssl != ssl) return    ← must be ssl=true here (set in 1b)
             ├─ infer HTTP role, bump msg_seq
             ├─ chunk loop (CHUNK_LIMIT): bpf_probe_read(msg, size, buf+off)
             │     bytes_sent = +size  (egress; SSL_read sets -size)
             └─ socket_data_events.perf_submit(...)  → userspace
          active_ssl_write_args_map.delete(pid_tgid)
```

`SSL_read` is identical with: `probe_entry_SSL_read_<ver>` →
`probe_entry_SSL_read_core` → `active_ssl_read_args_map` → `probe_ret_SSL_read`
→ `process_syscall_data(is_send=false, ssl=true)` → `bytes_sent = -size`.

### 1d. Summary ordering (one SSL_write)

```
connect kprobes  →  conn_info_map entry (ssl=false)      [prerequisite, earlier in time]
     …later…
SSL_write entry  →  get_fd → set_conn_as_ssl(ssl=true) → stash {fd,buf}
SSL_write body   →  (OpenSSL encrypts, calls write()/send() syscall internally)
     ↑ that inner write() syscall IS still hooked, but process_syscall_data
       sees conn_info->ssl==true while called with ssl=false → dropped. Good:
       prevents double (encrypted) capture.
SSL_write ret    →  process_syscall_data(ssl=true) → perf_submit plaintext
```

---

## 2. Userspace: how the uprobe actually gets attached (the synthesis)

The kernel probes above do nothing until userspace attaches the uprobe to the
target's `libssl.so`. This is the part most likely to be silently broken.

### 2a. Boot sequence (`ebpf/main.go`)

```
main()
 ├─ compile BPF source, bpfModule = bcc.NewModule(...)
 ├─ setupTracePids()  → fills kubernetes_pids map from TRACE_PIDS
 ├─ setupTraceComms() → fills allowed_comms   map from TRACE_COMMS
 │     if BOTH empty → set trace_all_flag = 1  (trace every process)   ← see §5
 ├─ attach syscall kprobes (Level1..Level4)   [connect/accept/read/write/close]
 ├─ ssl.InitMaps(bpfModule)   (go/node sym tables; not used for openssl)
 └─ if CAPTURE_SSL=="true" || CAPTURE_ALL=="true":
        go ticker(pollInterval)                ← default 20 min, UPROBE_POLL_INTERVAL
           every tick → processFactory.AddNewProcessesToProbe(bpfModule)
```

> **DEBUG GOTCHA #A — the 20-minute delay.** The openssl uprobe attach loop is
> driven **only** by a `time.NewTicker(pollInterval)` with **no immediate first
> run**. Default `pollInterval` is **20 minutes**. So a freshly started
> collector will NOT attach to any libssl process until the first tick fires.
> If you start the collector and the Python process and see no SSL data for
> minutes — this is why. Set `UPROBE_POLL_INTERVAL` to something small (e.g.
> `10s`) when debugging.

### 2b. Per-process discovery & attach (`processFactory.AddNewProcessesToProbe`)

```
for each pid on the host:
   sleep 200ms                                        ← throttle; slow with many pids
   skip if already in processMap or unattachedProcess
   skip if checkSelf(pid)   (our own ebpf-logging binary)
   containers = CheckProcessCGroupBelongToKube(pid)
       if err (not a kube proc) AND !PROBE_ALL_PID:
           mark unattached, SKIP                       ← see §5 / GOTCHA #B
   libraries = FindLibrariesPathInMapFile(pid)         ← parses /proc/<pid>/maps
       - only executable ('x') mappings
       - resolves each to host path /proc/<pid>/root/<lib>
   attached = ssl.TryOpensslProbes(libraries, bpfModule)   ← §2c
       if attached: record Process{OpenSSL}, continue
   else try GoTLS, then Node
   else mark pid unattached (won't retry)
```

Notes that bite in practice:

- **`unattachedProcess` is sticky.** Once a pid fails all probe types it is
  added to `unattachedProcess` and **never retried** for the life of the
  collector. If Python `import ssl` / first TLS use happens *after* the tick
  that examined it (so libssl wasn't mapped yet), it can get permanently marked
  unattached. Restart the collector, or ensure libssl is already loaded.
- **`FindLibrariesPathInMapFile` only sees libs already mmap'd.** A Python proc
  that hasn't yet imported `ssl` won't have `libssl.so` in `/proc/<pid>/maps`,
  so `TryOpensslProbes` returns "no modules found".
- **Static/embedded OpenSSL is not covered by this path.** Attach is on the
  dynamically linked `libssl.so` found in maps. If Python's `_ssl` statically
  links OpenSSL (unusual for distro Python, possible for some manylinux wheels
  / conda builds), there's no `libssl.so` mapping to attach to. (`gohelper`/
  static handling exists only for GoTLS.)

### 2c. `TryOpensslProbes` — version detection & hook selection (`ssl/openssl.go`)

```
modules = FindModules(libs, "libcrypto.so", "libssl.so")
   MUST find BOTH (len==2) else error "OpenSSL library not complete"
addresses = buildOpenSSLSymAddrConfig(libCryptoPath)
   → runs `strings libcrypto.so`, regex ^OpenSSL\s+(\d)\.(\d)\.(\d+)
   → picks version → offsetsForVersion(major,minor,fix)
   → HARD CAP: version > 3.5.x → error "not support"
switch addresses.version:
   V_1_0        → AttachUprobes(libssl, pid=-1, SslHooks_1_0)
   V_1_1        → AttachUprobes(libssl, pid=-1, SslHooks_1_1)
   V_3_0 / V_3_2→ AttachUprobes(SslHooks_3_0) + AttachUprobes(SslHooks_3_0_ex)
   V_3_5        → AttachUprobes(SslHooks_3_5) + AttachUprobes(SslHooks_3_5_ex)
```

> **DEBUG GOTCHA #C — version detection depends on `libcrypto.so`, not
> `libssl.so`.** The version string is read from **libcrypto** via the
> `strings` binary. If `strings` isn't on PATH in the collector image, or
> libcrypto lacks the `OpenSSL X.Y.Z` banner, or only one of the two libs is in
> the maps, attach fails with "library not complete" / "could not find the
> version". Both libs must be present and matched.

> **DEBUG GOTCHA #D — uprobes attach with `pid == -1` (global).** OpenSSL
> uprobes are attached to the `.so` file for **all** processes sharing that
> libssl, NOT scoped to the discovered pid. Per-process filtering happens
> **inside the kernel** via `should_trace_comm()` (see §5). So "attached to pid
> X" in logs really means "attached the libssl uprobe globally after seeing pid
> X". Two consequences:
>   - A different process using the same libssl is also probed (then filtered in
>     kernel).
>   - Re-attaching for a second pid on the same `.so` may log a duplicate-probe
>     error from bcc; usually harmless.

### 2d. Which hook set maps to which entry function

| Detected version | Go hook var        | Entry hook fn (kernel)      | `get_fd` case | Also `_ex`? |
|------------------|--------------------|-----------------------------|---------------|-------------|
| 1.0.x / 1.1.0    | `SslHooks_1_0`     | `probe_entry_SSL_write_1_0` | `get_fd(...,1)` | no |
| 1.1.1            | `SslHooks_1_1`     | `probe_entry_SSL_write_1_1` | `get_fd(...,2)` | no |
| 3.0.x / 3.1.x    | `SslHooks_3_0`     | `probe_entry_SSL_write_3_0` | `get_fd(...,3)` | + `SslHooks_3_0_ex` |
| 3.2.x / 3.3.x    | `SslHooks_3_0`(!)  | `probe_entry_SSL_write_3_0` | `get_fd(...,3)` | + `SslHooks_3_0_ex` |
| 3.4.x / 3.5.x    | `SslHooks_3_5`     | `probe_entry_SSL_write_3_5` | `get_fd(...,5)` | + `SslHooks_3_5_ex` |

The `_ex` hook sets attach the **same** kernel entry functions to
`SSL_write_ex` / `SSL_read_ex` (OpenSSL 3.x added these; some clients use them).

> **DEBUG GOTCHA #E — V_3_2 uses the 3_0 offsets/hooks.** `offsetsForVersion`
> returns a distinct `version: V_3_2` with *different* userspace offsets
> (`BIOReadOffset:72`), but `TryOpensslProbes` lumps `V_3_0, V_3_2` into the same
> `SslHooks_3_0` case → kernel `get_fd(ssl, 3, ...)` uses `SSL_rbio_offset=16`,
> which is the **3.0** layout. For OpenSSL **3.2/3.3** the rbio field moved
> (ssl_st was split into ssl_connection_st). So on 3.2/3.3 the fd extracted by
> `get_fd` case 3 can be **wrong/garbage** → `set_conn_as_ssl`/lookup on a bogus
> fd → SSL data silently dropped. This is a prime suspect if the target uses
> OpenSSL 3.2 or 3.3. (Python 3.12+ on recent distros often ships 3.2+.)

> **Offset provenance mismatch to be aware of:** the **userspace**
> `OpenSSLSymbolAddresses` offsets (`ssl/openssl.go`) are computed but for the
> OpenSSL path are **not pushed to the kernel** — they're informational. The
> kernel `get_fd` uses its **own hardcoded** `SSL_rbio_offset`/`RBIO_num_offset`
> keyed by the `sslVersion` int (1..5). So the offsets that actually matter for
> fd extraction live in `module.cc:get_fd`, not in `openssl.go`. When a new
> OpenSSL layout breaks fd extraction, **`get_fd` is the thing to patch.**

---

## 3. `get_fd` — how the socket fd is recovered from `SSL*` (kernel)

`module.cc: static u32 get_fd(void *ssl, int sslVersion, bool rw)`

```
SSL_rbio_offset (default 16); switch(sslVersion):
   1: RBIO_num_offset = 40                      (OpenSSL 1.0)
   2: RBIO_num_offset = 48                      (OpenSSL 1.1.1)
   3: RBIO_num_offset = 56                      (OpenSSL 3.0/3.1  — also used for 3.2/3.3, see GOTCHA #E)
   4: SSL_rbio_offset = 24; RBIO_num_offset=24  (BoringSSL)
   5: SSL_rbio_offset = 80; RBIO_num_offset=56  (OpenSSL 3.2+ / 3.5; rbio in ssl_connection_st, base 64B)

rbio = *(void**)(ssl + SSL_rbio_offset)
fd   = *(int*)(rbio + RBIO_num_offset)
```

So fd extraction = "follow `ssl->rbio`, then read `rbio->num`". If the offsets
don't match the actual struct layout, `rbio` is a bad pointer and `fd` is
garbage. `PRINT_BPF_LOGS` prints `SSL fd offset: <fd> <SSL_rbio_offset>
<RBIO_num_offset>` — check the fd looks like a small plausible integer.

Note `get_fd` ignores the `rw` arg — it always uses **rbio** (read BIO), for
both read and write. For a normally connected socket rbio and wbio share the
same fd, so this is fine; for asymmetric BIO setups it could be wrong.

---

## 3b. `set_conn_as_ssl` — line-exact (kernel, `module.cc` ~1381)

Called by **every** SSL entry probe (`probe_entry_SSL_write_core` /
`probe_entry_SSL_read_core`) right after the buf/fd are stashed. It is the *only*
place `conn_info->ssl` is set to true for the OpenSSL path.

```c
static void set_conn_as_ssl(u32 tgid, u32 fd){
    u64 tgid_fd = gen_tgid_fd(tgid, fd);           // (tgid<<32)|fd  — SAME key scheme as connect kprobe
    conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;                                     // ← SILENT no-op. ssl NEVER set. (log: "SSL tgid:" only)
    }
    conn_info->ssl = true;                          // ← the flip. (log: "SSL marking ssl tgid:")
}
```

Exactly-what-happens notes:

- **The fd here comes from `get_fd(ssl,...)`, not from a syscall.** So the key is
  `(tgid, get_fd_result)`. If `get_fd` returns a wrong fd (e.g. 0, or garbage),
  the lookup misses and `ssl` is never set — even though a perfectly good
  `conn_info` exists under the *correct* fd.
- **It mutates the map entry in place** (`conn_info` is a pointer into the BPF
  hash). No re-`update()` needed; the flag persists for the connection's life.
- **Idempotent & unconditional-true.** It only ever sets true, never false.
  Once a conn is ssl, it stays ssl until evicted/closed. There is no "unmark".
- **Two distinct trace_printk lines** (only with `PRINT_BPF_LOGS`) let you tell
  the two outcomes apart — this is the single most useful signal in the whole
  SSL debug:
  - `SSL tgid: <key>`         → entered, about to look up.
  - `SSL marking ssl tgid: <key>` → lookup succeeded, ssl set to true.
  - **See the first without the second ⇒ `conn_info==NULL` ⇒ the fd/key is wrong
    or the conn was never created/was evicted.** This is failure mode #1, pinned
    to an exact line.

## 3c. `process_syscall_data` — line-exact (kernel, `module.cc` ~402)

The shared emit function for **both** SSL and plain syscalls. Called from the SSL
**return** probes as `process_syscall_data(ctx, args, id, is_send, ssl=true,
compute_meta=true)`. Walking every gate in order, because each is a silent drop:

```c
int bytes_exchanged = PT_REGS_RC(ret);              // (1) return value of SSL_read/SSL_write
if (args->iovlen > 0 && args->buf_size > 0)         //     (iovec path only; not SSL — SSL has no iov)
    bytes_exchanged = args->buf_size;
if (bytes_exchanged <= 0) return;                   // (2) DROP: SSL_ERROR_WANT_*, handshake, 0/neg
if (args->fd < 0) return;                            // (3) DROP: bad fd

u64 tgid_fd = gen_tgid_fd(tgid, args->fd);          // (4) key from args->fd (= get_fd result for SSL)
conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
if (conn_info == NULL) return;                       // (5) DROP: no conn_info  (log: "conn_info not found")

if (conn_info->ssl != ssl) return;                   // (6) DROP: flag mismatch  ← the dedup gate
   // for SSL ret probe ssl==true, so conn_info->ssl MUST be true here.
   // If set_conn_as_ssl earlier no-op'd (3b NULL), ssl is still false → DROP.
   // Conversely this is what suppresses the PLAIN read/write probe (called ssl=false)
   // once the conn is SSL — so decrypted data is emitted once, not encrypted twice.

socket_data_event = socket_data_event_buffer_heap.lookup(&kZero);  // (7) per-CPU scratch
if (socket_data_event == NULL) return;               //     DROP: heap slot missing (never in practice)

// copy header fields id/fd/conn_start_ns/rport/raddr/laddr/lport/ssl from conn_info
direction = is_send ? kEgress : kIngress;            // SSL_write→egress, SSL_read→ingress

if (compute_meta) {                                  // (8) true for SSL (single buffer)
    if (role==kRoleUnknown && buf!=NULL)             //     infer client/server from HTTP verb/status
        infer_http_message(buf, bytes_exchanged);    //     (GET/POST/... vs HTTP/) → set role
    if (msg_seq==0) { msg_seq=1; prev_direction=dir }//     first message
    else if (dir != prev_direction) { msg_seq++ ; }  //     bump on direction flip (req→resp boundary)
}
socket_data_event->role/direction/msg_seq = ...;

#pragma unroll
for (i=0; i<CHUNK_LIMIT; i++) {                      // (9) chunk the payload
    bytes_remaining = bytes_exchanged - bytes_sent;
    if (bytes_remaining <= 0) break;
    current_size = min(bytes_remaining, MAX_MSG_SIZE);           // 30720 cap per event
    ... verifier-safety asm dance on current_size ...
    bpf_probe_read(&socket_data_event->msg, current_size, args->buf + bytes_sent);  // ← reads PLAINTEXT buf
    if (is_send) conn_info->writeEventsCount++;      //     per-CHUNK counter bump (not per-syscall!)
    else         conn_info->readEventsCount++;
    socket_data_event->writeEventsCount/readEventsCount = conn_info->...;
    socket_data_event->bytes_sent = (is_send ? +1 : -1) * size_to_save;   // sign = direction
    socket_data_events.perf_submit(ret, socket_data_event,
                                   sizeof(event) - MAX_MSG_SIZE + size_to_save);  // trimmed size
    bytes_sent += current_size;
}
```

Exactly-what-happens notes that matter for debugging:

- **`bytes_exchanged = PT_REGS_RC` is the linchpin for SSL.** For `SSL_read`/
  `SSL_write` (classic) the return value **is** the byte count — correct. For
  `SSL_read_ex`/`SSL_write_ex` the return value is **1/0 success**, and the real
  length is in the `*readbytes`/`*written` out-param which this function never
  reads → for the `_ex` family it would emit **1 byte**. (Matches the `_ex`
  discrepancy noted in the setup doc. Classic path is fine.)
- **The buffer is read at return time** (`args->buf + bytes_sent`). For
  `SSL_write` the buf was captured at entry (arg2) and is valid. For `SSL_read`
  the buf is only *filled* by the time the return probe runs — which is exactly
  why the read path emits at ret, not entry. `args->buf` for SSL is the raw
  plaintext pointer from `PT_REGS_PARM2` at entry.
- **`conn_info->ssl != ssl` (gate 6) is the dedup mechanism.** It is *both* the
  reason SSL works (plain probe on same fd is dropped) *and* a failure mode (if
  `ssl` never got set, the SSL ret probe itself is dropped). set_conn_as_ssl
  (3b) and this gate are two halves of the same coin.
- **`readEventsCount`/`writeEventsCount` increment per CHUNK, not per call.** A
  payload > 30720 bytes emits multiple events and bumps the counter multiple
  times. For small Python JSON it's one chunk = one increment.
- **`bytes_sent` field sign encodes direction** (`+` egress / `−` ingress), and
  its magnitude is the emitted chunk size (`size_to_save`), which can be < the
  full `bytes_exchanged` if chunked.
- **msg_seq** increments on each direction change — so a request (egress, seq
  becomes 1) then response (ingress, seq becomes 2) on the same conn are
  distinguishable downstream. Only computed when `compute_meta` (SSL: always).

### The two failure modes these functions own (pinned)

1. **`set_conn_as_ssl` NULL (3b):** `SSL tgid:` printed, `SSL marking ssl tgid:`
   NOT printed. Cause: `get_fd` returned a key with no conn_info (wrong fd, or
   conn never created / evicted). Result: ssl stays false → gate (6) later drops
   the ret probe.
2. **`process_syscall_data` gate (5) or (6):** `conn_info not found` printed, or
   silent drop at the ssl-mismatch. Same root cause family (fd/key/conn_info),
   observed one step later at emit time.

Both point at the **same question**: *does `conn_info_map` have an entry under
`(tgid, get_fd_result)` with `ssl=true`?* If `get_fd` disagrees with the fd the
`connect` kprobe used, the answer is no and everything downstream drops.

---

## 4. Why an SSL event gets dropped — decision points (most→least common)

Every one of these is a silent `return` in the kernel; enable `PRINT_BPF_LOGS`
to see them.

1. **`conn_info == NULL` in `set_conn_as_ssl` or `process_syscall_data`.**
   The `(tgid,fd)` entry doesn't exist. Causes:
   - `connect`/`accept` was never traced for this fd (e.g. socket opened before
     collector started — see `fillExistingConnections`, which back-fills only
     kube pids passed in).
   - Connection map **rotation**: `conn_info_map` is a fixed-size ring
     (`TRAFFIC_MAX_CONNECTION_MAP_SIZE`, 128*1024). `process_syscall_accept`
     deletes the oldest entry when the counter wraps — a long-lived Python conn
     can have its entry evicted, after which its SSL data drops.
   - Wrong `fd` from `get_fd` (GOTCHA #E) → lookup on a bogus key → NULL.
2. **`conn_info->ssl != ssl` guard** (`process_syscall_data`). For the SSL
   return probe, `ssl=true` is passed; if `set_conn_as_ssl` never ran (because
   conn_info was NULL at entry time), `conn_info->ssl` is still false → drop.
3. **`bytes_exchanged <= 0`.** `SSL_write`/`SSL_read` returned 0 or negative
   (WANT_READ/WANT_WRITE, renegotiation, handshake-in-progress). Normal; no
   payload to copy.
4. **`should_trace_comm()` / `should_trace_tgid()` false** (§5). Kernel-side
   process filter rejected this pid/comm. Since openssl uprobes are global
   (pid=-1), this is the real per-process gate for SSL data.
5. **Entry probe never fired** → `active_ssl_*_args_map.lookup` NULL in return
   probe. Means the uprobe isn't actually attached (wrong libssl, wrong
   version, attach happened after the call, 20-min ticker, etc. — §2).
6. **Ignore-port filter (userspace).** `eventCallbacks.go` drops events whose
   `rport` ∈ {9092/19092/29092 kafka, 2181 zk, 27017 mongo, 6379 redis} when
   `TRAFFIC_IGNORE_DEFAULT_PORTS` (default true). Irrelevant for typical HTTPS
   (443) but will silently eat SSL to those ports.

---

## 5. Process filtering: `PROBE_ALL_PID`, `TRACE_PIDS`, `TRACE_COMMS`

There are **two** filters and they are easy to confuse.

### Filter 1 — userspace, decides *whether to attach the uprobe at all*
`processFactory.AddNewProcessesToProbe`:
- If the process is **not** a kube process (`CheckProcessCGroupBelongToKube`
  fails) **and `PROBE_ALL_PID` is false**, the pid is skipped and marked
  unattached.
- **GOTCHA #B:** For a plain (non-Kubernetes) host Python process you almost
  certainly need **`PROBE_ALL_PID=true`**, otherwise attach never happens. The
  user's stated setup is `PROBE_ALL_PID=true` — good, this filter is disabled.

### Filter 2 — kernel, decides *whether a fired probe processes data*
Every kernel hook starts with `should_trace_comm()` (syscall & SSL entry
probes) or `should_trace_tgid()`:
```
if trace_all_flag == 1: trace everything          ← set when TRACE_PIDS and TRACE_COMMS both empty
else should_trace_comm(): current comm ∈ allowed_comms   (from TRACE_COMMS)
     should_trace_tgid(): tgid ∈ kubernetes_pids         (from TRACE_PIDS)
```
- If you set neither `TRACE_PIDS` nor `TRACE_COMMS`, `trace_all_flag=1` and all
  processes pass the kernel filter.
- If you set `TRACE_COMMS`, the comm must match (max 16 bytes — Python's comm is
  usually `python`/`python3`). `should_trace_comm()` is what gates the SSL entry
  probes (they call `should_trace_comm`, not `should_trace_tgid`).

> **Interaction:** `PROBE_ALL_PID` (Filter 1) only controls attaching the
> uprobe; `trace_all_flag` / `TRACE_COMMS` (Filter 2) controls whether the
> kernel probe does anything once fired. For a non-kube Python target you
> typically want **`PROBE_ALL_PID=true` AND (TRACE_PIDS/TRACE_COMMS empty →
> trace_all, OR TRACE_COMMS=python3)**. If SSL capture fails, verify *both*
> filters, not just one.

---

## 6. Userspace consumption of the SSL event (`connections/eventCallbacks.go`)

Once `socket_data_events.perf_submit` fires, the record lands in
`SocketDataEventCallback`:

```
kernelBytes (raw perf record, host byte order)
 ├─ if len < eventAttributesSize (72): drop ("smaller than event attributes")
 ├─ attr = (*SocketDataEventAttr)(&kernelBytes[0])     ← zero-copy cast, no binary.Read
 ├─ connId = attr.ConnId ; bytesSent = attr.Bytes_sent
 ├─ if ignorePorts && rport ∈ ignorePortsMap: drop     ← §4.6
 ├─ connectionFactory.CreateIfNotExists(connId)
 ├─ (if IsIngestLogsEnabled) LogIngest "Got data" with ssl=attr.Ssl, msg_seq, rc/wc, first 32 bytes
 └─ connectionFactory.SendDataEvent(connId, &kernelBytes)   ← handed to worker by reference
```

The event carries `attr.Ssl` (bool). For SSL captures this should be **true** —
if you see the payload arriving with `ssl=false`, it came through the plain
syscall path, meaning the SSL marking/dedup didn't take effect (the connection
wasn't marked ssl, so both the SSL return probe *and* the inner encrypted
write() may have raced — usually you then see encrypted garbage).

Key userspace log to grep: `LogIngest("Got data", ... "ssl", ...)` — enable via
the ingest-logs flag. For a healthy Python HTTPS capture you want to see
`ssl=true`, a plausible small `fd`, `rport=443` (or your server port), and
readable plaintext (e.g. `GET /...`, `HTTP/1.1 200`) in the `data` field.

---

## 7. Debug checklist for "Python + openssl, SSL not captured"

Run top-to-bottom; each maps to a section above.

1. **Is SSL capture even enabled?** `CAPTURE_SSL=true` or `CAPTURE_ALL=true`
   (default). Else the ticker goroutine never starts. (§2a)
2. **Did you wait for / shorten the ticker?** Default 20 min before first
   attach. Set `UPROBE_POLL_INTERVAL=10s`. (GOTCHA #A)
3. **Is `PROBE_ALL_PID=true`?** Required for non-kube host Python. (GOTCHA #B)
   *(User's setup: yes.)*
4. **Has Python actually loaded libssl?** `grep -E 'libssl|libcrypto'
   /proc/<pid>/maps` — both must appear, executable mapping. If not, Python
   hasn't done TLS yet, or links OpenSSL statically. (§2b/§2c)
5. **Is the OpenSSL version supported & correctly detected?**
   `strings <libcrypto path> | grep -m1 '^OpenSSL'`. Must be ≤ 3.5.x. Note the
   version. (§2c)
6. **Is it 3.2 or 3.3?** If so, suspect the wrong-offset bug (GOTCHA #E): fd from
   `get_fd` case 3 may be garbage → all SSL drops. This is the highest-value
   thing to check for modern distros.
7. **Turn on kernel logs.** Build with `PRINT_BPF_LOGS` and
   `cat /sys/kernel/debug/tracing/trace_pipe`. Look for, in order:
   - `probe_entry_SSL_write_<ver>: fd: <n>` — probe fired; is `<n>` sane?
   - `SSL fd offset: <fd> <rbio_off> <num_off>` — fd extraction detail.
   - `SSL marking ssl tgid: <key>` — conn was found & marked (GOOD). If you see
     `SSL tgid: <key>` but **not** `SSL marking ssl` → `conn_info` was NULL
     (failure mode #1). Means connect/accept wasn't traced for that fd.
   - `probe_ret_SSL_write: pid` then a `data:` line — payload emitted.
   - `process_syscall_data conn_info not found id=.. fd=..` → dropped, #1.
8. **Turn on userspace ingest logs** and confirm `Got data ... ssl=true` with
   readable plaintext and the right port. (§6)
9. **Ports not on the ignore list?** 443 is fine; watch mongo/redis/etc.
   (§4.6, `TRAFFIC_IGNORE_DEFAULT_PORTS`)
10. **Kernel process filter passing?** If `TRACE_COMMS` is set, does it include
    `python`/`python3`? Else leave `TRACE_PIDS`/`TRACE_COMMS` empty so
    `trace_all_flag=1`. (§5)

---

## 8. Source map (exact locations, for editing)

| Concern | File | Symbols / lines |
|---|---|---|
| SSL entry/return probes, `get_fd`, `set_conn_as_ssl` | `ebpf/kernel/module.cc` | `get_fd` ~1341, `set_conn_as_ssl` ~1381, `probe_entry_SSL_write_core` ~1396, `probe_entry_SSL_write_{1_0,1_1,3_0,3_5}` ~1415–1449, `probe_ret_SSL_write` ~1472, read mirror ~1488–1579 |
| Data emit + ssl/direction/msg_seq + drop guards | `ebpf/kernel/module.cc` | `process_syscall_data` ~402 (esp. `conn_info==NULL` ~420, `ssl!=ssl` ~427, `bytes<=0` ~409) |
| Conn creation (prereq) | `ebpf/kernel/module.cc` | `process_syscall_accept` ~226, `syscall__probe_ret_connect` ~668, ring rotation ~328–357 |
| Kernel process filter | `ebpf/kernel/module.cc` | `should_trace_comm` ~181, `should_trace_tgid` ~193, maps `kubernetes_pids`/`allowed_comms`/`trace_all_flag` ~166–179 |
| Hook name→function tables | `ebpf/bpfwrapper/sslhooks.go` | `SslHooks_1_0/1_1/3_0/3_5` + `_ex` |
| node/boring/egress hook sets | `ebpf/bpfwrapper/hooks.go` | `SslHooks`, `SslHooksEgress`, `BoringsslHooks` |
| uprobe attach mechanics | `ebpf/bpfwrapper/uprobes.go` | `AttachUprobes` |
| Version detect + hook selection + offsets | `ebpf/uprobeBuilder/ssl/openssl.go` | `TryOpensslProbes` ~24, `offsetsForVersion` ~114, `buildOpenSSLSymAddrConfig` ~143 |
| Per-process discovery/attach loop | `ebpf/uprobeBuilder/process/processFactory.go` | `AddNewProcessesToProbe` ~54, `PROBE_ALL_PID` ~47/51, `unattachedProcess` sticky-skip |
| Library discovery from /proc maps | `ebpf/uprobeBuilder/process/process.go` | `FindLibrariesPathInMapFile` ~60, `CheckProcessCGroupBelongToKube` ~21 |
| BPF map key helpers, pid map delete | `ebpf/uprobeBuilder/ssl/util.go` | `DeletePidFromBPFMap`, `InitMaps` (go/node only) |
| Boot wiring, ticker, filters, capture flags | `ebpf/main.go` | ticker ~215–242 (`UPROBE_POLL_INTERVAL`, no immediate first run), pid maps ~120–135/300–349, hook attach ~177–202 |
| Userspace event consume + ignore ports | `ebpf/connections/eventCallbacks.go` | `SocketDataEventCallback` ~98, `ignorePortsMap` ~23 |

### Env vars that matter for this path
- `CAPTURE_SSL` / `CAPTURE_ALL` — enable the SSL attach ticker.
- `PROBE_ALL_PID` — attach to non-kube processes (needed for host Python).
- `UPROBE_POLL_INTERVAL` — how often (and first delay!) to scan/attach. **Lower it when debugging.**
- `TRACE_PIDS` / `TRACE_COMMS` — kernel-side per-process filter; both empty ⇒ trace all.
- `TRAFFIC_IGNORE_DEFAULT_PORTS` — drops kafka/mongo/redis/zk ports.
- `PRINT_BPF_LOGS` (compile-time) — kernel `bpf_trace_printk` diagnostics.
- `TRAFFIC_MAX_CONNECTION_MAP_SIZE` — conn ring size; too small ⇒ eviction drops.
