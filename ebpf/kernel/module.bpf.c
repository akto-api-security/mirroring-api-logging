// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET      2
#define AF_INET6     10
#define EINPROGRESS  115

// Set from Go via spec.Variables. When false, compiler dead-code-eliminates.
const volatile bool ENABLE_BPF_METRICS = false;
const volatile bool ENABLE_BPF_DEBUG = false;
const volatile u32  TRACE_MODE = 0; // 0=all, 1=pid, 2=comm (enum trace_mode_t)

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

enum endpoint_role_t {
    kRoleUnknown = 0,
    kRoleClient  = 1,
    kRoleServer  = 2,
};

enum conn_event_type_t {
    kEventOpen  = 0,
    kEventClose = 1,
};

enum trace_mode_t {
    kTraceModeAll  = 0,  // trace every process
    kTraceModePid  = 1,  // trace only PIDs in traced_pids map
    kTraceModeComm = 2,  // trace only comms in traced_comms map
};

enum metric_t {
    METRIC_CONN_OPEN = 0,
    METRIC_CONN_CLOSE,
    METRIC_RINGBUF_DROP,
    METRIC_ACCEPT_FEXIT_MISS,   // fexit/inet_csk_accept didn't fire before sys_exit_accept
    METRIC_FILTERED,
    METRIC_CONNECT_SKIP_NON_TCP,
    METRIC_ACCEPT_FAILED,
    METRIC_CONNECT_FAILED,
    METRIC_CONNMAP_FULL,        // conn_info_map update failed (map full)
    __METRIC_MAX,
};

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// Persists in CONN_INFO_MAP for lifetime of connection
struct conn_info_t {
    u64 id;          // pid_tgid
    u32 fd;
    u64 conn_start_ns;
    u32 raddr;       // remote IP
    u32 laddr;       // local IP
    u16 rport;       // remote port (network byte order)
    u16 lport;       // local port (host byte order)
    u32 role;        // endpoint_role_t
};

// Sent to userspace via ring buffer
struct conn_event_t {
    struct conn_info_t conn;
    u32 event_type;  // conn_event_type_t
};

// Temp: saved at sys_enter_accept, consumed at sys_exit_accept
struct accept_args_t {
    struct sockaddr *addr;
};

// Temp: saved at fexit/inet_csk_accept, consumed at sys_exit_accept
struct accept_sock_info_t {
    u32 laddr;
    u16 lport;
    u16 family;
};

// Temp: saved at sys_enter_connect, consumed at sys_exit_connect
struct connect_args_t {
    u32 fd;
    struct sockaddr *addr;
};

// Temp: saved at fexit/tcp_v4_connect, consumed at sys_exit_connect
struct laddr_info_t {
    u32 laddr;
    u16 lport;
};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

// Connection tracking — persists for connection lifetime
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, u64);              // tgid_fd
    __type(value, struct conn_info_t);
} conn_info_map SEC(".maps");

// Accept temp maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);              // pid_tgid
    __type(value, struct accept_args_t);
} active_accept_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct accept_sock_info_t);
} active_accept_sock SEC(".maps");

// Connect temp maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct connect_args_t);
} active_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct laddr_info_t);
} active_connect_sock SEC(".maps");

// Events to userspace — max_entries overridden from Go (default 4MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);  // 4MB default
} socket_control_events SEC(".maps");

// PID/comm filtering
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);              // pid
    __type(value, u8);
} traced_pids SEC(".maps");

typedef char comm_t[16];
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, comm_t);
    __type(value, u8);
} traced_comms SEC(".maps");


// Metrics — per-CPU counters, zero lock contention
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, __METRIC_MAX);
    __type(key, u32);
    __type(value, u64);
} metrics SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline void metric_inc(u32 key) {
    if (!ENABLE_BPF_METRICS) return;
    u64 *val = bpf_map_lookup_elem(&metrics, &key);
    if (val) (*val)++;
}

static __always_inline u64 gen_tgid_fd(u32 tgid, u32 fd) {
    return ((u64)tgid << 32) | fd;
}

static __always_inline bool should_trace() {
    if (TRACE_MODE == kTraceModeAll)
        return true;

    if (TRACE_MODE == kTraceModePid) {
        u64 id = bpf_get_current_pid_tgid();
        u32 tgid = id >> 32;
        if (bpf_map_lookup_elem(&traced_pids, &tgid))
            return true;
    }

    if (TRACE_MODE == kTraceModeComm) {
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        if (bpf_map_lookup_elem(&traced_comms, &comm))
            return true;
    }

    metric_inc(METRIC_FILTERED);
    return false;
}

static __always_inline void emit_conn_event(void *ctx, struct conn_info_t *ci, u32 event_type) {
    struct conn_event_t *e = bpf_ringbuf_reserve(&socket_control_events, sizeof(*e), 0);
    if (!e) {
        metric_inc(METRIC_RINGBUF_DROP);
        return;
    }

    __builtin_memcpy(&e->conn, ci, sizeof(*ci));
    e->event_type = event_type;

    bpf_ringbuf_submit(e, 0);
}

// ---------------------------------------------------------------------------
// Accept probes
// ---------------------------------------------------------------------------

// Common handler for sys_enter_accept and sys_enter_accept4
static __always_inline int handle_sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    struct accept_args_t args = {};
    args.addr = (struct sockaddr *)ctx->args[1];

    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    if (ENABLE_BPF_DEBUG) bpf_printk("sys_enter_accept: pid=%d listen_fd=%d", id >> 32, (int)ctx->args[0]);
    return 0;
}

SEC("tp/syscalls/sys_enter_accept4")
int tp_sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    return handle_sys_enter_accept(ctx);
}

SEC("tp/syscalls/sys_enter_accept")
int tp_sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    return handle_sys_enter_accept(ctx);
}

// fexit/inet_csk_accept — capture local IP from the returned sock
SEC("fexit/inet_csk_accept")
int BPF_PROG(fexit_inet_csk_accept, struct sock *sk, int flags, int *err, bool kern, struct sock *ret) {
    if (!ret)
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    // Only process if we have a pending accept
    struct accept_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args)
        return 0;

    struct accept_sock_info_t info = {};
    info.family = BPF_CORE_READ(ret, __sk_common.skc_family);
    info.lport  = BPF_CORE_READ(ret, __sk_common.skc_num);

    if (info.family == AF_INET) {
        info.laddr = BPF_CORE_READ(ret, __sk_common.skc_rcv_saddr);
    } else if (info.family == AF_INET6) {
        // For IPv4-mapped IPv6, s6_addr32[3] has the IPv4 address
        struct in6_addr v6addr;
        v6addr = BPF_CORE_READ(ret, __sk_common.skc_v6_rcv_saddr);
        info.laddr = v6addr.in6_u.u6_addr32[3];
    }

    bpf_map_update_elem(&active_accept_sock, &id, &info, BPF_ANY);

    if (ENABLE_BPF_DEBUG) bpf_printk("fexit_inet_csk_accept: pid=%d family=%d lport=%d", id >> 32, info.family, info.lport);
    return 0;
}

// Common handler for sys_exit_accept and sys_exit_accept4
static __always_inline int handle_sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    int ret_fd = (int)ctx->ret;

    // Always clean up, even on failure
    struct accept_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        return 0;
    }

    struct sockaddr *addr = args->addr;

    // Clean up temp maps before any early returns
    struct accept_sock_info_t *sock_info = bpf_map_lookup_elem(&active_accept_sock, &id);

    if (ret_fd < 0) {
        metric_inc(METRIC_ACCEPT_FAILED);
        if (ENABLE_BPF_DEBUG) bpf_printk("sys_exit_accept: pid=%d FAILED ret=%d", tgid, ret_fd);
        goto cleanup;
    }

    // Build conn_info
    struct conn_info_t conn = {};
    conn.id = id;
    conn.fd = (u32)ret_fd;
    conn.conn_start_ns = bpf_ktime_get_ns();
    conn.role = kRoleServer;

    // Read local IP from fexit data
    if (sock_info) {
        conn.laddr = sock_info->laddr;
        conn.lport = sock_info->lport;
    } else {
        metric_inc(METRIC_ACCEPT_FEXIT_MISS);
    }

    // Read remote IP from userspace sockaddr (kernel filled it during accept)
    if (addr) {
        // Read sa_family first
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

        if (family == AF_INET) {
            struct sockaddr_in sa4 = {};
            bpf_probe_read_user(&sa4, sizeof(sa4), addr);
            conn.raddr = sa4.sin_addr.s_addr;
            conn.rport = sa4.sin_port;
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sa6 = {};
            bpf_probe_read_user(&sa6, sizeof(sa6), addr);
            conn.raddr = sa6.sin6_addr.in6_u.u6_addr32[3];
            conn.rport = sa6.sin6_port;
        }
    }

    // Store in conn_info_map
    u64 tgid_fd = gen_tgid_fd(tgid, (u32)ret_fd);
    if (bpf_map_update_elem(&conn_info_map, &tgid_fd, &conn, BPF_ANY) != 0) {
        metric_inc(METRIC_CONNMAP_FULL);
        goto cleanup;
    }

    // Emit event to userspace
    metric_inc(METRIC_CONN_OPEN);
    emit_conn_event(ctx, &conn, kEventOpen);

    if (ENABLE_BPF_DEBUG) {
        bpf_printk("accept: pid=%d fd=%d role=server", tgid, ret_fd);
        bpf_printk("accept: laddr=%d.%d", conn.laddr & 0xFF, (conn.laddr >> 8) & 0xFF);
        bpf_printk("accept: laddr=%d.%d:%d", (conn.laddr >> 16) & 0xFF, (conn.laddr >> 24) & 0xFF, conn.lport);
        bpf_printk("accept: raddr=%d.%d", conn.raddr & 0xFF, (conn.raddr >> 8) & 0xFF);
        bpf_printk("accept: raddr=%d.%d:%d", (conn.raddr >> 16) & 0xFF, (conn.raddr >> 24) & 0xFF, __builtin_bswap16(conn.rport));
    }

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    bpf_map_delete_elem(&active_accept_sock, &id);
    return 0;
}

SEC("tp/syscalls/sys_exit_accept4")
int tp_sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
    return handle_sys_exit_accept(ctx);
}

SEC("tp/syscalls/sys_exit_accept")
int tp_sys_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    return handle_sys_exit_accept(ctx);
}

// ---------------------------------------------------------------------------
// Connect probes
// ---------------------------------------------------------------------------

SEC("tp/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    struct connect_args_t args = {};
    args.fd   = (u32)ctx->args[0];
    args.addr = (struct sockaddr *)ctx->args[1];

    bpf_map_update_elem(&active_connect_args, &id, &args, BPF_ANY);

    if (ENABLE_BPF_DEBUG) bpf_printk("sys_enter_connect: pid=%d fd=%d", id >> 32, args.fd);
    return 0;
}

// fexit/tcp_v4_connect — capture local IP after route selection
SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret) {
    if (ret != 0 && ret != -EINPROGRESS)
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    struct connect_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args)
        return 0;

    struct laddr_info_t info = {};
    info.laddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    info.lport = BPF_CORE_READ(sk, __sk_common.skc_num);

    bpf_map_update_elem(&active_connect_sock, &id, &info, BPF_ANY);

    if (ENABLE_BPF_DEBUG) bpf_printk("fexit_tcp_v4_connect: pid=%d lport=%d", id >> 32, info.lport);
    return 0;
}

// fexit/tcp_v6_connect — same for IPv6
SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret) {
    if (ret != 0 && ret != -115)
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    struct connect_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args)
        return 0;

    struct laddr_info_t info = {};
    // For IPv4-mapped IPv6, use s6_addr32[3]
    struct in6_addr v6addr;
    v6addr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
    info.laddr = v6addr.in6_u.u6_addr32[3];
    info.lport = BPF_CORE_READ(sk, __sk_common.skc_num);

    bpf_map_update_elem(&active_connect_sock, &id, &info, BPF_ANY);

    if (ENABLE_BPF_DEBUG) bpf_printk("fexit_tcp_v6_connect: pid=%d lport=%d", id >> 32, info.lport);
    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int tp_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    int ret = (int)ctx->ret;

    struct connect_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args)
        return 0;

    // connect can return -EINPROGRESS for non-blocking sockets — that's OK
    if (ret != 0 && ret != -EINPROGRESS) {
        metric_inc(METRIC_CONNECT_FAILED);
        if (ENABLE_BPF_DEBUG) bpf_printk("sys_exit_connect: pid=%d FAILED ret=%d", tgid, ret);
        goto cleanup;
    }

    // If fexit/tcp_v4_connect didn't fire, this isn't TCP — skip (UDP, Unix, etc.)
    struct laddr_info_t *linfo = bpf_map_lookup_elem(&active_connect_sock, &id);
    if (!linfo) {
        metric_inc(METRIC_CONNECT_SKIP_NON_TCP);
        goto cleanup;
    }

    struct conn_info_t conn = {};
    conn.id = id;
    conn.fd = args->fd;
    conn.conn_start_ns = bpf_ktime_get_ns();
    conn.role = kRoleClient;
    conn.laddr = linfo->laddr;
    conn.lport = linfo->lport;

    // Read remote IP from userspace sockaddr (saved at sys_enter_connect)
    if (args->addr) {
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), &args->addr->sa_family);

        if (family == AF_INET) {
            struct sockaddr_in sa4 = {};
            bpf_probe_read_user(&sa4, sizeof(sa4), args->addr);
            conn.raddr = sa4.sin_addr.s_addr;
            conn.rport = sa4.sin_port;
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sa6 = {};
            bpf_probe_read_user(&sa6, sizeof(sa6), args->addr);
            conn.raddr = sa6.sin6_addr.in6_u.u6_addr32[3];
            conn.rport = sa6.sin6_port;
        }
    }

    // Store in conn_info_map
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    if (bpf_map_update_elem(&conn_info_map, &tgid_fd, &conn, BPF_ANY) != 0) {
        metric_inc(METRIC_CONNMAP_FULL);
        goto cleanup;
    }

    // Emit event to userspace
    metric_inc(METRIC_CONN_OPEN);
    emit_conn_event(ctx, &conn, kEventOpen);

    if (ENABLE_BPF_DEBUG) {
        bpf_printk("connect: pid=%d fd=%d role=client", tgid, args->fd);
        bpf_printk("connect: laddr=%d.%d", conn.laddr & 0xFF, (conn.laddr >> 8) & 0xFF);
        bpf_printk("connect: laddr=%d.%d:%d", (conn.laddr >> 16) & 0xFF, (conn.laddr >> 24) & 0xFF, conn.lport);
        bpf_printk("connect: raddr=%d.%d", conn.raddr & 0xFF, (conn.raddr >> 8) & 0xFF);
        bpf_printk("connect: raddr=%d.%d:%d", (conn.raddr >> 16) & 0xFF, (conn.raddr >> 24) & 0xFF, __builtin_bswap16(conn.rport));
    }

cleanup:
    bpf_map_delete_elem(&active_connect_args, &id);
    bpf_map_delete_elem(&active_connect_sock, &id);
    return 0;
}

// ---------------------------------------------------------------------------
// Close probe
// ---------------------------------------------------------------------------

SEC("tp/syscalls/sys_enter_close")
int tp_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 fd = (u32)ctx->args[0];

    u64 tgid_fd = gen_tgid_fd(tgid, fd);
    struct conn_info_t *conn = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (!conn)
        return 0;

    // Emit close event before deleting
    metric_inc(METRIC_CONN_CLOSE);
    emit_conn_event(ctx, conn, kEventClose);

    if (ENABLE_BPF_DEBUG) bpf_printk("close: pid=%d fd=%d", tgid, fd);

    bpf_map_delete_elem(&conn_info_map, &tgid_fd);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
