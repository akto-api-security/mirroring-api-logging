/*
 * module.bpf.c — libbpf/CO-RE eBPF kernel program.
 *
 * Compiled ahead-of-time with bpf2go; no BCC or host kernel headers required.
 * vmlinux.h provides all kernel types from the running kernel's BTF data.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * Some vmlinux.h builds drag in kernel helper headers that define bpf_printk.
 * Undefine it so bpf_helpers.h can install its modern variadic version cleanly.
 */
#ifdef bpf_printk
#undef bpf_printk
#endif

/* AF_INET / AF_INET6 are preprocessor constants not captured by BTF. */
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif


#define bpf_printk(fmt, ...) \
({ \
    char ____fmt[] = fmt; \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

/*
 * Map bpf2go target defines to the custom arch macros used throughout this file.
 * bpf2go sets __TARGET_ARCH_x86 for amd64 and __TARGET_ARCH_arm64 for arm64.
 */
#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
  #define TARGET_ARCH_X86_64
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
  #define TARGET_ARCH_AARCH64
#endif

/*
 * Portable syscall-argument accessors.
 *
 * On both x86-64 and ARM64, the kernel syscall wrapper has the signature:
 *   asmlinkage long __x64_sys_xxx(const struct pt_regs *regs)   // x86-64
 *   asmlinkage long __arm64_sys_xxx(const struct pt_regs *regs) // ARM64
 *
 * PT_REGS_PARM1(ctx) gives us that 'regs' pointer (the wrapper's argument).
 * PT_REGS_PARM1_CORE_SYSCALL is supposed to dereference it, but older libbpf
 * versions define it as a simple BPF_CORE_READ(ctx, di/regs[0]) — i.e. it
 * returns the pointer value itself, not the actual syscall argument.
 * Casting that 64-bit kernel address to int gives garbage fd values.
 *
 * Fix: explicitly dereference the inner pt_regs using the correct field names
 * for each architecture (di/si/dx on x86-64, regs[0/1/2] on ARM64).
 */
#ifdef TARGET_ARCH_AARCH64
  #define SYSCALL_PARM1(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), regs[0])
  #define SYSCALL_PARM2(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), regs[1])
  #define SYSCALL_PARM3(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), regs[2])
#elif defined(TARGET_ARCH_X86_64)
  #define SYSCALL_PARM1(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), di)
  #define SYSCALL_PARM2(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), si)
  #define SYSCALL_PARM3(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), dx)
#else
  #define SYSCALL_PARM1(ctx) PT_REGS_PARM1_CORE_SYSCALL(ctx)
  #define SYSCALL_PARM2(ctx) PT_REGS_PARM2_CORE_SYSCALL(ctx)
  #define SYSCALL_PARM3(ctx) PT_REGS_PARM3_CORE_SYSCALL(ctx)
#endif

/*
 * BPF global read-only variable — set from userspace via CollectionSpec before loading.
 * Replaces the runtime Go string-substitution used in the BCC version.
 */
volatile const bool print_bpf_logs = false;
/* When true (env TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS), count each socket_data ringbuf submit. */
volatile const bool log_socket_data_submit_stats = false;
/* When true (env FILTER_LOCAL_TRAFFIC), skip connections whose remote IP matches
 * local_traffic_ip (default 127.0.0.1 as LE u32 = 16777343). */
volatile const bool filter_local_traffic = false;
volatile const __u32 local_traffic_ip = 16777343;
/* When true (env TRAFFIC_STRICT_REMOTE_PORT_FILTER), only capture connections whose remote
 * port matches strict_remote_port (default 10275). */
volatile const bool filter_strict_remote_port = false;
volatile const __u16 strict_remote_port = 10275;
/* When true (env TRAFFIC_DISABLE_PERF_SUBMIT), skip all ringbuf_output calls. */
volatile const bool disable_ring_submit = false;

/*
 * CHUNK_SIZE_LIMIT must be a compile-time constant because it is used as the
 * bound of a #pragma-unrolled loop (the BPF verifier requires statically known
 * loop counts).  Override at build time via bpf2go cflags: -DCHUNK_SIZE_LIMIT=<n>
 */
#ifndef CHUNK_SIZE_LIMIT
#define CHUNK_SIZE_LIMIT 4
#endif

#define MAX_MSG_SIZE 30720
#define CHUNK_LIMIT  CHUNK_SIZE_LIMIT
#define LOOP_LIMIT   42

/*
 * Default connection map size.  The Go loader can resize individual maps via
 * CollectionSpec.Maps[name].MaxEntries before calling LoadAndAssign.
 */
#define TRAFFIC_MAX_CONNECTION_MAP_SIZE 131072

char LICENSE[] SEC("license") = "GPL";

/* ===================================================================
 * Enums
 * =================================================================== */

enum source_function_t {
  kSyscallAccept,
  kSyscallConnect,
  kSyscallClose,
  kSyscallWrite,
  kSyscallRead,
  kSyscallSend,
  kSyscallRecv,
  kSyscallSendTo,
  kSyscallRecvFrom,
  kSyscallSendMsg,
  kSyscallRecvMsg,
  kSyscallSendMMsg,
  kSyscallRecvMMsg,
  kSyscallWriteV,
  kSyscallReadV,
  kSyscallSendfile,
  kSSLWrite,
  kSSLRead,
  kGoTLSWrite,
  kGoTLSRead
};

/* ===================================================================
 * User-defined structs (layout must stay in sync with structs/structs.go)
 * =================================================================== */

struct conn_info_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    bool ssl;
    u32 readEventsCount;
    u32 writeEventsCount;
};

/*
 * Plain-C mirrors of the sockaddr family structs.
 *
 * These are intentionally NOT from vmlinux.h so they carry no
 * preserve_access_index attribute and generate zero CO-RE relocations.
 * All sockaddr data arrives from user space and is read with
 * bpf_probe_read_user(), so we never need CO-RE portability for these.
 */
struct akto_sockaddr {
    unsigned short sa_family;
    char           sa_data[14];
};

struct akto_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;    /* big-endian */
    unsigned int   sin_addr;    /* s_addr, big-endian */
    unsigned char  _pad[8];
};

struct akto_sockaddr_in6 {
    unsigned short sin6_family;
    unsigned short sin6_port;   /* big-endian */
    unsigned int   sin6_flowinfo;
    unsigned char  sin6_addr[16];
    unsigned int   sin6_scope_id;
};

/*
 * Plain-C mirror of the first fields of struct socket (no preserve_access_index).
 *
 * CO-RE relocations for struct socket::sk consistently fail at load time with
 * 0xbad2310 ("bad relo") on the target kernel even though bpf_core_field_exists()
 * returns 1 for the same field.  This is the same class of issue described in
 * cilium/ebpf#1031: the FIELD_EXISTS and FIELD_BYTE_OFFSET relocation types are
 * resolved from different BTF scopes (vmlinux vs. module BTF), producing an
 * inconsistent result.
 *
 * The fix follows the same pattern used for akto_sockaddr*: define a plain C
 * struct that mirrors the kernel layout and use bpf_probe_read_kernel — no CO-RE
 * relocation is generated, the compile-time offsetof() is correct because
 * vmlinux.h is regenerated from the *running* kernel by `make generate`.
 *
 * Layout of struct socket (stable across all 64-bit kernels we support):
 *   offset  0: state (socket_state enum, 4 bytes)
 *   offset  4: type  (short, 2 bytes)
 *   offset  6: _pad  (2 bytes)
 *   offset  8: flags (unsigned long, 8 bytes)
 *   offset 16: file  (struct file *, 8 bytes)
 *   offset 24: sk    (struct sock  *, 8 bytes)  ← what we need
 */
struct akto_socket {
    __u32  state;
    __u16  type;
    __u16  _pad;
    __u64  flags;
    __u64  file;
    __u64  sk;    /* struct sock * stored as u64 to avoid CO-RE on the pointer type */
};

struct accept_args_t {
    struct sockaddr* addr;
    struct sock *sock;
    struct socket* sock_alloc_socket;
    u32 fd;
};

struct data_args_t {
    enum source_function_t source_fn;
    bool sock_event;
    u32 fd;
    const char* buf;
    const struct iovec* iov;
    int iovlen;
    int buf_size;
};

struct close_args_t {
    u32 fd;
};

struct socket_open_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    u32 src_ip;
    unsigned short src_port;
    u64 socket_open_ns;
};

struct socket_close_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    u64 socket_close_ns;
};

struct socket_data_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    int bytes_sent;
    u32 readEventsCount;
    u32 writeEventsCount;
    bool ssl;
    char msg[MAX_MSG_SIZE];
};

/* ===================================================================
 * BPF maps — BTF-typed declarations replacing BCC macros
 * =================================================================== */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TRAFFIC_MAX_CONNECTION_MAP_SIZE);
    __type(key, u64);
    __type(value, struct conn_info_t);
} conn_info_map SEC(".maps");

/*
 * conn_info_map_keys: rotating ring of active conn_info_map keys.
 * BPF array keys are always u32 (array index); value is the u64 tgid_fd.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TRAFFIC_MAX_CONNECTION_MAP_SIZE);
    __type(key, u32);
    __type(value, u64);
} conn_info_map_keys SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, int);
} conn_counter SEC(".maps");

/* Total socket_data bpf_ringbuf_output calls (userspace reads for windowed logs). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket_data_submit_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024);
} socket_data_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} socket_open_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} socket_close_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct socket_data_event_t);
} socket_data_event_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct close_args_t);
} active_close_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_write_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_ssl_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_ssl_write_args_map SEC(".maps");

/* ===================================================================
 * Node.js TLS structs and maps
 * =================================================================== */

struct node_tlswrap_symaddrs_t {
  u32 TLSWrapStreamListenerOffset;
  u32 StreamListenerStreamOffset;
  u32 StreamBaseStreamResourceOffset;
  u32 LibuvStreamWrapStreamBaseOffset;
  u32 LibuvStreamWrapStreamOffset;
  u32 UVStreamSIOWatcherOffset;
  u32 UVIOSFDOffset;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct node_tlswrap_symaddrs_t);
} node_tlswrap_symaddrs_map SEC(".maps");

/*
 * active_TLSWrap_memfn_this: stores void* (tls_wrap pointer) per pid_tgid.
 * void* cannot be a BTF map value type; stored as __u64.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, __u64);
} active_TLSWrap_memfn_this SEC(".maps");

/*
 * node_ssl_tls_wrap_map: ssl* → tls_wrap* mapping.
 * Both pointers stored as __u64.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} node_ssl_tls_wrap_map SEC(".maps");

/* ===================================================================
 * Go TLS structs and maps
 * =================================================================== */

struct tgid_goid_t {
  u32 tgid;
  long long goid;
};

struct go_tls_conn_args {
  void* conn_ptr;
  char* plaintext_ptr;
};

struct go_interface {
  int64_t type;
  void* ptr;
};

enum location_type_t {
  kLocationTypeStack = 1,
  kLocationTypeRegisters = 2
};

struct location_t {
  enum location_type_t type;
  u32 offset;
};

struct go_symaddrs_t {
  u64 FDSysFDOffset;
  u64 TLSConnOffset;
  u64 GIDOffset;
  u64 TCPConnOffset;
  u64 IsClientOffset;

  struct location_t WriteConnectionLoc;
  struct location_t WriteBufferLoc;
  struct location_t WriteRet0Loc;
  struct location_t WriteRet1Loc;

  struct location_t ReadConnectionLoc;
  struct location_t ReadBufferLoc;
  struct location_t ReadRet0Loc;
  struct location_t ReadRet1Loc;
};

struct go_regabi_regs {
  uint64_t regs[9];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct go_regabi_regs);
} regs_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct go_symaddrs_t);
} go_symaddrs_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tgid_goid_t);
    __type(value, struct go_tls_conn_args);
} active_tls_conn_op_map SEC(".maps");

/* ===================================================================
 * Helper functions
 * =================================================================== */

static __always_inline u64 gen_tgid_fd(u32 tgid, int fd) {
  return ((u64)tgid << 32) | (u32)fd;
}

static __always_inline void process_syscall_accept(struct pt_regs* ctx,
                                             const struct accept_args_t* args,
                                             u64 id, bool isConnect) {
    int ret_fd = PT_REGS_RC(ctx);

    if (!isConnect && ret_fd < 0) {
        return;
    }

    struct conn_info_t conn_info = {};
    bool socketConn = false;

    u32 srcIp = 0;
    uint16_t lport = 0;

    if (args->addr != NULL) {
        if (print_bpf_logs) {
            bpf_printk("sock addr found, processing");
        }
    }

    if (args->sock_alloc_socket != NULL) {
        if (print_bpf_logs) {
            bpf_printk("sock alloc found, processing");
        }
        socketConn = true;

        /*
         * Read struct sock* from struct socket without CO-RE.
         * BPF_CORE_READ on struct socket::sk fails with 0xbad2310 on this
         * kernel even though bpf_core_field_exists() says the field exists —
         * the two relocation types use different BTF resolution paths (cilium/ebpf#1031).
         * akto_socket mirrors the stable first-field layout; no CO-RE is generated.
         */
        struct akto_socket sock_hdr = {};
        if (bpf_probe_read_kernel(&sock_hdr, sizeof(sock_hdr),
                                  args->sock_alloc_socket) != 0)
            return;
        struct sock* sk = (struct sock *)(unsigned long)sock_hdr.sk;

        if (sk == NULL)
            return;

        /* struct sock CO-RE relocations succeed normally on this kernel. */
        uint16_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
        conn_info.port  = BPF_CORE_READ(sk, __sk_common.skc_dport);
        lport           = BPF_CORE_READ(sk, __sk_common.skc_num);

        if (family == AF_INET) {
            if (print_bpf_logs) {
                bpf_printk("sock alloc found ipv4, processing");
            }
            conn_info.ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            srcIp        = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        } else if (family == AF_INET6) {
            if (print_bpf_logs) {
                bpf_printk("sock alloc found ipv6, processing");
            }
            __u8 v6_dst[16] = {};
            __u8 v6_src[16] = {};
            if (bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
                bpf_core_read(v6_dst, sizeof(v6_dst),
                              &sk->__sk_common.skc_v6_daddr);
                bpf_core_read(v6_src, sizeof(v6_src),
                              &sk->__sk_common.skc_v6_rcv_saddr);
            }
            conn_info.ip = ((__u32 *)v6_dst)[3];
            srcIp        = ((__u32 *)v6_src)[3];
        } else {
            return;
        }
        if (print_bpf_logs) {
            bpf_printk("sock alloc found, processed: id: %llu ip: %llu port: %d",
                             id, conn_info.ip, conn_info.port);
            bpf_printk("sock alloc found, processed: id: %llu srcIp: %llu srcPort: %d",
                             id, srcIp, lport);
        }
    }

    if (!socketConn) {
        if (args->addr != NULL) {
            struct akto_sockaddr sa_hdr = {};
            if (bpf_probe_read_user(&sa_hdr, sizeof(sa_hdr), args->addr) != 0) {
                return;
            }
            if (sa_hdr.sa_family != AF_INET && sa_hdr.sa_family != AF_INET6) {
                return;
            }
        }
        // addr == NULL means accept(fd, NULL, NULL) — register the connection
        // with ip/port=0 so data probes can find it in conn_info_map.
    }

    conn_info.id = id;
    if (isConnect) {
        conn_info.fd = args->fd;
    } else {
        conn_info.fd = ret_fd;
    }
    conn_info.conn_start_ns = bpf_ktime_get_ns();

    if (!socketConn && args->addr != NULL) {
        struct akto_sockaddr sa_hdr = {};
        bpf_probe_read_user(&sa_hdr, sizeof(sa_hdr), args->addr);
        if (sa_hdr.sa_family == AF_INET) {
            struct akto_sockaddr_in sin = {};
            if (bpf_probe_read_user(&sin, sizeof(sin), args->addr) == 0) {
                conn_info.port = sin.sin_port;
                conn_info.ip   = sin.sin_addr;
            }
        } else {
            struct akto_sockaddr_in6 sin6 = {};
            if (bpf_probe_read_user(&sin6, sizeof(sin6), args->addr) == 0) {
                conn_info.port = sin6.sin6_port;
                conn_info.ip   = ((__u32 *)sin6.sin6_addr)[3];
            }
        }
    }

    conn_info.ssl = false;
    conn_info.readEventsCount = 0;
    conn_info.writeEventsCount = 0;

    if (filter_local_traffic && conn_info.ip == local_traffic_ip) {
        if (print_bpf_logs) {
            bpf_printk("Dropping local traffic ip:%u fd:%d", conn_info.ip, args->fd);
        }
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = 0;
    if (isConnect) {
        tgid_fd = gen_tgid_fd(tgid, args->fd);
    } else {
        tgid_fd = gen_tgid_fd(tgid, ret_fd);
    }

    u32 idx = 0;
    int *counter = bpf_map_lookup_elem(&conn_counter, &idx);
    int  val = 0;
    u32  val_key = 0;
    if (counter != NULL) {
        if ((*counter) > (TRAFFIC_MAX_CONNECTION_MAP_SIZE - 5)) {
            int reset = 0;
            bpf_map_update_elem(&conn_counter, &idx, &reset, BPF_ANY);
            if (print_bpf_logs) {
                bpf_printk("conn_info_counter reset: %d", *counter);
            }
        }
        (*counter)++;
        val     = *counter;
        val_key = (u32)val;
        if (print_bpf_logs) {
            bpf_printk("conn_info_counter found: %d", val);
        }
        u64* curr = bpf_map_lookup_elem(&conn_info_map_keys, &val_key);
        if (curr != NULL) {
            u64 curVal = *curr;
            struct conn_info_t* old_conn_info = bpf_map_lookup_elem(&conn_info_map, &curVal);
            if (old_conn_info != NULL) {
                bpf_map_delete_elem(&conn_info_map, &curVal);
                if (print_bpf_logs) {
                    bpf_printk("conn_info_counter deleting: %d", curVal);
                }
            }
        }
    }

    bpf_map_update_elem(&conn_info_map_keys, &val_key, &tgid_fd, BPF_ANY);
    bpf_map_update_elem(&conn_info_map, &tgid_fd, &conn_info, BPF_ANY);

    struct socket_open_event_t socket_open_event = {};
    socket_open_event.id            = conn_info.id;
    socket_open_event.fd            = conn_info.fd;
    socket_open_event.conn_start_ns = conn_info.conn_start_ns;
    socket_open_event.port          = conn_info.port;
    socket_open_event.ip            = conn_info.ip;
    socket_open_event.src_ip        = srcIp;
    socket_open_event.src_port      = lport;

    if (print_bpf_logs) {
        bpf_printk("accept call: %llu %d %d",
                         socket_open_event.id, socket_open_event.fd, isConnect);
        bpf_printk("accept call 2: %llu %d %d",
                         socket_open_event.ip, socket_open_event.port, isConnect);
        bpf_printk("accept call 3: %llu %d %d",
                         socket_open_event.src_ip, socket_open_event.src_port, isConnect);
    }

    socket_open_event.socket_open_ns = conn_info.conn_start_ns;
    if (!disable_ring_submit) {
        bpf_ringbuf_output(&socket_open_events, &socket_open_event,
                           sizeof(struct socket_open_event_t), 0);
    }
}

static __always_inline void process_syscall_close(struct pt_regs* ctx,
                                            const struct close_args_t* args,
                                            u64 id) {
    int ret_val = PT_REGS_RC(ctx);

    if (ret_val < 0) {
        return;
    }

    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info == NULL) {
        return;
    }

    struct socket_close_event_t socket_close_event = {};
    socket_close_event.id            = conn_info->id;
    socket_close_event.fd            = conn_info->fd;
    socket_close_event.conn_start_ns = conn_info->conn_start_ns;
    socket_close_event.port          = conn_info->port;
    socket_close_event.ip            = conn_info->ip;

    socket_close_event.socket_close_ns = bpf_ktime_get_ns();
    if (!disable_ring_submit) {
        bpf_ringbuf_output(&socket_close_events, &socket_close_event,
                           sizeof(struct socket_close_event_t), 0);
    }
    bpf_map_delete_elem(&conn_info_map, &tgid_fd);
}

/*
 * Non-inline helper so the compiler cannot see through the call boundary
 * and eliminate the bounds check.  The BPF verifier sees
 * "if (size >= MAX_MSG_SIZE) size = MAX_MSG_SIZE" and proves
 * size ∈ [0, MAX_MSG_SIZE] which fits in msg[MAX_MSG_SIZE].
 *
 * Returns the number of bytes actually read, or 0 on failure/skip.
 */
static __noinline u32 bounded_probe_read_user(
        struct socket_data_event_t *event, u32 size, const void *src) {
    if (size >= MAX_MSG_SIZE) {
        size = MAX_MSG_SIZE;
    }
    if (size == 0) {
        return 0;
    }
    if (bpf_probe_read_user(event->msg, size, src) != 0) {
        return 0;
    }
    return size;
}

static __always_inline void process_syscall_data(struct pt_regs* ctx,
                                           const struct data_args_t* args,
                                           u64 id, bool is_send, bool ssl) {
    int bytes_exchanged = PT_REGS_RC(ctx);

    if (args->iovlen > 0 && args->buf_size > 0) {
        bytes_exchanged = args->buf_size;
    }

    if (bytes_exchanged <= 0) {
        return;
    }

    if (print_bpf_logs) {
        bpf_printk("SSL data 1 %d", id);
    }
    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    if (print_bpf_logs) {
        bpf_printk("SSL data 2 %d %llu %lu", id, tgid_fd, tgid);
    }
    struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    if (print_bpf_logs) {
        bpf_printk("SSL data 3 %d %llu %lu", id, tgid_fd, tgid);
    }

    if (conn_info->ssl != ssl) {
        return;
    }

    if (filter_strict_remote_port && conn_info->port != strict_remote_port) {
        return;
    }

    if (disable_ring_submit) {
        return;
    }

    if (print_bpf_logs) {
        bpf_printk("SSL data 4 %llu %llu %d", id, tgid_fd, ssl);
    }

    u32 kZero = 0;
    struct socket_data_event_t* socket_data_event =
        bpf_map_lookup_elem(&socket_data_event_buffer_heap, &kZero);
    if (socket_data_event == NULL) {
        return;
    }

    socket_data_event->id            = conn_info->id;
    socket_data_event->fd            = conn_info->fd;
    socket_data_event->conn_start_ns = conn_info->conn_start_ns;
    socket_data_event->port          = conn_info->port;
    socket_data_event->ip            = conn_info->ip;
    socket_data_event->ssl           = conn_info->ssl;

    int bytes_sent  = 0;
    u32  size_to_save = 0;
    int i = 0;
#pragma unroll
    for (i = 0; i < CHUNK_LIMIT; ++i) {
        const int bytes_remaining = bytes_exchanged - bytes_sent;

        if (bytes_remaining <= 0) {
            break;
        }
        u32 current_size;
        if (bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1)) {
            current_size = (u32)MAX_MSG_SIZE;
        } else {
            current_size = (u32)bytes_remaining;
        }

        u32 read_size = bounded_probe_read_user(
            socket_data_event, current_size,
            (const char *)args->buf + bytes_sent);
        if (read_size == 0 && current_size > 0) {
            break;
        }
        size_to_save = read_size;

        if (is_send) {
            conn_info->writeEventsCount = (conn_info->writeEventsCount) + 1u;
        } else {
            conn_info->readEventsCount = (conn_info->readEventsCount) + 1u;
        }

        socket_data_event->writeEventsCount = conn_info->writeEventsCount;
        socket_data_event->readEventsCount  = conn_info->readEventsCount;

        if (print_bpf_logs) {
            bpf_printk("pid: %d conn-id:%d, fd: %d",
                             id, conn_info->id, conn_info->fd);
            bpf_printk("current_size: %d i:%d, bytes_exchanged: %d",
                             current_size, i, bytes_exchanged);
            bpf_printk("rwc: %d tdfd: %llu data: %s",
                             (socket_data_event->readEventsCount * 10000 +
                              socket_data_event->writeEventsCount % 10000),
                             tgid_fd, socket_data_event->msg);
        }

        socket_data_event->bytes_sent  = is_send ? 1 : -1;
        socket_data_event->bytes_sent *= size_to_save;
        if (log_socket_data_submit_stats) {
            u32 __sd_k = 0;
            u64 *__sd_tot = bpf_map_lookup_elem(&socket_data_submit_total, &__sd_k);
            if (__sd_tot != NULL) {
                (*__sd_tot) += 1;
            }
        }
        bpf_ringbuf_output(&socket_data_events, socket_data_event,
                           sizeof(struct socket_data_event_t) - MAX_MSG_SIZE + size_to_save, 0);

        bytes_sent += current_size;
    }
}

static __always_inline void process_syscall_data_vecs(struct pt_regs* ctx,
                                                struct data_args_t* args,
                                                u64 id, bool is_send) {
    int bytes_sent  = 0;
    int total_size  = PT_REGS_RC(ctx);
    const struct iovec* iov = args->iov;
    for (int i = 0; i < LOOP_LIMIT && i < args->iovlen && bytes_sent < total_size; ++i) {
        struct iovec iov_cpy;
        bpf_probe_read_user(&iov_cpy, sizeof(iov_cpy), &iov[i]);

        const int bytes_remaining = total_size - bytes_sent;
        const size_t iov_size = iov_cpy.iov_len < bytes_remaining
                                ? iov_cpy.iov_len : bytes_remaining;

        args->buf      = iov_cpy.iov_base;
        args->buf_size = iov_size;
        process_syscall_data(ctx, args, id, is_send, false);
        bytes_sent += iov_size;
    }
}

/* ===================================================================
 * Kprobe hooks — syscall level
 * All functions use SEC("kprobe"). The Go loader attaches them as
 * kprobe or kretprobe based on the ProbeType in the hook tables.
 * Syscall arguments are read from pt_regs via PT_REGS_PARM*_CORE_SYSCALL.
 * =================================================================== */

SEC("kprobe")
int syscall__probe_entry_accept(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_accept: pid: %d", id);
    }

    struct sockaddr* addr = (struct sockaddr*)SYSCALL_PARM2(ctx);

    struct accept_args_t accept_args = {};
    accept_args.addr = addr;
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_accept(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_accept: pid: %d", id);
    }

    struct accept_args_t* accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);

    if (accept_args != NULL) {
        process_syscall_accept(ctx, accept_args, id, false);
    }

    bpf_map_delete_elem(&active_accept_args_map, &id);
    return 0;
}

SEC("kprobe")
int probe_ret_sock_alloc(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_ret_sock_alloc: pid: %d", id);
    }

    struct accept_args_t* accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (accept_args == NULL) {
        return 0;
    }

    if (accept_args->sock_alloc_socket == NULL) {
        accept_args->sock_alloc_socket = (struct socket*)PT_REGS_RC(ctx);
    }

    return 0;
}

SEC("kprobe")
int probe_entry_tcp_connect(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tcp_connect: pid: %d", id);
    }

    struct accept_args_t* accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (accept_args == NULL) {
        return 0;
    }

    if (accept_args->sock == NULL) {
        accept_args->sock = (void*)PT_REGS_PARM1(ctx);
    }

    return 0;
}

SEC("kprobe")
int syscall__probe_entry_connect(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_connect: pid: %d", id);
    }

    int sockfd          = (int)SYSCALL_PARM1(ctx);
    struct sockaddr* addr = (struct sockaddr*)SYSCALL_PARM2(ctx);

    struct accept_args_t accept_args = {};
    accept_args.fd   = sockfd;
    accept_args.addr = addr;
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_connect(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_connect: pid: %d", id);
    }

    struct accept_args_t* accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);

    if (accept_args != NULL) {
        if (accept_args->sock != NULL) {
            struct sock* sock = accept_args->sock;
            accept_args->sock_alloc_socket = BPF_CORE_READ(sock, sk_socket);
        }
        process_syscall_accept(ctx, accept_args, id, true);
    }

    bpf_map_delete_elem(&active_accept_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_close(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_close: pid: %d", id);
    }

    int fd = (int)SYSCALL_PARM1(ctx);

    struct close_args_t close_args = {};
    close_args.fd = fd;
    bpf_map_update_elem(&active_close_args_map, &id, &close_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_close(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_close: pid: %d", id);
    }

    struct close_args_t* close_args = bpf_map_lookup_elem(&active_close_args_map, &id);

    if (close_args != NULL) {
        process_syscall_close(ctx, close_args, id);
    }

    bpf_map_delete_elem(&active_close_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_writev(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_writev: pid: %d", id);
    }

    int fd                  = (int)SYSCALL_PARM1(ctx);
    const struct iovec* iov = (const struct iovec*)SYSCALL_PARM2(ctx);
    int iovlen              = (int)SYSCALL_PARM3(ctx);

    struct data_args_t write_args = {};
    write_args.fd     = fd;
    write_args.iov    = iov;
    write_args.iovlen = iovlen;
    write_args.source_fn = kSyscallWriteV;

    struct data_args_t* existing = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (existing != NULL && existing->sock_event) {
        write_args.sock_event = true;
    }

    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_writev(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_writev: pid: %d", id);
    }

    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    /* Match module.cc: only capture after security_socket_sendmsg marked this syscall. */
    if (write_args != NULL && write_args->sock_event) {
        if (print_bpf_logs) {
            bpf_printk("syscall__probe_ret_writev data process: pid: %d", id);
        }
        process_syscall_data_vecs(ctx, write_args, id, true);
    }

    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_sendmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    int fd = (int)SYSCALL_PARM1(ctx);
    struct user_msghdr* msghdr = (struct user_msghdr*)SYSCALL_PARM2(ctx);

    if (msghdr != NULL) {
        if (print_bpf_logs) {
            bpf_printk("syscall__probe_entry_sendmsg: pid: %d", id);
        }

        struct user_msghdr msghdr_copy = {};
        if (bpf_probe_read_user(&msghdr_copy, sizeof(msghdr_copy), msghdr) != 0) {
            return 0;
        }

        struct data_args_t write_args = {};
        write_args.fd        = fd;
        write_args.iov       = msghdr_copy.msg_iov;
        write_args.iovlen    = msghdr_copy.msg_iovlen;
        write_args.source_fn = kSyscallSendMsg;
        bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);
    }

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_sendmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_sendmsg: pid: %d", id);
    }

    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (write_args != NULL) {
        process_syscall_data_vecs(ctx, write_args, id, true);
    }

    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_readv(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_readv: pid: %d", id);
    }

    int fd             = (int)SYSCALL_PARM1(ctx);
    struct iovec* iov  = (struct iovec*)SYSCALL_PARM2(ctx);
    int iovlen         = (int)SYSCALL_PARM3(ctx);

    struct data_args_t read_args = {};
    read_args.fd        = fd;
    read_args.iov       = iov;
    read_args.iovlen    = iovlen;
    read_args.source_fn = kSyscallReadV;

    struct data_args_t* existing = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (existing != NULL && existing->sock_event) {
        read_args.sock_event = true;
    }

    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_readv(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_readv: pid: %d", id);
    }

    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    /* Match module.cc: only capture after security_socket_recvmsg marked this syscall. */
    if (read_args != NULL && read_args->sock_event) {
        process_syscall_data_vecs(ctx, read_args, id, false);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_recvfrom(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    int fd     = (int)SYSCALL_PARM1(ctx);
    char* buf  = (char*)SYSCALL_PARM2(ctx);

    if (print_bpf_logs) {
        struct data_args_t* read_args_1 = bpf_map_lookup_elem(&active_read_args_map, &id);
        if (read_args_1 != NULL) {
            bpf_printk("syscall__probe_entry_recvfrom: pid: %llu fd: %d read args : %d",
                             id, fd, read_args_1->fd);
        } else {
            bpf_printk("syscall__probe_entry_recvfrom: pid: %llu fd: %d read args : NULL",
                             id, fd);
        }
    }

    struct data_args_t read_args = {};
    read_args.buf       = buf;
    read_args.fd        = fd;
    read_args.source_fn = kSyscallRecvFrom;
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_recvfrom(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_recvfrom: pid: %d", id);
    }

    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);

    if (read_args != NULL) {
        process_syscall_data(ctx, read_args, id, false, false);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_sendto(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    int fd    = (int)SYSCALL_PARM1(ctx);
    char* buf = (char*)SYSCALL_PARM2(ctx);

    if (print_bpf_logs) {
        struct data_args_t* write_args_1 = bpf_map_lookup_elem(&active_write_args_map, &id);
        if (write_args_1 != NULL) {
            bpf_printk("syscall__probe_entry_sendto: pid: %llu fd: %d write args : %d",
                             id, fd, write_args_1->fd);
        } else {
            bpf_printk("syscall__probe_entry_sendto: pid: %llu fd: %d write args : NULL",
                             id, fd);
        }
    }

    struct data_args_t write_args = {};
    write_args.buf       = buf;
    write_args.fd        = fd;
    write_args.source_fn = kSyscallSendTo;
    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_sendto(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_sendto: pid: %d", id);
    }

    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);

    if (write_args != NULL) {
        process_syscall_data(ctx, write_args, id, true, false);
    }

    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_recv(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_recv: pid: %d", id);
    }

    int fd    = (int)SYSCALL_PARM1(ctx);
    char* buf = (char*)SYSCALL_PARM2(ctx);

    struct data_args_t read_args = {};
    read_args.buf       = buf;
    read_args.fd        = fd;
    read_args.source_fn = kSyscallRecv;
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_recv(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_recv: pid: %d", id);
    }

    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);

    if (read_args != NULL) {
        process_syscall_data(ctx, read_args, id, false, false);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_read(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    int fd    = (int)SYSCALL_PARM1(ctx);
    char* buf = (char*)SYSCALL_PARM2(ctx);

    if (print_bpf_logs) {
        struct data_args_t* read_args_1 = bpf_map_lookup_elem(&active_read_args_map, &id);
        if (read_args_1 != NULL) {
            bpf_printk("syscall__probe_entry_read: pid: %llu fd: %d read args : %d",
                             id, fd, read_args_1->fd);
        } else {
            bpf_printk("syscall__probe_entry_read: pid: %llu fd: %d read args : NULL",
                             id, fd);
        }
    }

    struct data_args_t read_args = {};
    read_args.buf       = buf;
    read_args.fd        = fd;
    read_args.source_fn = kSyscallRead;

    struct data_args_t* existing = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (existing != NULL && existing->sock_event) {
        read_args.sock_event = true;
    }

    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_read(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_read: pid: %d", id);
    }

    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);

    /* Match module.cc: only capture after security_socket_recvmsg marked this syscall. */
    if (read_args != NULL && read_args->sock_event) {
        process_syscall_data(ctx, read_args, id, false, false);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_recvmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    int fd = (int)SYSCALL_PARM1(ctx);
    struct user_msghdr* msghdr = (struct user_msghdr*)SYSCALL_PARM2(ctx);

    if (msghdr != NULL) {
        if (print_bpf_logs) {
            bpf_printk("syscall__probe_entry_recvmsg: pid: %d", id);
        }

        struct user_msghdr msghdr_copy = {};
        if (bpf_probe_read_user(&msghdr_copy, sizeof(msghdr_copy), msghdr) != 0) {
            return 0;
        }

        struct data_args_t read_args = {};
        read_args.fd        = fd;
        read_args.iov       = msghdr_copy.msg_iov;
        read_args.iovlen    = msghdr_copy.msg_iovlen;
        read_args.source_fn = kSyscallRecvMsg;
        bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);
    }

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_recvmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_recvmsg: pid: %d", id);
    }

    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);

    if (read_args != NULL) {
        process_syscall_data_vecs(ctx, read_args, id, false);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_send(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_send: pid: %d", id);
    }

    int fd    = (int)SYSCALL_PARM1(ctx);
    char* buf = (char*)SYSCALL_PARM2(ctx);

    struct data_args_t write_args = {};
    write_args.buf       = buf;
    write_args.fd        = fd;
    write_args.source_fn = kSyscallSend;
    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);

    return 0;
}

SEC("kprobe")
int syscall__probe_ret_send(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_send: pid: %d", id);
    }

    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);

    if (write_args != NULL) {
        process_syscall_data(ctx, write_args, id, true, false);
    }

    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_write(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_entry_write: pid: %d", id);
    }

    int fd    = (int)SYSCALL_PARM1(ctx);
    char* buf = (char*)SYSCALL_PARM2(ctx);

    struct data_args_t write_args = {};
    write_args.buf       = buf;
    write_args.fd        = fd;
    write_args.source_fn = kSyscallWrite;

    struct data_args_t* existing = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (existing != NULL && existing->sock_event) {
        write_args.sock_event = true;
    }

    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);
    return 0;
}

SEC("kprobe")
int syscall__probe_ret_write(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        struct data_args_t* write_args_1 = bpf_map_lookup_elem(&active_write_args_map, &id);
        if (write_args_1 != NULL) {
            bpf_printk("syscall__probe_ret_write: pid: %llu write args : %d",
                             id, write_args_1->fd);
        } else {
            bpf_printk("syscall__probe_ret_write: pid: %llu write args : NULL", id);
        }
    }

    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);

    /* Match module.cc: only capture after security_socket_sendmsg marked this syscall. */
    if (write_args != NULL && write_args->sock_event) {
        if (print_bpf_logs) {
            bpf_printk("syscall__probe_ret_write data process: pid: %d", id);
        }
        process_syscall_data(ctx, write_args, id, true, false);
    }

    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

SEC("kprobe")
int probe_entry_security_socket_sendmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_entry_security_socket_sendmsg: pid: %d", id);
    }
    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (write_args != NULL) {
        write_args->sock_event = true;
    }
    return 0;
}

SEC("kprobe")
int probe_entry_security_socket_recvmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_entry_security_socket_recvmsg: pid: %d", id);
    }

    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args != NULL) {
        read_args->sock_event = true;
    }
    return 0;
}

SEC("kprobe")
int probe_entry_setsockopt(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_entry_setsockopt: pid: %d", id);
    }

    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (write_args != NULL) {
        write_args->sock_event = true;
    }
    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args != NULL) {
        read_args->sock_event = true;
    }
    return 0;
}

/* ===================================================================
 * SSL / OpenSSL uprobe helpers and probes
 * BPF_UPROBE extracts named args from pt_regs; ctx is still available.
 * =================================================================== */

static u32 get_fd(void* ssl, int sslVersion, bool rw) {
    int32_t SSL_rbio_offset;
    int32_t RBIO_num_offset = 0;

    SSL_rbio_offset = 16;
    switch (sslVersion) {
    case 1:
        RBIO_num_offset = 40;
        break;
    case 2:
        RBIO_num_offset = 48;
        break;
    case 3:
        RBIO_num_offset = 56;
        break;
    case 4:
        SSL_rbio_offset = 24;
        RBIO_num_offset = 24;
        break;
    default:
        break;
    }

    const void* rbio_ptr;
    bpf_probe_read_user(&rbio_ptr, sizeof(rbio_ptr), ssl + SSL_rbio_offset);
    u32 rbio_num;
    bpf_probe_read_user(&rbio_num, sizeof(rbio_num), rbio_ptr + RBIO_num_offset);

    if (print_bpf_logs) {
        bpf_printk("SSL fd offset: %d %d %d", rbio_num,
                         SSL_rbio_offset, RBIO_num_offset);
    }
    return rbio_num;
}

static void set_conn_as_ssl(u32 tgid, u32 fd) {
    u64 tgid_fd = gen_tgid_fd(tgid, fd);
    if (print_bpf_logs) {
        bpf_printk("SSL tgid: %d", tgid_fd);
    }
    struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    if (print_bpf_logs) {
        bpf_printk("SSL marking ssl tgid: %d", tgid_fd);
    }
    conn_info->ssl = true;
}

/*
 * probe_entry_SSL_write_core — shared inner handler for all SSL write entry probes.
 * With BPF_UPROBE, buf is already extracted from pt_regs by the macro; we pass it directly.
 */
static void probe_entry_SSL_write_core(struct pt_regs* ctx, void* ssl, void* buf,
                                        int num, u32 fd) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_core: pid: %d %d %d", id, tgid, fd);
    }

    char* bufc = (char*)buf;

    struct data_args_t write_args = {};
    write_args.fd  = fd;
    write_args.buf = bufc;
    bpf_map_update_elem(&active_ssl_write_args_map, &id, &write_args, BPF_ANY);

    set_conn_as_ssl(tgid, write_args.fd);
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_1_0, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 1, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_1_0: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_1_1, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 2, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_1_1: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_3_0, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 3, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_3_0: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
    return 0;
}

/* Node-OpenSSL only: FD resolved via the TLS-wrap map. */
SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write, void* ssl, void* buf, int num) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    __u64 ssl_key = (__u64)ssl;
    __u64* tls_wrap_val = bpf_map_lookup_elem(&node_ssl_tls_wrap_map, &ssl_key);
    u32 fd = 0;
    if (tls_wrap_val != NULL) {
        /* get_fd_node logic inlined for the node case */
        u32 tgid_key = tgid;
        struct node_tlswrap_symaddrs_t* symaddrs =
            bpf_map_lookup_elem(&node_tlswrap_symaddrs_map, &tgid_key);
        if (symaddrs != NULL) {
            void* tls_wrap = (void*)*tls_wrap_val;
            void* stream_ptr = tls_wrap + symaddrs->TLSWrapStreamListenerOffset
                               + symaddrs->StreamListenerStreamOffset;
            void* stream = NULL;
            bpf_probe_read(&stream, sizeof(stream), stream_ptr);
            if (stream != NULL) {
                void* uv_stream_ptr = stream
                                      - symaddrs->StreamBaseStreamResourceOffset
                                      - symaddrs->LibuvStreamWrapStreamBaseOffset
                                      + symaddrs->LibuvStreamWrapStreamOffset;
                void* uv_stream = NULL;
                bpf_probe_read(&uv_stream, sizeof(uv_stream), uv_stream_ptr);
                if (uv_stream != NULL) {
                    int32_t* fd_ptr = uv_stream + symaddrs->UVStreamSIOWatcherOffset
                                      + symaddrs->UVIOSFDOffset;
                    int32_t fd_val = 0;
                    if (bpf_probe_read(&fd_val, sizeof(fd_val), fd_ptr) == 0) {
                        fd = (u32)fd_val;
                    }
                }
            }
        }
    }
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_boring, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 4, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_boring: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int probe_ret_SSL_write(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_ret_SSL_write: pid: %d", id);
    }

    const struct data_args_t* write_args = bpf_map_lookup_elem(&active_ssl_write_args_map, &id);
    if (write_args != NULL) {
        process_syscall_data(ctx, write_args, id, true, true);
    }

    bpf_map_delete_elem(&active_ssl_write_args_map, &id);
    return 0;
}

static void probe_entry_SSL_read_core(struct pt_regs* ctx, void* ssl, void* buf,
                                       int num, u32 fd) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_core: pid: %d %d %d", id, tgid, fd);
    }

    char* bufc = (char*)buf;

    struct data_args_t read_args = {};
    read_args.fd  = fd;
    read_args.buf = bufc;
    bpf_map_update_elem(&active_ssl_read_args_map, &id, &read_args, BPF_ANY);

    set_conn_as_ssl(tgid, read_args.fd);
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_1_0, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 1, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_1_0: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_1_1, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 2, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_1_1: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_3_0, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 3, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_3_0: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
    return 0;
}

/* Node-OpenSSL only. */
SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read, void* ssl, void* buf, int num) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    __u64 ssl_key = (__u64)ssl;
    __u64* tls_wrap_val = bpf_map_lookup_elem(&node_ssl_tls_wrap_map, &ssl_key);
    int32_t fd = 0;
    if (tls_wrap_val != NULL) {
        u32 tgid_key = tgid;
        struct node_tlswrap_symaddrs_t* symaddrs =
            bpf_map_lookup_elem(&node_tlswrap_symaddrs_map, &tgid_key);
        if (symaddrs != NULL) {
            void* tls_wrap = (void*)*tls_wrap_val;
            void* stream_ptr = tls_wrap + symaddrs->TLSWrapStreamListenerOffset
                               + symaddrs->StreamListenerStreamOffset;
            void* stream = NULL;
            bpf_probe_read(&stream, sizeof(stream), stream_ptr);
            if (stream != NULL) {
                void* uv_stream_ptr = stream
                                      - symaddrs->StreamBaseStreamResourceOffset
                                      - symaddrs->LibuvStreamWrapStreamBaseOffset
                                      + symaddrs->LibuvStreamWrapStreamOffset;
                void* uv_stream = NULL;
                bpf_probe_read(&uv_stream, sizeof(uv_stream), uv_stream_ptr);
                if (uv_stream != NULL) {
                    int32_t* fd_ptr = uv_stream + symaddrs->UVStreamSIOWatcherOffset
                                      + symaddrs->UVIOSFDOffset;
                    int32_t fd_val = 0;
                    if (bpf_probe_read(&fd_val, sizeof(fd_val), fd_ptr) == 0) {
                        fd = fd_val;
                    }
                }
            }
        }
    }
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_boring, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 4, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_boring: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
    return 0;
}

SEC("uprobe")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_ret_SSL_read: pid: %d", id);
    }

    const struct data_args_t* read_args = bpf_map_lookup_elem(&active_ssl_read_args_map, &id);
    if (read_args != NULL) {
        process_syscall_data(ctx, read_args, id, false, true);
    }

    bpf_map_delete_elem(&active_ssl_read_args_map, &id);
    return 0;
}

/* ===================================================================
 * Go TLS probes
 * =================================================================== */

static __always_inline uint64_t* go_regabi_regs(const struct pt_regs* ctx) {
    uint32_t kZero = 0;
    struct go_regabi_regs* regs_heap_var = bpf_map_lookup_elem(&regs_heap, &kZero);
    if (regs_heap_var == NULL) {
        return NULL;
    }

#if defined(TARGET_ARCH_X86_64)
    regs_heap_var->regs[0] = ctx->ax;
    regs_heap_var->regs[1] = ctx->bx;
    regs_heap_var->regs[2] = ctx->cx;
    regs_heap_var->regs[3] = ctx->di;
    regs_heap_var->regs[4] = ctx->si;
    regs_heap_var->regs[5] = ctx->r8;
    regs_heap_var->regs[6] = ctx->r9;
    regs_heap_var->regs[7] = ctx->r10;
    regs_heap_var->regs[8] = ctx->r11;
#elif defined(TARGET_ARCH_AARCH64)
#pragma unroll
    for (uint32_t i = 0; i < 9; i++) {
        regs_heap_var->regs[i] = ctx->regs[i];
    }
#else
#error Target Architecture not supported
#endif

    return regs_heap_var->regs;
}

static inline uint64_t get_goid(struct pt_regs* ctx) {
    uint64_t id   = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;
    struct go_symaddrs_t* common_symaddrs = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (common_symaddrs == NULL) {
        return 0;
    }

    /* CO-RE: resolve task_struct->thread field offsets from BTF. */
    struct task_struct* task_ptr = (struct task_struct*)bpf_get_current_task();
    if (!task_ptr) {
        return 0;
    }

#if defined(TARGET_ARCH_X86_64)
    const void* fs_base = (void*)BPF_CORE_READ(task_ptr, thread.fsbase);
#elif defined(TARGET_ARCH_AARCH64)
    const void* fs_base = (void*)BPF_CORE_READ(task_ptr, thread.uw.tp_value);
#else
#error Target architecture not supported
#endif

    int32_t g_addr_offset = -8;
    uint64_t goid;
    size_t g_addr;
    bpf_probe_read_user(&g_addr, sizeof(void*), (void*)(fs_base + g_addr_offset));
    bpf_probe_read_user(&goid, sizeof(void*),
                        (void*)(g_addr + common_symaddrs->GIDOffset));
    return goid;
}

static __always_inline void assign_arg(void* arg, size_t arg_size, struct location_t loc,
                                 const void* sp, uint64_t* regs) {
    if (loc.type == kLocationTypeStack) {
        bpf_probe_read_user(arg, arg_size, sp + loc.offset);
    } else if (loc.type == kLocationTypeRegisters) {
        if (loc.offset >= 0) {
            bpf_probe_read(arg, arg_size, (char*)regs + loc.offset);
        }
    }
}

static __always_inline int32_t get_fd_from_conn_intf_core(struct go_interface conn_intf,
                                                    const struct go_symaddrs_t* symaddrs) {
    // All pointers here live in the Go process heap (user space).
    // On kernels >= 5.11 bpf_probe_read() aliases bpf_probe_read_kernel()
    // and returns -EFAULT for user-space addresses. Use bpf_probe_read_user().
    //
    // Also skip the TCPConnOffset type check: that value comes from DWARF and
    // does not match the runtime interface type pointer for PIE binaries.
    if (bpf_probe_read_user(&conn_intf, sizeof(conn_intf),
                            conn_intf.ptr + symaddrs->TLSConnOffset) != 0) {
        return 0;
    }
    if (conn_intf.ptr == NULL) {
        return 0;
    }
    void* fd_ptr = NULL;
    if (bpf_probe_read_user(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr) != 0 || fd_ptr == NULL) {
        return 0;
    }
    int32_t sysfd = 0;
    bpf_probe_read_user(&sysfd, sizeof(sysfd), fd_ptr + symaddrs->FDSysFDOffset);
    return sysfd;
}

SEC("uprobe")
int probe_entry_tls_conn_write(struct pt_regs* ctx) {
    uint64_t id   = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;

    struct tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_write FIRED tgid=%lu", tgid);
    }

    uint64_t goid = get_goid(ctx);

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_write goid=%llu tgid=%lu", goid, tgid);
    }

    if (goid == 0) {
        return 0;
    }
    tgid_goid.goid = goid;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_write 1 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp  = (const void*)PT_REGS_SP(ctx);
    uint64_t* regs  = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_write 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_tls_conn_args args = {};
    assign_arg(&args.conn_ptr, sizeof(args.conn_ptr),
               symaddrs->WriteConnectionLoc, sp, regs);
    assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr),
               symaddrs->WriteBufferLoc, sp, regs);

    bpf_map_update_elem(&active_tls_conn_op_map, &tgid_goid, &args, BPF_ANY);

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_write 3 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }
    return 0;
}

static __always_inline int probe_return_tls_conn_write_core(struct pt_regs* ctx, uint64_t id,
                                                      uint32_t tgid,
                                                      struct go_tls_conn_args* args) {
    struct go_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp = (const void*)PT_REGS_SP(ctx);
    uint64_t* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    int64_t retval0 = 0;
    assign_arg(&retval0, sizeof(retval0), symaddrs->WriteRet0Loc, sp, regs);

    struct go_interface retval1 = {};
    assign_arg(&retval1, sizeof(retval1), symaddrs->WriteRet1Loc, sp, regs);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 2.1 %llu %lu", id, tgid);
    }

    if (retval1.ptr != 0) {
        return 0;
    }

    struct go_interface conn_intf;
    conn_intf.type = 1;
    conn_intf.ptr  = args->conn_ptr;
    int fd  = get_fd_from_conn_intf_core(conn_intf, symaddrs);
    u32 fdu = (u32)fd;

    if (print_bpf_logs) {
        bpf_printk("TLS write fd: %d", fd);
    }

    if (fd <= 0) {
        return 0;
    }

    set_conn_as_ssl(tgid, fdu);
    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 2.2 %llu %lu", id, tgid);
    }

    struct data_args_t data_args;
    data_args.source_fn = kGoTLSWrite;
    data_args.buf       = args->plaintext_ptr;
    data_args.fd        = fd;

    process_syscall_data(ctx, &data_args, id, true, true);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 2.3 %llu %lu", id, tgid);
    }

    return 0;
}

SEC("uprobe")
int probe_return_tls_conn_write(struct pt_regs* ctx) {
    uint64_t id   = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;

    struct tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;
    uint64_t goid  = get_goid(ctx);
    if (goid == 0) {
        return 0;
    }
    tgid_goid.goid = goid;

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 1 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_tls_conn_args* args = bpf_map_lookup_elem(&active_tls_conn_op_map, &tgid_goid);
    if (args == NULL) {
        return 0;
    }

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    probe_return_tls_conn_write_core(ctx, id, tgid, args);

    bpf_map_delete_elem(&active_tls_conn_op_map, &tgid_goid);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 3 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }
    return 0;
}

SEC("uprobe")
int probe_entry_tls_conn_read(struct pt_regs* ctx) {
    uint64_t id   = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;

    struct tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;
    uint64_t goid  = get_goid(ctx);
    if (goid == 0) {
        return 0;
    }
    tgid_goid.goid = goid;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_read 1 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp = (const void*)PT_REGS_SP(ctx);
    uint64_t* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_read 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_tls_conn_args args = {};
    assign_arg(&args.conn_ptr, sizeof(args.conn_ptr),
               symaddrs->ReadConnectionLoc, sp, regs);
    assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr),
               symaddrs->ReadBufferLoc, sp, regs);

    bpf_map_update_elem(&active_tls_conn_op_map, &tgid_goid, &args, BPF_ANY);

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_read 3 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    return 0;
}

static __always_inline int probe_return_tls_conn_read_core(struct pt_regs* ctx, uint64_t id,
                                                     uint32_t tgid,
                                                     struct go_tls_conn_args* args) {
    struct go_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    const void* sp = (const void*)PT_REGS_SP(ctx);
    uint64_t* regs = go_regabi_regs(ctx);
    if (regs == NULL) {
        return 0;
    }

    int64_t retval0 = 0;
    assign_arg(&retval0, sizeof(retval0), symaddrs->ReadRet0Loc, sp, regs);

    struct go_interface retval1 = {};
    assign_arg(&retval1, sizeof(retval1), symaddrs->ReadRet1Loc, sp, regs);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 2.1 %llu %lu", id, tgid);
    }

    if (retval1.ptr != 0) {
        return 0;
    }

    struct go_interface conn_intf;
    conn_intf.type = 1;
    conn_intf.ptr  = args->conn_ptr;
    int fd  = get_fd_from_conn_intf_core(conn_intf, symaddrs);
    u32 fdu = (u32)fd;

    if (print_bpf_logs) {
        bpf_printk("TLS read fd: %d", fd);
    }

    if (fd <= 0) {
        return 0;
    }

    set_conn_as_ssl(tgid, fdu);
    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 2.2 %llu %lu", id, tgid);
    }

    struct data_args_t data_args;
    data_args.source_fn = kGoTLSRead;
    data_args.buf       = args->plaintext_ptr;
    data_args.fd        = fd;

    process_syscall_data(ctx, &data_args, id, false, true);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 2.3 %llu %lu", id, tgid);
    }

    return 0;
}

SEC("uprobe")
int probe_return_tls_conn_read(struct pt_regs* ctx) {
    uint64_t id   = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;

    struct tgid_goid_t tgid_goid = {};
    tgid_goid.tgid = tgid;
    uint64_t goid  = get_goid(ctx);
    if (goid == 0) {
        return 0;
    }
    tgid_goid.goid = goid;

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 1 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_tls_conn_args* args = bpf_map_lookup_elem(&active_tls_conn_op_map, &tgid_goid);
    if (args == NULL) {
        return 0;
    }

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    probe_return_tls_conn_read_core(ctx, id, tgid, args);

    bpf_map_delete_elem(&active_tls_conn_op_map, &tgid_goid);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 3 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }
    return 0;
}

/* ===================================================================
 * Node.js TLS wrap probes
 * =================================================================== */

SEC("uprobe")
int probe_ret_SSL_new(struct pt_regs* ctx) {
    void* ssl = (void*)PT_REGS_RC(ctx);
    if (ssl == NULL) {
        return 0;
    }
    uint64_t id   = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;

    struct node_tlswrap_symaddrs_t* symaddrs =
        bpf_map_lookup_elem(&node_tlswrap_symaddrs_map, &tgid);
    if (symaddrs == NULL) {
        return 0;
    }

    /* update_node_ssl_tls_wrap_map inlined */
    __u64* tls_wrap_val = bpf_map_lookup_elem(&active_TLSWrap_memfn_this, &id);
    if (tls_wrap_val != NULL) {
        __u64 ssl_key       = (__u64)ssl;
        __u64 tls_wrap_copy = *tls_wrap_val;
        bpf_map_update_elem(&node_ssl_tls_wrap_map, &ssl_key, &tls_wrap_copy, BPF_ANY);
    }

    return 0;
}

SEC("uprobe")
int probe_entry_TLSWrap_memfn(struct pt_regs* ctx) {
    __u64 tls_wrap = (__u64)PT_REGS_PARM1(ctx);
    uint64_t id    = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_TLSWrap_memfn_this, &id, &tls_wrap, BPF_ANY);
    return 0;
}

SEC("uprobe")
int probe_ret_TLSWrap_memfn(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&active_TLSWrap_memfn_this, &id);
    return 0;
}
