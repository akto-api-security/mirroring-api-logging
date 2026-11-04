/*
 * module.bpf.c — libbpf/CO-RE eBPF kernel program.
 *
 * Compiled ahead-of-time with bpf2go; no BCC or host kernel headers required.
 * vmlinux.h provides all kernel types from the running kernel's BTF data.
 */

#include "vmlinux.h"

/*
 * On arm64, libbpf's PT_REGS_* macros from bpf_tracing.h cast the probe context
 * to struct user_pt_regs*. Some bpftool-generated vmlinux.h files only forward-
 * declare user_pt_regs, which breaks compilation. The layout matches Linux
 * arch/arm64 UAPI (include/uapi/asm/ptrace.h).
 */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

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
 * for each architecture (di/si/dx on x86-64).
 *
 * On ARM64, BTF struct pt_regs often omits named user_regs/regs fields (anonymous
 * unions). Syscall GPRs still match struct user_pt_regs at offset 0, so cast the
 * inner regs pointer and BPF_CORE_READ user_pt_regs.regs[n] (CO-RE against the
 * kernel's user_pt_regs type, not pt_regs layout names).
 */
#ifdef TARGET_ARCH_AARCH64
  #define __syscall_user_regs_ptr(ctx) \
      ((const struct user_pt_regs *)(const void *)PT_REGS_PARM1(ctx))
  #define SYSCALL_PARM1(ctx) BPF_CORE_READ(__syscall_user_regs_ptr(ctx), regs[0])
  #define SYSCALL_PARM2(ctx) BPF_CORE_READ(__syscall_user_regs_ptr(ctx), regs[1])
  #define SYSCALL_PARM3(ctx) BPF_CORE_READ(__syscall_user_regs_ptr(ctx), regs[2])
  #define SYSCALL_PARM4(ctx) BPF_CORE_READ(__syscall_user_regs_ptr(ctx), regs[3])
#elif defined(TARGET_ARCH_X86_64)
  #define SYSCALL_PARM1(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), di)
  #define SYSCALL_PARM2(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), si)
  #define SYSCALL_PARM3(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), dx)
  /* 4th syscall argument is r10 on x86-64 (rcx is clobbered by syscall). */
  #define SYSCALL_PARM4(ctx) \
      BPF_CORE_READ((const struct pt_regs *)PT_REGS_PARM1(ctx), r10)
#else
  #define SYSCALL_PARM1(ctx) PT_REGS_PARM1_CORE_SYSCALL(ctx)
  #define SYSCALL_PARM2(ctx) PT_REGS_PARM2_CORE_SYSCALL(ctx)
  #define SYSCALL_PARM3(ctx) PT_REGS_PARM3_CORE_SYSCALL(ctx)
  #define SYSCALL_PARM4(ctx) PT_REGS_PARM4_CORE_SYSCALL(ctx)
#endif

/* recv flag: data is returned but stays in the socket and is read again. */
#ifndef MSG_PEEK
#define MSG_PEEK 2
#endif

/*
 * BPF global read-only variable — set from userspace via CollectionSpec before loading.
 * Replaces the runtime Go string-substitution used in the BCC version.
 */
volatile const bool print_bpf_logs = false;
/* When true (env TRAFFIC_LOG_BPF_SOCKET_DATA_SUBMITS), count each socket_data ringbuf submit. */
volatile const bool log_socket_data_submit_stats = false;
/* When true (env FILTER_LOCAL_TRAFFIC, default on), skip connections whose remote IP matches
 * local_traffic_ip (set from env LOCAL_TRAFFIC_IP IPv4; loader converts to LE u32). */
volatile const bool filter_local_traffic = true;
volatile const __u32 local_traffic_ip = 16777343;
/* When true (env TRAFFIC_STRICT_REMOTE_PORT_FILTER), only capture connections whose remote
 * port matches strict_remote_port (default 10275). */
volatile const bool filter_strict_remote_port = false;
volatile const __u16 strict_remote_port = 10275;
/* When true (env TRAFFIC_DISABLE_PERF_SUBMIT), skip all ringbuf_output calls. */
volatile const bool disable_ring_submit = false;
/* When true (env TRAFFIC_DISABLE_EGRESS, default on), skip registering conn_info_map
 * entries for connect()-originated sockets — this process acting as a TCP client
 * (e.g. nginx -> upstream). Userspace already discards this side when building Kafka
 * messages (ebpf/connections/factory.go); doing it here means those sockets never
 * reach conn_info_map, the data/open/close ring buffers, or the Go tracker at all.
 * accept()-originated (ingress) sockets are unaffected. */
volatile const bool disable_egress_capture = true;

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
#define SOCKET_DATA_RINGBUF_SHARDS 8
#define SOCKET_DATA_RINGBUF_SHARD_SIZE (64 * 1024 * 1024)

static __always_inline void increment_counter(void *counter_map) {
    u32 key = 0;
    u64 *total = bpf_map_lookup_elem(counter_map, &key);
    if (total != NULL) {
        (*total) += 1;
    }
}

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
    /* Bytes of each direction not delivered since the last delivered chunk
     * of that direction (ring full, failed user read, chunk-limit cut,
     * ingest paused). Stamped on the next delivered chunk, then cleared. */
    u32 lost_read;
    u32 lost_write;
    /* The part of lost_* that fell in the current run of that direction
     * (a run ends when the socket's direction changes), and that direction:
     * 0 none yet, 1 read, 2 write. A chunk whose run lost nothing before it
     * is a safe point for userspace to resume framing. */
    u32 lost_run;
    u32 run_dir;
    /* Local address of the socket (skc_rcv_saddr, skc_num in host order),
     * stamped on every data record so userspace always knows both ends,
     * even when it never saw the open record. */
    u32 laddr;
    u32 lport;
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
    /* The pointers after flags differ by kernel: 5.3+ has file, sk, ops;
     * older kernels (RHEL 8's 4.18) have wq, file, sk. Stored as u64 to avoid
     * CO-RE on struct socket; sk is picked by checking sk->sk_socket. */
    __u64  p0;
    __u64  p1;
    __u64  p2;
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
    /* SSL_read_ex / SSL_write_ex: they return 1/0 and report the byte count
     * through this out-pointer (NULL for every other source). */
    size_t* ex_bytes;
    /* SSL_* calls: the SSL object, so a syscall made inside the call can bind
     * the real socket fd to it (see bind_pending_ssl_fd). */
    u64 ssl_ptr;
    /* SSL_*: get_fd layout code to read the fd again at return (0: none), and
     * whether a syscall inside the call used another fd than the SSL object's. */
    u32 ssl_ver;
    u32 other_fd; /* SSL_*: fd of a syscall inside the call that differs from fd */
};

struct close_args_t {
    u32 fd;
};

/*
 * Every record on a socket_data_events_N ring starts with the same conn id
 * prefix. `kind` sits in what used to be the alignment hole after fd, so the
 * offsets of all other fields are unchanged.
 */
enum event_kind_t {
    kEventData  = 0,
    kEventOpen  = 1,
    kEventClose = 2,
};

struct socket_open_event_t {
    u64 id;
    u32 fd;
    u32 kind;
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
    u32 kind;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    u64 socket_close_ns;
    /* Final per-direction chunk counters and undelivered bytes, so
     * userspace can tell whether the tail of the last message was lost. */
    u32 readEventsCount;
    u32 writeEventsCount;
    u32 lost_read;
    u32 lost_write;
};

struct socket_data_event_t {
    u64 id;
    u32 fd;
    u32 kind;
    u64 conn_start_ns;
    unsigned short port;
    u32 ip;
    int bytes_sent;
    u32 readEventsCount;
    u32 writeEventsCount;
    bool ssl;
    /* Bytes of this direction lost right before this chunk (see conn_info_t),
     * and how many of them belong to this chunk's own run. */
    u32 lost;
    u32 lost_run;
    /* Local address of the socket (see conn_info_t). */
    u32 laddr;
    u32 lport;
    char msg[MAX_MSG_SIZE];
};

/* ===================================================================
 * BPF maps — BTF-typed declarations replacing BCC macros
 * =================================================================== */

/*
 * LRU so entries whose close() we never saw (process exit, fd passed on)
 * age out on their own. This replaces a hand-rolled ring of keys whose
 * counter was bumped without atomics: two CPUs accepting at once got the
 * same slot, and the second deleted the connection the first had just
 * registered, so that connection was never captured.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, TRAFFIC_MAX_CONNECTION_MAP_SIZE);
    __type(key, u64);
    __type(value, struct conn_info_t);
} conn_info_map SEC(".maps");

/* Total socket_data bpf_ringbuf_output calls (userspace reads for windowed logs). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket_data_submit_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket_data_submit_failed_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket_open_submit_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket_open_submit_failed_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket_close_submit_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket_close_submit_failed_total SEC(".maps");

/* TLS calls whose plaintext could not be put on a connection: no fd from the
 * SSL object nor from a syscall inside the call, or the two disagreed. Each
 * becomes a hole of unknown size (see ssl_hole_map), never a silent gap. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} ssl_fd_resolve_failed_total SEC(".maps");

/* Returns never observed, noticed at the thread's next call (syscall / TLS). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} missed_syscall_return_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} missed_ssl_return_total SEC(".maps");

/*
 * (process, SSL object) -> directions owing a hole: a TLS call of this session
 * moved plaintext that could not be put on a connection. The session's next
 * call in that direction marks the hole on its connection before its own
 * bytes. An SSL object is used by one thread at a time, so that is exactly
 * where the missing bytes sat in that direction's stream.
 */
struct ssl_hole_key_t {
    u64 ssl;
    u32 tgid;
    u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ssl_hole_key_t);
    __type(value, u32); /* bit 0: read, bit 1: write */
} ssl_hole_map SEC(".maps");

/* fd value meaning "could not be determined" (never 0: 0 is a real fd). */
#define SSL_FD_UNKNOWN 0xFFFFFFFFu

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_5 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_DATA_RINGBUF_SHARD_SIZE);
} socket_data_events_7 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8);
} system_cpu_ingest_paused SEC(".maps");

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

static __always_inline bool is_system_cpu_ingest_paused(void) {
    u32 key = 0;
    u8 *paused = bpf_map_lookup_elem(&system_cpu_ingest_paused, &key);
    return paused != NULL && *paused != 0;
}

/*
 * Ringbuf submit size for struct socket_data_event_t: header + valid bytes in msg[].
 * Keep bounds explicit for strict verifiers (RHEL 8 / 4.18): bpf_ringbuf_output R3
 * must not depend on un-clamped arithmetic from syscall return values.
 */
static __always_inline u32 socket_data_event_output_len(u32 msg_len) {
    const u32 hdr_sz = (u32)(sizeof(struct socket_data_event_t) - MAX_MSG_SIZE);
    u32 pl = msg_len;
    if (pl > MAX_MSG_SIZE) {
        pl = MAX_MSG_SIZE;
    }
    u32 out = hdr_sz + pl;
    const u32 cap = (u32)sizeof(struct socket_data_event_t);
    if (out > cap) {
        out = cap;
    }
    return out;
}

/*
 * All records of one connection (open, data, close) go to the same shard, so
 * the shard's single userspace reader sees them in syscall order. Sharding by
 * CPU would split a connection across readers and lose that order.
 */
static __always_inline u32 conn_shard(u64 tgid_fd) {
    return (u32)((tgid_fd * 0x9E3779B97F4A7C15ULL) >> 61) & (SOCKET_DATA_RINGBUF_SHARDS - 1);
}

static __noinline long output_to_data_shard(void *data, u64 size, u64 tgid_fd) {
    /*
     * bpf_ringbuf_output size (R3) must be provably bounded on older verifiers
     * (e.g. RHEL 8 / 4.18): "R3 unbounded memory access, use 'if (var < const)'".
     * This is the only variable-size bpf_ringbuf_output path in this module;
     * bpf_ringbuf_reserve paths use a fixed sizeof(...) only.
     */
    const __u32 max_bytes = sizeof(struct socket_data_event_t);
    __u32 nbytes;
    if (size > max_bytes) {
        nbytes = max_bytes;
    } else {
        nbytes = (__u32)size;
    }

    u32 shard = conn_shard(tgid_fd);
    switch (shard) {
    case 0: return bpf_ringbuf_output(&socket_data_events_0, data, nbytes, 0);
    case 1: return bpf_ringbuf_output(&socket_data_events_1, data, nbytes, 0);
    case 2: return bpf_ringbuf_output(&socket_data_events_2, data, nbytes, 0);
    case 3: return bpf_ringbuf_output(&socket_data_events_3, data, nbytes, 0);
    case 4: return bpf_ringbuf_output(&socket_data_events_4, data, nbytes, 0);
    case 5: return bpf_ringbuf_output(&socket_data_events_5, data, nbytes, 0);
    case 6: return bpf_ringbuf_output(&socket_data_events_6, data, nbytes, 0);
    case 7: return bpf_ringbuf_output(&socket_data_events_7, data, nbytes, 0);
    default: return bpf_ringbuf_output(&socket_data_events_0, data, nbytes, 0);
    }
}

static __always_inline u64 gen_tgid_fd(u32 tgid, int fd) {
  return ((u64)tgid << 32) | (u32)fd;
}

/*
 * Missed returns. A call's return can go unseen: a kretprobe runs out of
 * return instances (kernel default maxactive is the CPU count on RHEL 8;
 * userspace raises it, see KRETPROBE_MAXACTIVE), or the call started between
 * the attach of its entry and its return probe (userspace attaches returns
 * first). The call's entry args then stay in its active_*_args map, and the
 * data it moved is neither delivered nor counted: userspace would splice the
 * bytes around it, or mistake the next request for pipelining.
 *
 * A thread can't start a new call of the same kind while one is in flight, so
 * an entry still present when the next one starts is a missed return. Count
 * one chunk on that connection and flag the hole as LOST_UNKNOWN (its size is
 * unknown): userspace then never counts it into a body and resyncs at the next
 * clean message start.
 */
#define LOST_UNKNOWN 0x80000000u

/* A hole of unknown size in one direction of (tgid, fd), at this point. */
static __always_inline void mark_unknown_hole(u32 tgid, u32 fd, bool is_send, bool ssl) {
    u64 tgid_fd = gen_tgid_fd(tgid, fd);
    struct conn_info_t* c = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (c == NULL || c->ssl != ssl) {
        return;
    }
    u32 run_dir = is_send ? 2u : 1u;
    if (c->run_dir != run_dir) {
        c->run_dir = run_dir;
        c->lost_run = 0;
    }
    if (is_send) {
        c->writeEventsCount += 1u;
        c->lost_write |= LOST_UNKNOWN;
    } else {
        c->readEventsCount += 1u;
        c->lost_read |= LOST_UNKNOWN;
    }
    c->lost_run |= LOST_UNKNOWN;
}

static __always_inline void account_missed_return(u64 id, const struct data_args_t* args,
                                                  bool is_send, bool ssl) {
    if (ssl) {
        increment_counter(&missed_ssl_return_total);
    } else {
        increment_counter(&missed_syscall_return_total);
    }
    mark_unknown_hole(id >> 32, args->fd, is_send, ssl);
}

/* Defined with the SSL probes below; syscall entries call them. */
static void set_conn_as_ssl(u32 tgid, u32 fd);
static __always_inline void bind_pending_ssl_fd(u64 id, u32 fd, bool is_send);

/* Called at every syscall data entry: syscalls don't nest on one thread. */
static __always_inline void note_missed_syscall_returns(u64 id) {
    struct data_args_t* a = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (a != NULL) {
        account_missed_return(id, a, false, false);
        bpf_map_delete_elem(&active_read_args_map, &id);
    }
    a = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (a != NULL) {
        account_missed_return(id, a, true, false);
        bpf_map_delete_elem(&active_write_args_map, &id);
    }
}

/* Called at every SSL data entry: no syscall or SSL call is in flight on this
 * thread when the application calls into SSL_read/SSL_write. */
static __always_inline void note_missed_returns_at_ssl_entry(u64 id) {
    note_missed_syscall_returns(id);
    struct data_args_t* a = bpf_map_lookup_elem(&active_ssl_read_args_map, &id);
    if (a != NULL) {
        account_missed_return(id, a, false, true);
        bpf_map_delete_elem(&active_ssl_read_args_map, &id);
    }
    a = bpf_map_lookup_elem(&active_ssl_write_args_map, &id);
    if (a != NULL) {
        account_missed_return(id, a, true, true);
        bpf_map_delete_elem(&active_ssl_write_args_map, &id);
    }
}

static __always_inline void process_syscall_accept(struct pt_regs* ctx,
                                             const struct accept_args_t* args_in,
                                             u64 id, bool isConnect) {
    if (args_in == NULL) {
        return;
    }

    if (isConnect && disable_egress_capture) {
        return;
    }

    struct accept_args_t args = *args_in;

    int ret_fd = PT_REGS_RC(ctx);

    if (!isConnect && ret_fd < 0) {
        return;
    }

    struct conn_info_t conn_info = {};
    bool socketConn = false;

    u32 srcIp = 0;
    uint16_t lport = 0;

    if (args.addr != NULL) {
        if (print_bpf_logs) {
            bpf_printk("sock addr found, processing");
        }
    }

    /*
     * sock_alloc_socket path: only set socketConn after we fully populate from sk.
     * On bpf_probe_read_kernel failure, sk NULL, or non-INET family, do not return —
     * otherwise conn_info_map is never updated and recvfrom/writev see conn_info_map
     * misses (trace: "sock alloc found, processing" without ipv4/processed lines).
     * Fall through to user sockaddr or ip/port=0 registration like accept(NULL).
     */
    if (args.sock_alloc_socket != NULL) {
        if (print_bpf_logs) {
            bpf_printk("sock alloc found, processing");
        }

        /*
         * Read struct sock* from struct socket without CO-RE.
         * BPF_CORE_READ on struct socket::sk fails with 0xbad2310 on this
         * kernel even though bpf_core_field_exists() says the field exists —
         * the two relocation types use different BTF resolution paths (cilium/ebpf#1031).
         * akto_socket mirrors the stable first-field layout; no CO-RE is generated.
         */
        struct akto_socket sock_hdr = {};
        if (bpf_probe_read_kernel(&sock_hdr, sizeof(sock_hdr),
                                  args.sock_alloc_socket) == 0) {
            /* The real sk points back to this socket (sk->sk_socket). */
            struct sock* sk = (struct sock *)(unsigned long)sock_hdr.p1;
            if (sk == NULL || BPF_CORE_READ(sk, sk_socket) != args.sock_alloc_socket) {
                sk = (struct sock *)(unsigned long)sock_hdr.p2;
                if (sk != NULL && BPF_CORE_READ(sk, sk_socket) != args.sock_alloc_socket) {
                    sk = NULL;
                }
            }

            if (sk != NULL) {
                uint16_t family = BPF_CORE_READ(sk, __sk_common.skc_family);

                if (family == AF_INET) {
                    if (print_bpf_logs) {
                        bpf_printk("sock alloc found ipv4, processing");
                    }
                    conn_info.port  = BPF_CORE_READ(sk, __sk_common.skc_dport);
                    lport           = BPF_CORE_READ(sk, __sk_common.skc_num);
                    conn_info.ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
                    srcIp        = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
                    socketConn = true;
                } else if (family == AF_INET6) {
                    if (print_bpf_logs) {
                        bpf_printk("sock alloc found ipv6, processing");
                    }
                    conn_info.port  = BPF_CORE_READ(sk, __sk_common.skc_dport);
                    lport           = BPF_CORE_READ(sk, __sk_common.skc_num);
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
                    socketConn = true;
                } else if (print_bpf_logs) {
                    bpf_printk("sock alloc skip non-inet family: %d", family);
                }
            } else if (print_bpf_logs) {
                bpf_printk("sock alloc sk NULL after hdr read");
            }
        } else if (print_bpf_logs) {
            bpf_printk("sock alloc bpf_probe_read_kernel(socket hdr) failed");
        }

        if (socketConn && print_bpf_logs) {
            bpf_printk("sock alloc found, processed: id: %llu ip: %llu port: %d",
                             id, conn_info.ip, conn_info.port);
            bpf_printk("sock alloc found, processed: id: %llu srcIp: %llu srcPort: %d",
                             id, srcIp, lport);
        }
    }

    if (!socketConn) {
        if (args.addr != NULL) {
            struct akto_sockaddr sa_hdr = {};
            if (bpf_probe_read_user(&sa_hdr, sizeof(sa_hdr), args.addr) != 0) {
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
        conn_info.fd = args.fd;
    } else {
        conn_info.fd = ret_fd;
    }
    conn_info.conn_start_ns = bpf_ktime_get_ns();

    if (!socketConn && args.addr != NULL) {
        struct akto_sockaddr sa_hdr = {};
        bpf_probe_read_user(&sa_hdr, sizeof(sa_hdr), args.addr);
        if (sa_hdr.sa_family == AF_INET) {
            struct akto_sockaddr_in sin = {};
            if (bpf_probe_read_user(&sin, sizeof(sin), args.addr) == 0) {
                conn_info.port = sin.sin_port;
                conn_info.ip   = sin.sin_addr;
            }
        } else {
            struct akto_sockaddr_in6 sin6 = {};
            if (bpf_probe_read_user(&sin6, sizeof(sin6), args.addr) == 0) {
                conn_info.port = sin6.sin6_port;
                conn_info.ip   = ((__u32 *)sin6.sin6_addr)[3];
            }
        }
    }

    conn_info.ssl = false;
    conn_info.readEventsCount = 0;
    conn_info.writeEventsCount = 0;
    conn_info.laddr = srcIp;
    conn_info.lport = lport;

    if (filter_local_traffic && conn_info.ip == local_traffic_ip) {
        if (print_bpf_logs) {
            bpf_printk("Dropping local traffic ip:%u fd:%d", conn_info.ip, args.fd);
        }
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = 0;
    if (isConnect) {
        tgid_fd = gen_tgid_fd(tgid, args.fd);
    } else {
        tgid_fd = gen_tgid_fd(tgid, ret_fd);
    }

    bpf_map_update_elem(&conn_info_map, &tgid_fd, &conn_info, BPF_ANY);

    if (!disable_ring_submit) {
        struct socket_open_event_t socket_open_event = {};
        socket_open_event.id             = conn_info.id;
        socket_open_event.fd             = conn_info.fd;
        socket_open_event.kind           = kEventOpen;
        socket_open_event.conn_start_ns  = conn_info.conn_start_ns;
        socket_open_event.port           = conn_info.port;
        socket_open_event.ip             = conn_info.ip;
        socket_open_event.src_ip         = srcIp;
        socket_open_event.src_port       = lport;
        socket_open_event.socket_open_ns = conn_info.conn_start_ns;

        if (print_bpf_logs) {
            bpf_printk("accept call: %llu %d %d",
                             socket_open_event.id, socket_open_event.fd, isConnect);
            bpf_printk("accept call 2: %llu %d %d",
                             socket_open_event.ip, socket_open_event.port, isConnect);
        }

        increment_counter(&socket_open_submit_total);
        if (output_to_data_shard(&socket_open_event, sizeof(socket_open_event), tgid_fd) != 0) {
            increment_counter(&socket_open_submit_failed_total);
        }
    }
}

static __always_inline void process_syscall_close(struct pt_regs* ctx,
                                            const struct close_args_t* args_in,
                                            u64 id) {
    if (args_in == NULL) {
        return;
    }
    struct close_args_t args = *args_in;

    int ret_val = PT_REGS_RC(ctx);

    if (ret_val < 0) {
        return;
    }

    if (args.fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args.fd);
    struct conn_info_t* conn_info_p = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info_p == NULL) {
        return;
    }
    struct conn_info_t conn_info = *conn_info_p;

    if (!disable_ring_submit) {
        struct socket_close_event_t socket_close_event = {};
        socket_close_event.id               = conn_info.id;
        socket_close_event.fd               = conn_info.fd;
        socket_close_event.kind             = kEventClose;
        socket_close_event.conn_start_ns    = conn_info.conn_start_ns;
        socket_close_event.port             = conn_info.port;
        socket_close_event.ip               = conn_info.ip;
        socket_close_event.socket_close_ns  = bpf_ktime_get_ns();
        socket_close_event.readEventsCount  = conn_info.readEventsCount;
        socket_close_event.writeEventsCount = conn_info.writeEventsCount;
        socket_close_event.lost_read        = conn_info.lost_read;
        socket_close_event.lost_write       = conn_info.lost_write;
        increment_counter(&socket_close_submit_total);
        if (output_to_data_shard(&socket_close_event, sizeof(socket_close_event), tgid_fd) != 0) {
            increment_counter(&socket_close_submit_failed_total);
        }
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

static __noinline void process_syscall_data(struct pt_regs* ctx,
                                           const struct data_args_t* args_in,
                                           u64 id, bool is_send, bool ssl) {
    if (args_in == NULL) {
        return;
    }
    struct data_args_t args = *args_in;

    int bytes_exchanged = PT_REGS_RC(ctx);

    if (args.iovlen > 0 && args.buf_size > 0) {
        bytes_exchanged = args.buf_size;
    }
    if (args.ex_bytes != NULL) {
        if (PT_REGS_RC(ctx) != 1) {
            return;
        }
        size_t n = 0;
        if (bpf_probe_read_user(&n, sizeof(n), args.ex_bytes) != 0 || n > 0x7fffffff) {
            return;
        }
        bytes_exchanged = (int)n;
    }

    if (bytes_exchanged <= 0) {
        return;
    }

    if (print_bpf_logs) {
        bpf_printk("SSL data 1 %d", id);
    }
    if (args.fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args.fd);
    if (print_bpf_logs) {
        bpf_printk("SSL data 2 %d %llu %lu", id, tgid_fd, tgid);
    }
    struct conn_info_t* conn_info_p = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info_p == NULL) {
        return;
    }
    struct conn_info_t conn_info = *conn_info_p;

    if (print_bpf_logs) {
        bpf_printk("SSL data 3 %d %llu %lu", id, tgid_fd, tgid);
    }

    if (conn_info.ssl != ssl) {
        return;
    }

    if (filter_strict_remote_port && conn_info.port != strict_remote_port) {
        return;
    }

    if (disable_ring_submit) {
        return;
    }

    /*
     * Counters are updated in place (not by writing back the conn_info copy),
     * so a concurrent reader and writer on one socket can't undo each other's
     * increments, and a concurrent set_conn_as_ssl isn't reverted.
     *
     * Every byte this syscall would have delivered but didn't is added to the
     * direction's lost counter, and the next delivered chunk carries it.
     * Userspace frames HTTP/1 messages by byte count, so it must know exactly
     * how many bytes are missing and where; otherwise the bytes on either side
     * would be spliced together.
     */
    u32 *lost_p = is_send ? &conn_info_p->lost_write : &conn_info_p->lost_read;
    u32 *lost_run_p = &conn_info_p->lost_run;
    u32 run_dir = is_send ? 2u : 1u;
    if (conn_info_p->run_dir != run_dir) {
        conn_info_p->run_dir = run_dir;
        *lost_run_p = 0;
    }
    if (is_system_cpu_ingest_paused()) {
        if (is_send) {
            conn_info_p->writeEventsCount += 1u;
        } else {
            conn_info_p->readEventsCount += 1u;
        }
        *lost_p += (u32)bytes_exchanged;
        *lost_run_p += (u32)bytes_exchanged;
        return;
    }

    if (print_bpf_logs) {
        bpf_printk("SSL data 4 %llu %llu %d", id, tgid_fd, ssl);
    }

    int bytes_sent  = 0;
    u32  size_to_save = 0;
    int i = 0;
#pragma unroll
    for (i = 0; i < CHUNK_LIMIT; ++i) {
        const int bytes_remaining = bytes_exchanged - bytes_sent;

        if (bytes_remaining <= 0) {
            break;
        }

        u32 kZero = 0;
        struct socket_data_event_t* socket_data_event =
            bpf_map_lookup_elem(&socket_data_event_buffer_heap, &kZero);
        if (socket_data_event == NULL) {
            break;
        }

        socket_data_event->id            = conn_info.id;
        socket_data_event->fd            = conn_info.fd;
        socket_data_event->kind          = kEventData;
        socket_data_event->conn_start_ns = conn_info.conn_start_ns;
        socket_data_event->port          = conn_info.port;
        socket_data_event->ip            = conn_info.ip;
        socket_data_event->ssl           = conn_info.ssl;

        u32 current_size;
        if (bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1)) {
            current_size = (u32)MAX_MSG_SIZE;
        } else {
            current_size = (u32)bytes_remaining;
        }

        u32 read_size = bounded_probe_read_user(
            socket_data_event, current_size,
            (const char *)args.buf + bytes_sent);

        if (is_send) {
            conn_info_p->writeEventsCount += 1u;
        } else {
            conn_info_p->readEventsCount += 1u;
        }
        if (read_size == 0 && current_size > 0) {
            *lost_p += (u32)bytes_remaining;
            *lost_run_p += (u32)bytes_remaining;
            break;
        }
        size_to_save = read_size;
        socket_data_event->lost = *lost_p;
        socket_data_event->lost_run = *lost_run_p;
        socket_data_event->laddr = conn_info.laddr;
        socket_data_event->lport = conn_info.lport;

        socket_data_event->writeEventsCount = conn_info_p->writeEventsCount;
        socket_data_event->readEventsCount  = conn_info_p->readEventsCount;

        if (print_bpf_logs) {
            bpf_printk("pid: %d conn-id:%d, fd: %d",
                             id, conn_info.id, conn_info.fd);
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
            increment_counter(&socket_data_submit_total);
        }
        long ret = output_to_data_shard(socket_data_event,
                                        socket_data_event_output_len(size_to_save),
                                        tgid_fd);
        if (ret != 0) {
            *lost_p += read_size;
            *lost_run_p += read_size;
            if (log_socket_data_submit_stats) {
                increment_counter(&socket_data_submit_failed_total);
            }
        } else {
            *lost_p = 0;
            *lost_run_p = 0;
        }
        /* Last chunk of an oversized syscall: only MAX_MSG_SIZE was copied. */
        if (current_size > read_size) {
            *lost_p += current_size - read_size;
            *lost_run_p += current_size - read_size;
        }

        bytes_sent += current_size;
    }

}

/*
 * Bytes a tracked socket sent without passing through user memory (sendfile:
 * the kernel copies file pages straight to the socket). They can't be
 * captured, but they are counted as lost so userspace keeps exact byte
 * positions in the stream: the message they belong to is cut at that point
 * instead of absorbing the next message's bytes.
 */
static __always_inline void account_uncaptured(u64 id, u32 fd, bool is_send, u32 n) {
    if (n == 0) {
        return;
    }
    u64 tgid_fd = gen_tgid_fd(id >> 32, fd);
    struct conn_info_t* conn_info_p = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info_p == NULL || conn_info_p->ssl) {
        return; /* a TLS connection's stream is the plaintext, not these bytes */
    }
    u32 run_dir = is_send ? 2u : 1u;
    if (conn_info_p->run_dir != run_dir) {
        conn_info_p->run_dir = run_dir;
        conn_info_p->lost_run = 0;
    }
    if (is_send) {
        conn_info_p->writeEventsCount += 1u;
        conn_info_p->lost_write += n;
    } else {
        conn_info_p->readEventsCount += 1u;
        conn_info_p->lost_read += n;
    }
    conn_info_p->lost_run += n;
}

static __noinline void account_unreadable(struct pt_regs* ctx,
                                          const struct data_args_t* args_in,
                                          u64 id, bool is_send) {
    if (args_in == NULL) {
        return;
    }
    int n = PT_REGS_RC(ctx);
    if (n <= 0) {
        return;
    }
    account_uncaptured(id, args_in->fd, is_send, (u32)n);
}

static __noinline void process_syscall_data_vecs(struct pt_regs* ctx,
                                                struct data_args_t* args_in,
                                                u64 id, bool is_send) {
    if (args_in == NULL) {
        return;
    }
    struct data_args_t args = *args_in;

    int bytes_sent  = 0;
    int total_size  = PT_REGS_RC(ctx);
    const struct iovec* iov = args.iov;
    if (total_size <= 0) {
        return;
    }
    for (int i = 0; i < LOOP_LIMIT && i < args.iovlen && bytes_sent < total_size; ++i) {
        struct iovec iov_cpy = {};
        if (bpf_probe_read_user(&iov_cpy, sizeof(iov_cpy), &iov[i]) != 0) {
            break;
        }
        const int bytes_remaining = total_size - bytes_sent;
        const size_t iov_size = iov_cpy.iov_len < bytes_remaining
                                ? iov_cpy.iov_len : bytes_remaining;
        if (iov_size == 0) {
            continue; /* size 0 would mean "whole syscall" below */
        }

        args.buf      = iov_cpy.iov_base;
        args.buf_size = iov_size;
        process_syscall_data(ctx, &args, id, is_send, false);
        bytes_sent += iov_size;
    }
    /* More vectors than the loop covers, or an unreadable iovec: the rest of
     * the bytes still moved on the socket and must be counted as a hole. */
    if (bytes_sent < total_size) {
        account_uncaptured(id, args.fd, is_send, (u32)(total_size - bytes_sent));
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

    struct accept_args_t* accept_args_p = bpf_map_lookup_elem(&active_accept_args_map, &id);

    if (accept_args_p != NULL) {
        struct accept_args_t accept_args = *accept_args_p;
        process_syscall_accept(ctx, &accept_args, id, false);
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

    struct accept_args_t* accept_args_p = bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (accept_args_p == NULL) {
        return 0;
    }
    struct accept_args_t accept_args = *accept_args_p;

    if (accept_args.sock_alloc_socket == NULL) {
        accept_args.sock_alloc_socket = (struct socket*)PT_REGS_RC(ctx);
        bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);
    }

    return 0;
}

SEC("kprobe")
int probe_entry_tcp_connect(struct pt_regs* ctx) {
    if (disable_egress_capture) {
        return 0;
    }

    uint64_t id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tcp_connect: pid: %d", id);
    }

    struct accept_args_t* accept_args_p = bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (accept_args_p == NULL) {
        return 0;
    }
    struct accept_args_t accept_args = *accept_args_p;

    if (accept_args.sock == NULL) {
        accept_args.sock = (void*)PT_REGS_PARM1(ctx);
        bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);
    }

    return 0;
}

SEC("kprobe")
int syscall__probe_entry_connect(struct pt_regs* ctx) {
    if (disable_egress_capture) {
        return 0;
    }

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

    if (disable_egress_capture) {
        // sock_alloc may have inserted an entry for this thread; drop it so
        // a later accept() on the same thread does not inherit it.
        bpf_map_delete_elem(&active_accept_args_map, &id);
        return 0;
    }

    if (print_bpf_logs) {
        bpf_printk("syscall__probe_ret_connect: pid: %d", id);
    }

    struct accept_args_t* accept_args_p = bpf_map_lookup_elem(&active_accept_args_map, &id);

    if (accept_args_p != NULL) {
        struct accept_args_t accept_args = *accept_args_p;
        if (accept_args.sock != NULL) {
            struct sock* sock = accept_args.sock;
            accept_args.sock_alloc_socket = BPF_CORE_READ(sock, sk_socket);
        }
        process_syscall_accept(ctx, &accept_args, id, true);
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

    bind_pending_ssl_fd(id, write_args.fd, true);

    note_missed_syscall_returns(id);

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
        bind_pending_ssl_fd(id, write_args.fd, true);
        note_missed_syscall_returns(id);
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

    bind_pending_ssl_fd(id, read_args.fd, false);

    note_missed_syscall_returns(id);

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

/* sendfile(out_fd, in_fd, offset, count): see account_unreadable. */
SEC("kprobe")
int syscall__probe_entry_sendfile(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct data_args_t args = {};
    args.fd        = (int)SYSCALL_PARM1(ctx);
    args.source_fn = kSyscallSendfile;
    bind_pending_ssl_fd(id, args.fd, true);
    note_missed_syscall_returns(id);
    bpf_map_update_elem(&active_write_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("kprobe")
int syscall__probe_ret_sendfile(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct data_args_t* args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (args != NULL && args->source_fn == kSyscallSendfile) {
        account_unreadable(ctx, args, id, true);
    }
    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

/* Same, for the egress hook set, which swaps the read and write directions. */
SEC("kprobe")
int syscall__probe_ret_sendfile_swapped(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct data_args_t* args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (args != NULL && args->source_fn == kSyscallSendfile) {
        account_unreadable(ctx, args, id, false);
    }
    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

SEC("kprobe")
int syscall__probe_entry_recvfrom(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    int fd     = (int)SYSCALL_PARM1(ctx);
    char* buf  = (char*)SYSCALL_PARM2(ctx);
    /* A peek is followed by a real read of the same bytes; capturing both
     * would duplicate them inside one message. */
    if (((int)SYSCALL_PARM4(ctx)) & MSG_PEEK) {
        return 0;
    }

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
    bind_pending_ssl_fd(id, read_args.fd, false);
    note_missed_syscall_returns(id);
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
    bind_pending_ssl_fd(id, write_args.fd, true);
    note_missed_syscall_returns(id);
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
    if (((int)SYSCALL_PARM4(ctx)) & MSG_PEEK) {
        return 0;
    }

    struct data_args_t read_args = {};
    read_args.buf       = buf;
    read_args.fd        = fd;
    read_args.source_fn = kSyscallRecv;
    bind_pending_ssl_fd(id, read_args.fd, false);
    note_missed_syscall_returns(id);
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

    bind_pending_ssl_fd(id, read_args.fd, false);

    note_missed_syscall_returns(id);

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
    if (((int)SYSCALL_PARM3(ctx)) & MSG_PEEK) {
        return 0;
    }

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
        bind_pending_ssl_fd(id, read_args.fd, false);
        note_missed_syscall_returns(id);
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
    bind_pending_ssl_fd(id, write_args.fd, true);
    note_missed_syscall_returns(id);
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

    bind_pending_ssl_fd(id, write_args.fd, true);

    note_missed_syscall_returns(id);

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

    /* These are reads of the process's memory and can fail (page not present,
     * e.g. during NUMA rebalancing). A failure must not read as fd 0. */
    const void* rbio_ptr = NULL;
    if (bpf_probe_read_user(&rbio_ptr, sizeof(rbio_ptr), ssl + SSL_rbio_offset) != 0 || rbio_ptr == NULL) {
        return SSL_FD_UNKNOWN;
    }
    u32 rbio_num = SSL_FD_UNKNOWN;
    if (bpf_probe_read_user(&rbio_num, sizeof(rbio_num), rbio_ptr + RBIO_num_offset) != 0) {
        return SSL_FD_UNKNOWN;
    }

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
    /*
     * Handshake ciphertext is already counted on this fd. Userspace drops
     * those bytes when the connection flips to TLS, and it only parses a
     * chunk sequence that starts at 1. Start the plaintext sequence over.
     */
    if (!conn_info->ssl) {
        conn_info->readEventsCount = 0;
        conn_info->writeEventsCount = 0;
        conn_info->lost_read = 0;
        conn_info->lost_write = 0;
        conn_info->lost_run = 0;
        conn_info->run_dir = 0;
    }
    conn_info->ssl = true;
    if (print_bpf_logs) {
        bpf_printk("SSL marking ssl tgid: %d", tgid_fd);
    }
}

/*
 * probe_entry_SSL_write_core — shared inner handler for all SSL write entry probes.
 * With BPF_UPROBE, buf is already extracted from pt_regs by the macro; we pass it directly.
 */
/*
 * Which socket a TLS call uses. Only exact sources, nothing remembered across
 * calls (a remembered fd goes stale when a close is missed, and then puts one
 * connection's plaintext on another):
 *   - the fd in the SSL object's BIO, read at entry, or again at return when
 *     the entry read failed (page not present; the library has just used it);
 *   - the fd of a socket syscall the library makes inside the call.
 * When neither is known, or they disagree, the plaintext is not delivered but
 * becomes a hole of unknown size (process_ssl_return): a guessed fd could put
 * one session's bytes on another connection, and a silent gap could splice
 * the bytes around it.
 */
static __always_inline void bind_pending_ssl_fd(u64 id, u32 fd, bool is_send) {
    struct data_args_t* a = is_send ? bpf_map_lookup_elem(&active_ssl_write_args_map, &id)
                                    : bpf_map_lookup_elem(&active_ssl_read_args_map, &id);
    if (a == NULL) {
        return;
    }
    if (a->fd == SSL_FD_UNKNOWN) {
        a->fd = fd;
        set_conn_as_ssl(id >> 32, fd);
        return;
    }
    if (a->fd != fd) {
        a->other_fd = fd;
    }
}

/* SSL_read / SSL_write return: emit the plaintext on the call's socket. */
static __always_inline void process_ssl_return(struct pt_regs* ctx, u64 id, bool is_send) {
    struct data_args_t* a = is_send ? bpf_map_lookup_elem(&active_ssl_write_args_map, &id)
                                    : bpf_map_lookup_elem(&active_ssl_read_args_map, &id);
    if (a == NULL) {
        return;
    }
    struct data_args_t args = *a;
    if (args.fd == SSL_FD_UNKNOWN && args.ssl_ver != 0) {
        args.fd = get_fd((void*)args.ssl_ptr, (int)args.ssl_ver, !is_send);
        if (args.fd != SSL_FD_UNKNOWN) {
            set_conn_as_ssl(id >> 32, args.fd);
        }
    }
    u32 tgid = id >> 32;
    u32 bit = is_send ? 2u : 1u;
    struct ssl_hole_key_t key = {};
    key.ssl  = args.ssl_ptr;
    key.tgid = tgid;
    if (args.fd == SSL_FD_UNKNOWN || args.other_fd != SSL_FD_UNKNOWN) {
        if ((long)PT_REGS_RC(ctx) <= 0) {
            return; /* nothing moved */
        }
        increment_counter(&ssl_fd_resolve_failed_total);
        if (args.fd == SSL_FD_UNKNOWN) {
            /* No connection to name now: the session owes a hole. */
            u32 owed = bit;
            u32* cur = bpf_map_lookup_elem(&ssl_hole_map, &key);
            if (cur != NULL) {
                owed |= *cur;
            }
            bpf_map_update_elem(&ssl_hole_map, &key, &owed, BPF_ANY);
        } else {
            /* Two candidates: the hole goes on both. */
            mark_unknown_hole(tgid, args.fd, is_send, true);
            mark_unknown_hole(tgid, args.other_fd, is_send, true);
        }
        return;
    }
    u32* owed = bpf_map_lookup_elem(&ssl_hole_map, &key);
    if (owed != NULL && (*owed & bit)) {
        mark_unknown_hole(tgid, args.fd, is_send, true);
        u32 rest = *owed & ~bit;
        if (rest == 0) {
            bpf_map_delete_elem(&ssl_hole_map, &key);
        } else {
            bpf_map_update_elem(&ssl_hole_map, &key, &rest, BPF_ANY);
        }
    }
    process_syscall_data(ctx, &args, id, is_send, true);
}

static void probe_entry_SSL_write_core(struct pt_regs* ctx, void* ssl, void* buf,
                                        int num, u32 fd, size_t* ex_bytes, int ver) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_core: pid: %d %d %d", id, tgid, fd);
    }

    char* bufc = (char*)buf;

    struct data_args_t write_args = {};
    write_args.fd  = fd;
    write_args.ssl_ptr = (u64)ssl;
    write_args.ssl_ver = (u32)ver;
    write_args.other_fd = SSL_FD_UNKNOWN;
    write_args.buf = bufc;
    write_args.ex_bytes = ex_bytes;
    note_missed_returns_at_ssl_entry(id);
    bpf_map_update_elem(&active_ssl_write_args_map, &id, &write_args, BPF_ANY);

    if (fd != SSL_FD_UNKNOWN) {
        set_conn_as_ssl(tgid, fd);
    }
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_1_0, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 1, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_1_0: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd, NULL, 1);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_1_1, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 2, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_1_1: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd, NULL, 2);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_3_0, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 3, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_3_0: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd, NULL, 3);
    return 0;
}

/* Node-OpenSSL only: FD resolved via the TLS-wrap map. */
/* Node.js: the socket fd is reached through the TLSWrap object, not SSL->rbio. */
static __always_inline u32 node_ssl_fd(void* ssl, u32 tgid) {
    __u64 ssl_key = (__u64)ssl;
    __u64* tls_wrap_val = bpf_map_lookup_elem(&node_ssl_tls_wrap_map, &ssl_key);
    u32 fd = SSL_FD_UNKNOWN;
    if (tls_wrap_val != NULL) {
        __u64 tls_wrap_word = *tls_wrap_val;
        u32 tgid_key = tgid;
        struct node_tlswrap_symaddrs_t* symaddrs_p =
            bpf_map_lookup_elem(&node_tlswrap_symaddrs_map, &tgid_key);
        if (symaddrs_p != NULL) {
            struct node_tlswrap_symaddrs_t symaddrs = *symaddrs_p;
            void* tls_wrap = (void*)tls_wrap_word;
            void* stream_ptr = tls_wrap + symaddrs.TLSWrapStreamListenerOffset
                               + symaddrs.StreamListenerStreamOffset;
            void* stream = NULL;
            bpf_probe_read(&stream, sizeof(stream), stream_ptr);
            if (stream != NULL) {
                void* uv_stream_ptr = stream
                                      - symaddrs.StreamBaseStreamResourceOffset
                                      - symaddrs.LibuvStreamWrapStreamBaseOffset
                                      + symaddrs.LibuvStreamWrapStreamOffset;
                void* uv_stream = NULL;
                bpf_probe_read(&uv_stream, sizeof(uv_stream), uv_stream_ptr);
                if (uv_stream != NULL) {
                    int32_t* fd_ptr = uv_stream + symaddrs.UVStreamSIOWatcherOffset
                                      + symaddrs.UVIOSFDOffset;
                    int32_t fd_val = 0;
                    if (bpf_probe_read(&fd_val, sizeof(fd_val), fd_ptr) == 0) {
                        fd = (u32)fd_val;
                    }
                }
            }
        }
    }
    return fd;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write, void* ssl, void* buf, int num) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    u32 fd = node_ssl_fd(ssl, tgid);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd, NULL, 0);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_boring, void* ssl, void* buf, int num) {
    u32 fd = get_fd(ssl, 4, false);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_write_boring: fd: %d", fd);
    }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd, NULL, 4);
    return 0;
}

SEC("uprobe")
int probe_ret_SSL_write(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_ret_SSL_write: pid: %d", id);
    }

    process_ssl_return(ctx, id, true);
    bpf_map_delete_elem(&active_ssl_write_args_map, &id);
    return 0;
}

static void probe_entry_SSL_read_core(struct pt_regs* ctx, void* ssl, void* buf,
                                        int num, u32 fd, size_t* ex_bytes, int ver) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_core: pid: %d %d %d", id, tgid, fd);
    }

    char* bufc = (char*)buf;

    struct data_args_t read_args = {};
    read_args.fd  = fd;
    read_args.ssl_ptr = (u64)ssl;
    read_args.ssl_ver = (u32)ver;
    read_args.other_fd = SSL_FD_UNKNOWN;
    read_args.buf = bufc;
    read_args.ex_bytes = ex_bytes;
    note_missed_returns_at_ssl_entry(id);
    bpf_map_update_elem(&active_ssl_read_args_map, &id, &read_args, BPF_ANY);

    if (fd != SSL_FD_UNKNOWN) {
        set_conn_as_ssl(tgid, fd);
    }
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_1_0, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 1, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_1_0: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd, NULL, 1);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_1_1, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 2, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_1_1: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd, NULL, 2);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_3_0, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 3, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_3_0: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd, NULL, 3);
    return 0;
}

/* Node-OpenSSL only. */
SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read, void* ssl, void* buf, int num) {
    u64 id   = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    u32 fd = node_ssl_fd(ssl, tgid);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd, NULL, 0);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_boring, void* ssl, void* buf, int num) {
    int32_t fd = get_fd(ssl, 4, true);
    if (print_bpf_logs) {
        bpf_printk("probe_entry_SSL_read_boring: fd: %d", fd);
    }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd, NULL, 4);
    return 0;
}


/* SSL_write_ex / SSL_read_ex (OpenSSL 3, Node): byte count via out-pointer. */
SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_ex_3_0, void* ssl, void* buf, size_t num, size_t* written) {
    probe_entry_SSL_write_core(ctx, ssl, buf, (int)num, get_fd(ssl, 3, false), written, 3);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_ex_3_0, void* ssl, void* buf, size_t num, size_t* readbytes) {
    probe_entry_SSL_read_core(ctx, ssl, buf, (int)num, get_fd(ssl, 3, true), readbytes, 3);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_write_ex, void* ssl, void* buf, size_t num, size_t* written) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    probe_entry_SSL_write_core(ctx, ssl, buf, (int)num, node_ssl_fd(ssl, tgid), written, 0);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(probe_entry_SSL_read_ex, void* ssl, void* buf, size_t num, size_t* readbytes) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    probe_entry_SSL_read_core(ctx, ssl, buf, (int)num, node_ssl_fd(ssl, tgid), readbytes, 0);
    return 0;
}

SEC("uprobe")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    if (print_bpf_logs) {
        bpf_printk("probe_ret_SSL_read: pid: %d", id);
    }

    process_ssl_return(ctx, id, false);
    bpf_map_delete_elem(&active_ssl_read_args_map, &id);
    return 0;
}

/* ===================================================================
 * Go TLS probes
 * =================================================================== */

/*
 * Snapshot Go register ABI args into caller stack memory only.
 * Do not stash pt_regs fields in a map: the next bpf_map_lookup_elem()
 * invalidates prior lookup pointers on older verifiers (e.g. RHEL 8 / 4.18),
 * which would poison symaddrs/active_tls reads used with assign_arg().
 *
 * Same rule elsewhere: copy `*map_ptr` to the stack (or re-lookup) before any
 * other bpf helper if you still need the map value; never use two live map-value
 * pointers across helpers; refresh per-CPU scratch after ringbuf_output / stats.
 */
static __always_inline void go_regabi_regs_fill(uint64_t regs_out[9], const struct pt_regs* ctx) {
#if defined(TARGET_ARCH_X86_64)
    regs_out[0] = ctx->ax;
    regs_out[1] = ctx->bx;
    regs_out[2] = ctx->cx;
    regs_out[3] = ctx->di;
    regs_out[4] = ctx->si;
    regs_out[5] = ctx->r8;
    regs_out[6] = ctx->r9;
    regs_out[7] = ctx->r10;
    regs_out[8] = ctx->r11;
#elif defined(TARGET_ARCH_AARCH64)
    regs_out[0] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[0]);
    regs_out[1] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[1]);
    regs_out[2] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[2]);
    regs_out[3] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[3]);
    regs_out[4] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[4]);
    regs_out[5] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[5]);
    regs_out[6] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[6]);
    regs_out[7] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[7]);
    regs_out[8] = BPF_CORE_READ((const struct user_pt_regs *)(const void *)ctx, regs[8]);
#else
#error Target Architecture not supported
#endif
}

static inline uint64_t get_goid(struct pt_regs* ctx) {
    uint64_t id   = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;
    struct go_symaddrs_t* common_symaddrs_p = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (common_symaddrs_p == NULL) {
        return 0;
    }
    struct go_symaddrs_t common_symaddrs = *common_symaddrs_p;

    /* CO-RE: resolve task_struct->thread field offsets from BTF. */
    struct task_struct* task_ptr = (struct task_struct*)bpf_get_current_task();
    if (!task_ptr) {
        return 0;
    }

#if defined(TARGET_ARCH_X86_64)
    const void* fs_base = (void*)BPF_CORE_READ(task_ptr, thread.fsbase);
#elif defined(TARGET_ARCH_AARCH64)
    /*
     * Go's TLS base matches TPIDR_EL0, stored as the first word after
     * cpu_context in arm64 thread_struct (see arch/arm64 processor.h: uw.tp_value).
     * Several bpftool vmlinux.h variants omit uw / tp_value as usable member names
     * on thread_struct, so we read at sizeof(cpu_context) with a CO-RE type size
     * so the offset tracks the target kernel layout.
     */
    unsigned long tls_tp = 0;
    const char *thread_bytes = (const char *)&task_ptr->thread;
    if (bpf_probe_read_kernel(&tls_tp, sizeof(tls_tp),
                              thread_bytes + bpf_core_type_size(struct cpu_context)) != 0)
        return 0;
    const void *fs_base = (const void *)tls_tp;
#else
#error Target architecture not supported
#endif

    int32_t g_addr_offset = -8;
    uint64_t goid;
    size_t g_addr;
    bpf_probe_read_user(&g_addr, sizeof(void*), (void*)(fs_base + g_addr_offset));
    bpf_probe_read_user(&goid, sizeof(void*),
                        (void*)(g_addr + common_symaddrs.GIDOffset));
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

    struct go_symaddrs_t* symaddrs_p = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs_p == NULL) {
        return 0;
    }
    struct go_symaddrs_t symaddrs = *symaddrs_p;

    const void* sp = (const void*)PT_REGS_SP(ctx);
    uint64_t       regs_buf[9]    = {};
    go_regabi_regs_fill(regs_buf, ctx);
    uint64_t* regs = regs_buf;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_write 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_tls_conn_args args = {};
    assign_arg(&args.conn_ptr, sizeof(args.conn_ptr),
               symaddrs.WriteConnectionLoc, sp, regs);
    assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr),
               symaddrs.WriteBufferLoc, sp, regs);

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
    struct go_symaddrs_t* symaddrs_p = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs_p == NULL) {
        return 0;
    }
    struct go_symaddrs_t symaddrs = *symaddrs_p;

    const void* sp         = (const void*)PT_REGS_SP(ctx);
    uint64_t    regs_buf[9] = {};
    go_regabi_regs_fill(regs_buf, ctx);
    uint64_t* regs = regs_buf;

    int64_t retval0 = 0;
    assign_arg(&retval0, sizeof(retval0), symaddrs.WriteRet0Loc, sp, regs);

    struct go_interface retval1 = {};
    assign_arg(&retval1, sizeof(retval1), symaddrs.WriteRet1Loc, sp, regs);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 2.1 %llu %lu", id, tgid);
    }

    if (retval1.ptr != 0) {
        return 0;
    }

    struct go_interface conn_intf;
    conn_intf.type = 1;
    conn_intf.ptr  = args->conn_ptr;
    int fd = get_fd_from_conn_intf_core(conn_intf, &symaddrs);
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

    /* Full zero-init: process_syscall_data reads iovlen/buf_size; stack garbage fails strict verifiers. */
    struct data_args_t data_args = {};
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

    struct go_tls_conn_args* args_ptr = bpf_map_lookup_elem(&active_tls_conn_op_map, &tgid_goid);
    if (args_ptr == NULL) {
        return 0;
    }
    struct go_tls_conn_args args_local = *args_ptr;

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_write 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    probe_return_tls_conn_write_core(ctx, id, tgid, &args_local);

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

    struct go_symaddrs_t* symaddrs_p = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs_p == NULL) {
        return 0;
    }
    struct go_symaddrs_t symaddrs = *symaddrs_p;

    const void* sp         = (const void*)PT_REGS_SP(ctx);
    uint64_t    regs_buf[9] = {};
    go_regabi_regs_fill(regs_buf, ctx);
    uint64_t* regs = regs_buf;

    if (print_bpf_logs) {
        bpf_printk("probe_entry_tls_conn_read 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    struct go_tls_conn_args args = {};
    assign_arg(&args.conn_ptr, sizeof(args.conn_ptr),
               symaddrs.ReadConnectionLoc, sp, regs);
    assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr),
               symaddrs.ReadBufferLoc, sp, regs);

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
    struct go_symaddrs_t* symaddrs_p = bpf_map_lookup_elem(&go_symaddrs_table, &tgid);
    if (symaddrs_p == NULL) {
        return 0;
    }
    struct go_symaddrs_t symaddrs = *symaddrs_p;

    const void* sp         = (const void*)PT_REGS_SP(ctx);
    uint64_t    regs_buf[9] = {};
    go_regabi_regs_fill(regs_buf, ctx);
    uint64_t* regs = regs_buf;

    int64_t retval0 = 0;
    assign_arg(&retval0, sizeof(retval0), symaddrs.ReadRet0Loc, sp, regs);

    struct go_interface retval1 = {};
    assign_arg(&retval1, sizeof(retval1), symaddrs.ReadRet1Loc, sp, regs);

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 2.1 %llu %lu", id, tgid);
    }

    if (retval1.ptr != 0) {
        return 0;
    }

    struct go_interface conn_intf;
    conn_intf.type = 1;
    conn_intf.ptr  = args->conn_ptr;
    int fd = get_fd_from_conn_intf_core(conn_intf, &symaddrs);
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

    struct data_args_t data_args = {};
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

    struct go_tls_conn_args* args_ptr = bpf_map_lookup_elem(&active_tls_conn_op_map, &tgid_goid);
    if (args_ptr == NULL) {
        return 0;
    }
    struct go_tls_conn_args args_local = *args_ptr;

    if (print_bpf_logs) {
        bpf_printk("probe_return_tls_conn_read 2 %lu %llu",
                         tgid_goid.tgid, tgid_goid.goid);
    }

    probe_return_tls_conn_read_core(ctx, id, tgid, &args_local);

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
