#include <bcc/proto.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/sock.h>

#define socklen_t size_t
#define MAX_MSG_SIZE 30720
#define CHUNK_LIMIT CHUNK_SIZE_LIMIT
#define LOOP_LIMIT 15

// MSG_PEEK (already defined as 2 by linux/socket.h, included above): the recv()
// peeks data WITHOUT consuming it. Envoy's listener inspectors (tls_inspector /
// http_inspector) peek the first bytes of each new downstream connection, then
// read the same bytes for real. Capturing the peek would duplicate the message
// in the msg_seq group, so recv-family probes skip it.

#define ARCH_TYPE 1

enum source_function_t {

  // For syscalls.
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

  // For SSL libraries.
  kSSLWrite,
  kSSLRead,

  kGoTLSWrite,
  kGoTLSRead
};

enum endpoint_role_t {
  kRoleUnknown = 0,
  kRoleClient  = 1,
  kRoleServer  = 2,
};

enum traffic_direction_t {
  kEgress  = 0,
  kIngress = 1,
};

enum message_type_t {
  kUnknown  = 0,
  kRequest  = 1,
  kResponse = 2,
};

// Wire protocol of a connection, derived from the first decisive bytes (see
// classify_protocol). Persisted in conn_info_t and echoed on every data event.
// gRPC is NOT distinguished from HTTP/2 here (its content-type lives in an
// HPACK-compressed HEADERS frame, undecodable in the verifier budget) — the
// grpc-vs-h2 split happens in Go.
enum protocol_t {
  kProtoUnknown = 0,  // unclassified, or first buffer too short → KEEP (fail-open)
  kProtoHTTP    = 1,  // HTTP/1.x request or response
  kProtoHTTP2   = 2,  // HTTP/2 / gRPC (cleartext preface, or decrypted plaintext)
  kProtoTLS     = 3,  // TLS record seen; plaintext reclassified after SSL uprobe
  kProtoOther   = 4,  // decisive non-match → DROP when drop_non_http_flag is set
};

struct conn_info_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short rport;
    u32 raddr;
    u32 laddr;
    unsigned short lport;
    bool ssl;
    u32 readEventsCount;
    u32 writeEventsCount;
    enum endpoint_role_t role;
    u32 msg_seq;
    enum traffic_direction_t prev_direction;
    enum protocol_t protocol;
};

union sockaddr_t {
    struct sockaddr sa;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
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
    // For the SSL_*_ex family only: the caller's out-param pointer
    // (size_t *written / *readbytes). Captured at entry, dereferenced at the
    // _ex return probe to get the real length. NULL for every other caller.
    const size_t* len_ptr;
    // Resolved length for the _ex path. When > 0, process_syscall_data uses it
    // instead of PT_REGS_RC (which for _ex is the 1/0 success flag, not a size).
    int msg_len;
};

struct close_args_t {
    u32 fd;
};

struct socket_open_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short rport;
    u32 raddr;
    u32 laddr;
    unsigned short lport;
    u64 socket_open_ns;
};

struct socket_close_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short rport;
    u32 raddr;
    u64 socket_close_ns;
};

struct socket_data_event_t {
    u64 id;
    u32 fd;
    u64 conn_start_ns;
    unsigned short rport;
    u32 raddr;
    u32 laddr;
    unsigned short lport;
    int bytes_sent;
    u32 readEventsCount;
    u32 writeEventsCount;
    bool ssl;
    enum endpoint_role_t role;
    enum traffic_direction_t direction;
    u32 msg_seq;
    enum protocol_t protocol;
    char msg[MAX_MSG_SIZE];
};

BPF_HASH(conn_info_map, u64, struct conn_info_t, TRAFFIC_MAX_CONNECTION_MAP_SIZE); // 128 * 1024
/*
Stores conn_info_map's keys on a rotating basic, using the conn_counter.
i.e. clear the one which you're on and store the new one.
*/
BPF_ARRAY(conn_info_map_keys, u64, TRAFFIC_MAX_CONNECTION_MAP_SIZE);
BPF_ARRAY(conn_counter, int, 1);

BPF_PERF_OUTPUT(socket_data_events);
BPF_PERF_OUTPUT(socket_open_events);
BPF_PERF_OUTPUT(socket_close_events);

BPF_PERCPU_ARRAY(socket_data_event_buffer_heap, struct socket_data_event_t, 1);

BPF_HASH(active_accept_args_map, u64, struct accept_args_t);
BPF_HASH(active_close_args_map, u64, struct close_args_t);
BPF_HASH(active_read_args_map, u64, struct data_args_t);
BPF_HASH(active_write_args_map, u64, struct data_args_t);
BPF_HASH(active_ssl_read_args_map, uint64_t, struct data_args_t);
BPF_HASH(active_ssl_write_args_map, uint64_t, struct data_args_t);

/*
Maintain a map of kubernetes pids, and only process, if data is from them.
This should reduce the noise a lot.
*/
BPF_HASH(kubernetes_pids, u32, u8);

/*
Map of allowed process comm names (max 16 bytes each).
Populated from TRACE_COMMS env variable.
*/
typedef char comm_t[16];
BPF_HASH(allowed_comms, comm_t, u8);

/*
When set to 1, all processes are traced regardless of kubernetes_pids or allowed_comms.
Set when both TRACE_PIDS and TRACE_COMMS are empty.
*/
BPF_ARRAY(trace_all_flag, u32, 1);

/*
When set to 1, connections classified as kProtoOther (not HTTP/1, HTTP/2, or TLS)
are dropped in-kernel before perf_submit. Set from Go via
AKTO_KERNEL_DROP_NON_HTTP_TRAFFIC (default 1).
*/
BPF_ARRAY(drop_non_http_flag, u32, 1);

static __inline bool should_trace_comm() {
  u32 zero = 0;
  u32 *flag = trace_all_flag.lookup(&zero);
  if (flag != NULL && *flag == 1) {
    return true;
  }
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  u8 *enabled = allowed_comms.lookup(&comm);
  return enabled != NULL;
}

static __inline bool should_trace_tgid(u64 id) {
  u32 zero = 0;
  u32 *flag = trace_all_flag.lookup(&zero);
  if (flag != NULL && *flag == 1) {
    return true;
  }
  u32 tgid = id >> 32;
  u8 *enabled = kubernetes_pids.lookup(&tgid);
  if (enabled == NULL) {
    return false;
  }
  return true;
}


// classify_protocol sniffs the first bytes of a connection ONCE and returns the
// wire protocol. For the HTTP/1 case it also resolves message type (request vs
// response) via *msg_type, so the same single bpf_probe_read serves both the
// protocol gate and role inference (this replaces the old infer_http_message).
//
// Positive-keep signatures: TLS record (0x16 0x03), HTTP/2 preface
// (PRI * HTTP/2.0), HTTP/1 response (HTTP/1.), HTTP/1 request methods. Methods
// OPTIONS/TRACE/CONNECT are intentionally excluded (treated as kProtoOther).
// Fewer than 16 bytes is too short to be decisive → kProtoUnknown (caller keeps
// it, fail-open); a fully-present buffer matching nothing → kProtoOther (drop).
static __inline enum protocol_t classify_protocol(const char* buf, int count,
                                                  enum message_type_t* msg_type) {
    *msg_type = kUnknown;
    if (count < 16) return kProtoUnknown;
    char b[16];
    bpf_probe_read(&b, sizeof(b), buf);

    // TLS record: 0x16 (handshake content type) 0x03 (SSL3/TLS major version).
    // Deliberately does NOT set *msg_type: a TLS connection is reclassified on its
    // decrypted plaintext (set_conn_as_ssl resets protocol -> classify runs again
    // on the real HTTP request/response), so role is resolved there — a better
    // signal than ClientHello/ServerHello. Distinguishing them here would be dead
    // weight. Role also normally comes from accept/connect.
    if (b[0] == 0x16 && b[1] == 0x03) return kProtoTLS;

    // HTTP/2 client connection preface: "PRI * HTTP/2.0", always client->server.
    // Unlike TLS, an h2c connection is classified ONLY ONCE (its later frames are
    // binary, not request/response lines), so the preface is the sole content role
    // signal — hence *msg_type = kRequest here but not for TLS.
    if (b[0]=='P'&&b[1]=='R'&&b[2]=='I'&&b[3]==' '&&b[4]=='*'&&b[5]==' '&&
        b[6]=='H'&&b[7]=='T'&&b[8]=='T'&&b[9]=='P'&&b[10]=='/'&&b[11]=='2') {
        *msg_type = kRequest; return kProtoHTTP2;
    }

    // HTTP/1 response line: "HTTP/1.".
    if (b[0]=='H'&&b[1]=='T'&&b[2]=='T'&&b[3]=='P'&&b[4]=='/'&&b[5]=='1') {
        *msg_type = kResponse; 
        return kProtoHTTP;
    }

    // HTTP/1 request methods (method + SP). OPTIONS/TRACE/CONNECT excluded.
    if (b[0]=='G'&&b[1]=='E'&&b[2]=='T'&&b[3]==' ')                                 { *msg_type = kRequest; return kProtoHTTP; }
    if (b[0]=='P'&&b[1]=='O'&&b[2]=='S'&&b[3]=='T'&&b[4]==' ')                       { *msg_type = kRequest; return kProtoHTTP; }
    if (b[0]=='P'&&b[1]=='U'&&b[2]=='T'&&b[3]==' ')                                 { *msg_type = kRequest; return kProtoHTTP; }
    if (b[0]=='H'&&b[1]=='E'&&b[2]=='A'&&b[3]=='D'&&b[4]==' ')                       { *msg_type = kRequest; return kProtoHTTP; }
    if (b[0]=='D'&&b[1]=='E'&&b[2]=='L'&&b[3]=='E'&&b[4]=='T'&&b[5]=='E'&&b[6]==' ') { *msg_type = kRequest; return kProtoHTTP; }
    if (b[0]=='P'&&b[1]=='A'&&b[2]=='T'&&b[3]=='C'&&b[4]=='H'&&b[5]==' ')            { *msg_type = kRequest; return kProtoHTTP; }

    // Decisive: enough bytes, matched none of the keep signatures.
    return kProtoOther;
}

static __inline u64 gen_tgid_fd(u32 tgid, int fd) {
  return ((u64)tgid << 32) | (u32)fd;
}

static __inline void process_syscall_accept(struct pt_regs* ret, const struct accept_args_t* args, u64 id, bool isConnect) {
    int ret_fd = PT_REGS_RC(ret);


    if(!isConnect && ret_fd < 0){
        if(PRINT_BPF_LOGS){ bpf_trace_printk("DEBUG_PROCESS_ACCEPT: ret_fd < 0, returning early"); }
        return;
    }
    union sockaddr_t* addr;

    struct conn_info_t conn_info = {};
    bool socketConn = false;

    u32 srcIp = 0;
    uint16_t lport = 0;

    if(args->addr != NULL){
        addr = (union sockaddr_t*)args->addr;
    }
    if(args->sock_alloc_socket !=NULL){
        socketConn = true;
        struct sock* sk = NULL;
        bpf_probe_read_kernel(&sk, sizeof(sk),  &(args->sock_alloc_socket)->sk);
        struct sock_common* sk_common = &sk->__sk_common;
        uint16_t family = -1;
        uint16_t rport = -1;
        u32 ip = 0;
        bpf_probe_read_kernel(&family, sizeof(family), &sk_common->skc_family);
        bpf_probe_read_kernel(&rport, sizeof(rport), &sk_common->skc_dport);
        bpf_probe_read_kernel(&lport, sizeof(lport), &sk_common->skc_num);
        conn_info.rport = rport;
        if (family == AF_INET) {
          bpf_probe_read_kernel(&(conn_info.raddr), sizeof(conn_info.raddr), &sk_common->skc_daddr);
          bpf_probe_read_kernel(&(srcIp), sizeof(srcIp), &sk_common->skc_rcv_saddr);
        } else if (family == AF_INET6) {
          struct in6_addr in_addr;
          struct in6_addr in_addr_2;
          bpf_probe_read_kernel(&(in_addr), sizeof(in_addr), &sk_common->skc_v6_daddr);
          bpf_probe_read_kernel(&(in_addr_2), sizeof(in_addr_2), &sk_common->skc_v6_rcv_saddr);
          conn_info.raddr = (in_addr.s6_addr32)[3];
          srcIp = (in_addr_2.s6_addr32)[3];
        } else {
          if(PRINT_BPF_LOGS){ bpf_trace_printk("DEBUG_PROCESS_ACCEPT: unknown family %d, returning", family); }
          return;
        }
    }
    if ( !socketConn && addr->sa.sa_family != AF_INET && addr->sa.sa_family != AF_INET6 ) {
        if(PRINT_BPF_LOGS){ bpf_trace_printk("DEBUG_PROCESS_ACCEPT: bad sa_family, returning"); }
        return;
    }

    conn_info.id = id;
    if(isConnect){
        conn_info.fd = args->fd;
    } else {
        conn_info.fd = ret_fd;
    }
    conn_info.conn_start_ns = bpf_ktime_get_ns();

    if(!socketConn){
    if ( addr->sa.sa_family == AF_INET ){
        struct sockaddr_in* sock_in = (struct sockaddr_in *)addr;
        conn_info.rport = sock_in->sin_port;
        struct in_addr *in_addr_ptr = &(sock_in->sin_addr);
        conn_info.raddr = in_addr_ptr->s_addr;
    } else {
        struct sockaddr_in6* sock_in = (struct sockaddr_in6 *)addr;
        conn_info.rport = sock_in->sin6_port;
        struct in6_addr *in_addr_ptr = &(sock_in->sin6_addr);
        conn_info.raddr = (in_addr_ptr->s6_addr32)[3];
    }
    }

    conn_info.ssl = false;
    conn_info.laddr = srcIp;
    conn_info.lport = lport;
    // rport was read from skc_dport / sin_port — both network byte order (__be16).
    // Canonicalize to host order here (once, covers both derivation paths above) so
    // every downstream consumer (open/data/close events, Go FormatAddr, and the
    // host-order port filter in eventCallbacks.go) sees it consistently with lport,
    // which is already host order (skc_num). Cold path: runs once per connection,
    // not in the data hot loop, so no verifier-instruction pressure.
    // NOTE: the sockaddr fallback (socketConn == false) still leaves lport/laddr = 0;
    // separate, rarer issue — not fixed here to keep this change minimal.
    conn_info.rport = bpf_ntohs(conn_info.rport);
    conn_info.role = isConnect ? kRoleClient : kRoleServer;

    conn_info.readEventsCount = 0;
    conn_info.writeEventsCount = 0;

//    if (PRINT_BPF_LOGS) {
//      u32 fd_assigned = isConnect ? args->fd : (u32)ret_fd;
//      u32 dip = conn_info.raddr;
//      u32 sip = srcIp;
//      bpf_trace_printk("new_conn: type=%s", isConnect ? "connect" : "accept");
//      bpf_trace_printk("new_conn: ret_fd=%d assigned_fd=%d", ret_fd, fd_assigned);
//      bpf_trace_printk("new_conn: local_ip=%d.%d", (sip) & 0xFF, (sip >> 8) & 0xFF);
//      bpf_trace_printk("new_conn: local_ip=%d.%d local_port=%d", (sip >> 16) & 0xFF, (sip >> 24) & 0xFF, lport);
//      bpf_trace_printk("new_conn: remote_ip=%d.%d", (dip) & 0xFF, (dip >> 8) & 0xFF);
//      bpf_trace_printk("new_conn: remote_ip=%d.%d remote_port=%d", (dip >> 16) & 0xFF, (dip >> 24) & 0xFF, bpf_ntohs(conn_info.rport));
//      bpf_trace_printk("new_conn: role=%d", conn_info.role);
//    }

    u32 tgid = id >> 32;
    u64 tgid_fd = 0;
    if(isConnect){
        tgid_fd = gen_tgid_fd(tgid, args->fd);
    } else {
        tgid_fd = gen_tgid_fd(tgid, ret_fd);
    }

    int zero = 0;
    int *counter = conn_counter.lookup_or_try_init(&zero, &zero);
    int val = 0;
    if (counter != NULL) {
      if ( (*counter) > ( TRAFFIC_MAX_CONNECTION_MAP_SIZE - 5 ) ) {
        conn_counter.update(&zero,&zero);
        if (PRINT_BPF_LOGS){
          bpf_trace_printk("conn_info_counter reset: %d", *counter);
        }
      }
      (*counter)++;
      val = *counter;
      if (PRINT_BPF_LOGS){
        bpf_trace_printk("conn_info_counter found: %d", val);
      }
      u64 *curr = conn_info_map_keys.lookup(&val);
      if (curr != NULL) {
        u64 curVal = *curr;
        struct conn_info_t *conn_info = conn_info_map.lookup(&curVal);
        if (conn_info != NULL) {
          conn_info_map.delete(&curVal);
          if (PRINT_BPF_LOGS){
            bpf_trace_printk("conn_info_counter deleting: %d", curVal);
          }
        }
      }
    }

    conn_info_map_keys.update(&val, &tgid_fd);
    conn_info_map.update(&tgid_fd, &conn_info);

    struct socket_open_event_t socket_open_event = {};
    socket_open_event.id = conn_info.id;
    socket_open_event.fd = conn_info.fd;
    socket_open_event.conn_start_ns = conn_info.conn_start_ns;
    socket_open_event.rport = conn_info.rport;
    socket_open_event.raddr = conn_info.raddr;
    socket_open_event.laddr = srcIp;
    socket_open_event.lport = lport;

    socket_open_event.socket_open_ns = conn_info.conn_start_ns;
    socket_open_events.perf_submit(ret, &socket_open_event, sizeof(struct socket_open_event_t));
}

static __inline void process_syscall_close(struct pt_regs* ret, const struct close_args_t* args, u64 id) {
    int ret_val = PT_REGS_RC(ret);

    if (ret_val < 0) {
        return;
    }

    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }

    struct socket_close_event_t socket_close_event = {};
    socket_close_event.id = conn_info->id;
    socket_close_event.fd = conn_info->fd;
    socket_close_event.conn_start_ns = conn_info->conn_start_ns;
    socket_close_event.rport = conn_info->rport;
    socket_close_event.raddr = conn_info->raddr;

    socket_close_event.socket_close_ns = bpf_ktime_get_ns();
    socket_close_events.perf_submit(ret, &socket_close_event, sizeof(struct socket_close_event_t));
    conn_info_map.delete(&tgid_fd);    
}

static __inline void process_syscall_data(struct pt_regs* ret, const struct data_args_t* args, u64 id, bool is_send, bool ssl, bool compute_meta) {
    int bytes_exchanged = PT_REGS_RC(ret);

    if(args->msg_len > 0){
        // SSL_*_ex path: real length came from the *written/*readbytes out-param
        // (PT_REGS_RC is just the 1/0 success flag for _ex).
        bytes_exchanged = args->msg_len;
    } else if(args->iovlen > 0 && args->buf_size > 0){
        bytes_exchanged = args->buf_size;
    }

    if (bytes_exchanged <= 0) {
        return;
    }

    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
      if (PRINT_BPF_LOGS){
        bpf_trace_printk("process_syscall_data conn_info not found id=%d fd=%d", tgid, args->fd);
      }
      return;
    }

    if (conn_info->ssl != ssl) {
        return;
    }

    u32 kZero = 0;
    struct socket_data_event_t* socket_data_event = socket_data_event_buffer_heap.lookup(&kZero);
    if (socket_data_event == NULL) {
        return;
    }

    socket_data_event->id = conn_info->id;
    socket_data_event->fd = conn_info->fd;
    socket_data_event->conn_start_ns = conn_info->conn_start_ns;
    socket_data_event->rport = conn_info->rport;
    socket_data_event->raddr = conn_info->raddr;
    socket_data_event->laddr = conn_info->laddr;
    socket_data_event->lport = conn_info->lport;
    socket_data_event->ssl = conn_info->ssl;

    enum traffic_direction_t direction = is_send ? kEgress : kIngress;

    // Protocol + role + msg_seq are per-connection/per-message properties, not
    // per-buffer: `direction` is constant across a syscall's iovecs, and the
    // values are cached in conn_info. Computing them is only meaningful once per
    // syscall, so callers that inline this function many times (the iovec loop)
    // pass compute_meta=false for all but the first buffer. Because compute_meta
    // is a compile-time constant at each inline site, the heavy classify_protocol
    // block is dead-code-eliminated from the copies that don't need it, keeping
    // the vec probes under the BPF verifier's instruction limit.
    if (compute_meta) {
        // Classify the connection once, on its first decisive buffer. The same
        // single read resolves the wire protocol AND (for HTTP/1) the role
        // fallback. protocol is reset to kProtoUnknown on the TLS->plaintext
        // transition (set_conn_as_ssl), so decrypted traffic is reclassified.
        if (conn_info->protocol == kProtoUnknown && args->buf != NULL) {
            enum message_type_t msg_type = kUnknown;
            conn_info->protocol = classify_protocol(args->buf, bytes_exchanged, &msg_type);
            if (conn_info->role == kRoleUnknown && msg_type != kUnknown) {
                conn_info->role = ((direction == kEgress) ^ (msg_type == kResponse))
                                      ? kRoleClient : kRoleServer;
            }
        }

        // msg_seq: increments on direction change (HTTP message boundary)
        if (conn_info->msg_seq == 0) {
            conn_info->msg_seq = 1;
            conn_info->prev_direction = direction;
        } else if (direction != conn_info->prev_direction) {
            conn_info->msg_seq++;
            conn_info->prev_direction = direction;
        }
    }

    // Drop connections that are decisively not HTTP/1, HTTP/2, or TLS, before the
    // chunk loop / perf_submit. The verdict persists in conn_info, so every later
    // event on this connection is dropped too. The flag lookup touches ONLY
    // kProtoOther connections (the ones we drop) — kept HTTP/h2/TLS traffic pays
    // just the comparison, no map lookup.
    if (conn_info->protocol == kProtoOther) {
        u32 drop_zero = 0;
        u32* drop = drop_non_http_flag.lookup(&drop_zero);
        if (drop != NULL && *drop == 1) {
            return;
        }
    }

    socket_data_event->role      = conn_info->role;
    socket_data_event->direction = direction;
    socket_data_event->msg_seq   = conn_info->msg_seq;
    socket_data_event->protocol  = conn_info->protocol;

//    if (PRINT_BPF_LOGS){
//      bpf_trace_printk("data_loop_start: pid=%d fd=%d total_bytes=%d", id >> 32, conn_info->fd, bytes_exchanged);
//      u32 ip = conn_info->raddr;
//      bpf_trace_printk("data: remote_ip=%d.%d", (ip) & 0xFF, (ip >> 8) & 0xFF);
//      bpf_trace_printk("data: remote_ip=%d.%d port=%d", (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, bpf_ntohs(conn_info->rport));
//      u32 sip = conn_info->laddr;
//      bpf_trace_printk("data: local_ip=%d.%d", (sip) & 0xFF, (sip >> 8) & 0xFF);
//      bpf_trace_printk("data: local_ip=%d.%d port=%d", (sip >> 16) & 0xFF, (sip >> 24) & 0xFF, conn_info->lport);
//      bpf_trace_printk("data: role=%d dir=%d msg_seq=%d", conn_info->role, direction, conn_info->msg_seq);
//    }

    int bytes_sent = 0;
    size_t size_to_save = 0;
    int i =0;
  #pragma unroll
  for (i = 0; i < CHUNK_LIMIT; ++i) {
    const int bytes_remaining = bytes_exchanged - bytes_sent;

    if (bytes_remaining <= 0) {
        break;
    }
    size_t current_size = (bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1)) ? MAX_MSG_SIZE : bytes_remaining;

    size_t current_size_minus_1 = current_size - 1;
    asm volatile("" : "+r"(current_size_minus_1) :);
    current_size = current_size_minus_1 + 1;

    if (current_size > MAX_MSG_SIZE) {
        current_size = MAX_MSG_SIZE;
    }

    if (current_size_minus_1 < MAX_MSG_SIZE) {
      bpf_probe_read(&socket_data_event->msg, current_size, args->buf + bytes_sent);
      size_to_save = current_size;
    } else if (current_size_minus_1 < 0x7fffffff) {
      bpf_probe_read(&socket_data_event->msg, MAX_MSG_SIZE, args->buf + bytes_sent);
      size_to_save = MAX_MSG_SIZE;
    }

    if (is_send){
      conn_info->writeEventsCount = (conn_info->writeEventsCount) + 1u;
    } else {
      conn_info->readEventsCount = (conn_info->readEventsCount) + 1u;
    }

    socket_data_event->writeEventsCount = conn_info->writeEventsCount;
    socket_data_event->readEventsCount = conn_info->readEventsCount;

    if(PRINT_BPF_LOGS){
          bpf_trace_printk("rc: %d wc: %d data: %s", socket_data_event->readEventsCount, socket_data_event->writeEventsCount, socket_data_event->msg);
    }
    socket_data_event->bytes_sent = is_send ? 1 : -1;
    socket_data_event->bytes_sent *= size_to_save;
    socket_data_events.perf_submit(ret, socket_data_event, sizeof(struct socket_data_event_t) - MAX_MSG_SIZE + size_to_save);

    bytes_sent += current_size;
  }

}

static __inline void process_syscall_data_vecs(struct pt_regs* ret, struct data_args_t* args, u64 id, bool is_send){
    int bytes_sent=0;
    int total_size = PT_REGS_RC(ret);
    const struct iovec* iov = args->iov;
    for (int i = 0; i < LOOP_LIMIT && i < args->iovlen && bytes_sent < total_size ; ++i) {
        struct iovec iov_cpy;
        bpf_probe_read(&iov_cpy, sizeof(iov_cpy), &iov[i]);

        const int bytes_remaining = total_size - bytes_sent;
        const size_t iov_size = iov_cpy.iov_len < bytes_remaining ? iov_cpy.iov_len : bytes_remaining ;
        
        args->buf = iov_cpy.iov_base;
        args->buf_size = iov_size;
        // compute_meta only on the first iovec: role/msg_seq are per-message,
        // and the HTTP request/response line lives in iov[0]. i==0 is a
        // compile-time constant per unrolled copy, so the metadata code is
        // emitted once instead of LOOP_LIMIT times.
        process_syscall_data(ret, args, id, is_send, false, /* compute_meta */ i == 0);
        bytes_sent += iov_size;
        
      }
}

// Hooks
int syscall__probe_entry_accept(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_accept: pid=%d fd=%d", id >> 32, sockfd);
  }

    struct accept_args_t accept_args = {};
    accept_args.addr = addr;
    active_accept_args_map.update(&id, &accept_args);
    
    return 0;
}

int syscall__probe_ret_accept(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    int ret_fd = PT_REGS_RC(ctx);


    if (!should_trace_comm()) {
        return 0;
    }

    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);

    if (accept_args == NULL) {
    } else {
        if(PRINT_BPF_LOGS){ bpf_trace_printk("DEBUG_RET_ACCEPT: accept_args found, calling process_syscall_accept"); }
        process_syscall_accept(ctx, accept_args, id, false);
    }

    active_accept_args_map.delete(&id);
    return 0;
}

int probe_ret_sock_alloc(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
    return 0;
  }
  
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_ret_sock_alloc: pid: %d", id);
  }
  // Only trace sock_alloc() called by accept()/accept4().
  struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
  if (accept_args == NULL) {
    return 0;
  }

  if (accept_args->sock_alloc_socket == NULL) {
    accept_args->sock_alloc_socket = (struct socket*)PT_REGS_RC(ctx);
  }

  return 0;
}

int probe_entry_tcp_connect(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
    return 0;
  }
  
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_tcp_connect: pid: %d", id);
  }
  // Only trace sock_alloc() called by accept()/accept4().
  struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
  if (accept_args == NULL) {
    return 0;
  }

  if (accept_args->sock == NULL){
    accept_args->sock = (void *)PT_REGS_PARM1(ctx);
  }

  return 0;
}

int syscall__probe_entry_connect(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_connect: pid=%d fd=%d", id >> 32, sockfd);
  }

    struct accept_args_t accept_args = {};
    accept_args.fd = sockfd;
    accept_args.addr = addr;
    active_accept_args_map.update(&id, &accept_args);
    
    return 0;
}

int syscall__probe_ret_connect(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_connect: pid: %d", id);
  }

    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);

    if (accept_args != NULL) {
      if (accept_args->sock != NULL) {
        struct sock *sock = accept_args->sock;
        struct socket *s;
        bpf_probe_read_kernel(&(s), sizeof(s), &sock->sk_socket);
        accept_args->sock_alloc_socket = s;
      }
      process_syscall_accept(ctx, accept_args, id, true);
    }

    active_accept_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_close(struct pt_regs* ctx, int fd) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_close: pid=%d fd=%d", id >> 32, fd);
  }

    struct close_args_t close_args = {};
    close_args.fd = fd;
    active_close_args_map.update(&id, &close_args);
    
    return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_close: pid: %d", id >> 32);
  }

    struct close_args_t* close_args = active_close_args_map.lookup(&id);

    if (close_args != NULL) {
        process_syscall_close(ctx, close_args, id);
    }

    active_close_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_writev(struct pt_regs* ctx, int fd, const struct iovec* iov, int iovlen){
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_writev: pid=%d fd=%d", id >> 32, fd);
  }

    struct data_args_t write_args = {};
    write_args.fd = fd;
    write_args.iov = iov;
    write_args.iovlen = iovlen;
    write_args.source_fn = kSyscallWriteV;

    struct data_args_t* existing_write_args = active_write_args_map.lookup(&id);
    if (existing_write_args != NULL && existing_write_args->sock_event) {
      write_args.sock_event = true;
    }

    active_write_args_map.update(&id, &write_args);
  
    return 0;
}

int syscall__probe_ret_writev(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }
    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_writev: pid: %d", id);
  }

    struct data_args_t* write_args = active_write_args_map.lookup(&id);
    if (write_args != NULL && write_args->sock_event) {
        if(PRINT_BPF_LOGS){
            bpf_trace_printk("syscall__probe_ret_writev data process: pid: %d", id >> 32);
        }
      process_syscall_data_vecs(ctx, write_args, id, true);
    }
    
    active_write_args_map.delete(&id);
    return 0;
  }

int syscall__probe_entry_sendmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msghdr){
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

	if (msghdr != NULL) {
      if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_sendmsg: pid=%d fd=%d", id >> 32, fd);
  }
	
		struct data_args_t write_args = {};
		write_args.fd = fd;
		write_args.iov = msghdr->msg_iov;
		write_args.iovlen = msghdr->msg_iovlen;
        write_args.source_fn = kSyscallSendMsg;
		active_write_args_map.update(&id, &write_args);
	  }
  
    return 0;
}

int syscall__probe_ret_sendmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

      if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_sendmsg: pid: %d", id >> 32);
  }

    struct data_args_t* write_args = active_write_args_map.lookup(&id);
    if (write_args != NULL) {
      process_syscall_data_vecs(ctx, write_args, id, true);
    }
    
    active_write_args_map.delete(&id);
    return 0;
  }

  int syscall__probe_entry_readv(struct pt_regs* ctx, int fd, struct iovec* iov, int iovlen) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }
      if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_readv: pid=%d fd=%d", id >> 32, fd);
  }
    
    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.iov = iov;
    read_args.iovlen = iovlen;
    read_args.source_fn = kSyscallReadV;

    struct data_args_t* existing_read_args = active_read_args_map.lookup(&id);
    if (existing_read_args != NULL && existing_read_args->sock_event) {
      read_args.sock_event = true;
    }

    active_read_args_map.update(&id, &read_args);
  
    return 0;
  }
  
  int syscall__probe_ret_readv(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }
    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_readv: pid: %d", id >> 32);
  }
    
    struct data_args_t* read_args = active_read_args_map.lookup(&id);
    if (read_args != NULL && read_args->sock_event) {
      process_syscall_data_vecs(ctx, read_args, id, false);
    }
    
    active_read_args_map.delete(&id);
    return 0;
  }

int syscall__probe_entry_recvfrom(struct pt_regs* ctx, int fd, char* buf, size_t count,
	int flags, struct sockaddr* src_addr, socklen_t* addrlen) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    // MSG_PEEK reads don't consume the socket; the real read follows and is
    // captured. Skip the peek so it isn't recorded as a duplicate fragment.
    if (flags & MSG_PEEK) {
        active_read_args_map.delete(&id);
        return 0;
    }

  if(PRINT_BPF_LOGS){
    struct data_args_t* read_args_1 = active_read_args_map.lookup(&id);

    if (read_args_1 != NULL){
      bpf_trace_printk("syscall__probe_entry_recvfrom: pid=%d fd=%d read args fd=%d", id >> 32, fd, read_args_1->fd);
    } else {
      bpf_trace_printk("syscall__probe_entry_recvfrom: pid=%d fd=%d read args=NULL", id >> 32, fd);
    }
  }

    struct data_args_t read_args = {};
    read_args.buf = buf;
    read_args.fd = fd;
	read_args.source_fn = kSyscallRecvFrom;
    active_read_args_map.update(&id, &read_args);
    
    return 0;
}

int syscall__probe_ret_recvfrom(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_recvfrom: pid: %d", id >> 32);
  }

    struct data_args_t* read_args = active_read_args_map.lookup(&id);

    if (read_args != NULL) {
        process_syscall_data(ctx, read_args, id, false, false, true);
    }

    active_read_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_sendto(struct pt_regs* ctx, int fd, char* buf, size_t count,
	int flags, const struct sockaddr* dest_addr, socklen_t addrlen) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

  if(PRINT_BPF_LOGS){
        struct data_args_t* write_args_1 = active_write_args_map.lookup(&id);

    if (write_args_1 != NULL) {
      bpf_trace_printk("syscall__probe_entry_sendto: pid=%d fd=%d write args fd=%d", id >> 32, fd, write_args_1->fd);
    } else {
      bpf_trace_printk("syscall__probe_entry_sendto: pid=%d fd=%d write args=NULL", id >> 32, fd);
    }
  }

    struct data_args_t write_args = {};
    write_args.buf = buf;
    write_args.fd = fd;
	write_args.source_fn = kSyscallSendTo;
    active_write_args_map.update(&id, &write_args);
    
    return 0;
}

int syscall__probe_ret_sendto(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_sendto: pid: %d", id >> 32);
  }

    struct data_args_t* write_args = active_write_args_map.lookup(&id);

    if (write_args != NULL) {
        process_syscall_data(ctx, write_args, id, true, false, true);
    }

    active_write_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_recv(struct pt_regs* ctx, int fd, char* buf, size_t count, int flags) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    // Skip MSG_PEEK (non-consuming); the real read follows. See recvfrom above.
    if (flags & MSG_PEEK) {
        active_read_args_map.delete(&id);
        return 0;
    }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_recv: pid=%d fd=%d", id >> 32, fd);
  }

    struct data_args_t read_args = {};
    read_args.buf = buf;
    read_args.fd = fd;
	read_args.source_fn = kSyscallRecv;
    active_read_args_map.update(&id, &read_args);
    
    return 0;
}

int syscall__probe_ret_recv(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_recv: pid: %d", id >> 32);
  }

    struct data_args_t* read_args = active_read_args_map.lookup(&id);

    if (read_args != NULL) {
        process_syscall_data(ctx, read_args, id, false, false, true);
    }

    active_read_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_read(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
      return 0;
  }
  if(PRINT_BPF_LOGS){
      struct data_args_t* read_args_1 = active_read_args_map.lookup(&id);

    if (read_args_1 != NULL)
    {
      bpf_trace_printk("syscall__probe_entry_read: pid=%d fd=%d read args fd=%d", id >> 32, fd, read_args_1->fd);
    }
    else
    {
      bpf_trace_printk("syscall__probe_entry_read: pid=%d fd=%d read args=NULL", id >> 32, fd);
    }
  }

    struct data_args_t read_args = {};
    read_args.buf = buf;
    read_args.fd = fd;
	read_args.source_fn = kSyscallRead;

    struct data_args_t* existing_read_args = active_read_args_map.lookup(&id);
    if (existing_read_args != NULL && existing_read_args->sock_event) {
      read_args.sock_event = true;
    }

    active_read_args_map.update(&id, &read_args);
    
    return 0;
}

int syscall__probe_ret_read(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    struct data_args_t* read_args = active_read_args_map.lookup(&id);

    if (read_args != NULL && read_args->sock_event) {
      if(PRINT_BPF_LOGS){
        bpf_trace_printk("syscall__probe_ret_read pid=%d fd=%d sock_event=1", id >> 32, read_args->fd);
      }
      process_syscall_data(ctx, read_args, id, false, false, true);
    } else if (read_args != NULL) {
      if(PRINT_BPF_LOGS){
        bpf_trace_printk("syscall__probe_ret_read pid=%d fd=%d sock_event=0 skipping", id >> 32, read_args->fd);
      }
    }

    active_read_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_recvmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msghdr, int flags) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

    // Skip MSG_PEEK (non-consuming); the real read follows. See recvfrom above.
    if (flags & MSG_PEEK) {
        active_read_args_map.delete(&id);
        return 0;
    }

	if (msghdr != NULL) {

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_recvmsg: pid=%d fd=%d", id >> 32, fd);
  }
	
		struct data_args_t read_args = {};
		read_args.fd = fd;
		read_args.iov = msghdr->msg_iov;
		read_args.iovlen = msghdr->msg_iovlen;
		read_args.source_fn = kSyscallRecvMsg;
		active_read_args_map.update(&id, &read_args);
	  }
    
    return 0;
}

int syscall__probe_ret_recvmsg(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_recvmsg: pid: %d", id >> 32);
  }

    struct data_args_t* read_args = active_read_args_map.lookup(&id);

    if (read_args != NULL) {
        process_syscall_data_vecs(ctx, read_args, id, false);
    }

    active_read_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_send(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_send: pid=%d fd=%d", id >> 32, fd);
  }

    struct data_args_t write_args = {};
    write_args.buf = buf;
    write_args.fd = fd;
	write_args.source_fn = kSyscallSend;
    active_write_args_map.update(&id, &write_args);
    
    return 0;
}

int syscall__probe_ret_send(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
        return 0;
    }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_send: pid: %d", id >> 32);
  }

    struct data_args_t* write_args = active_write_args_map.lookup(&id);

    if (write_args != NULL) {
        process_syscall_data(ctx, write_args, id, true, false, true);
    }

    active_write_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_write(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
      return 0;
  }
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_write: pid=%d fd=%d", id >> 32, fd);
  }

    struct data_args_t write_args = {};
    write_args.buf = buf;
    write_args.fd = fd;
	  write_args.source_fn = kSyscallWrite;

    struct data_args_t* existing_write_args = active_write_args_map.lookup(&id);
    if (existing_write_args != NULL && existing_write_args->sock_event) {
      write_args.sock_event = true;
    }
    
    active_write_args_map.update(&id, &write_args);
    return 0;
}

int syscall__probe_ret_write(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
      return 0;
  }

  if(PRINT_BPF_LOGS){
    struct data_args_t* write_args_1 = active_write_args_map.lookup(&id);

    if (write_args_1 != NULL) {
      bpf_trace_printk("syscall__probe_ret_write: pid: %d write args : %d", id >> 32, write_args_1->fd);
    } else {
      bpf_trace_printk("syscall__probe_ret_write: pid: %d write args : NULL", id >> 32);
    }
  }

    struct data_args_t* write_args = active_write_args_map.lookup(&id);

    if (write_args != NULL && write_args->sock_event) {
      if(PRINT_BPF_LOGS){
        bpf_trace_printk("syscall__probe_ret_write data process: pid=%d fd=%d sock_event=1", id >> 32, write_args->fd);
      }
      process_syscall_data(ctx, write_args, id, true, false, true);
    } else if (write_args != NULL) {
      if(PRINT_BPF_LOGS){
        bpf_trace_printk("syscall__probe_ret_write pid=%d fd=%d sock_event=0 skipping", id >> 32, write_args->fd);
      }
    }

    active_write_args_map.delete(&id);
    return 0;
}


// Trace kernel function:
// int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
// which is called by write/writev
int probe_entry_security_socket_sendmsg(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
    return 0;
  }


  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    write_args->sock_event = true;
    if(PRINT_BPF_LOGS){
      bpf_trace_printk("probe_entry_security_socket_sendmsg: pid: %d, fd: %d", id >> 32, write_args->fd);
    }
  }
  return 0;
}

// Trace kernel function:
// int security_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size)
int probe_entry_security_socket_recvmsg(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
    return 0;
  }

  
  
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    read_args->sock_event = true;
    if(PRINT_BPF_LOGS){
      bpf_trace_printk("probe_entry_security_socket_recvmsg: pid: %d, fd: %d", id >> 32, read_args->fd);
    }
  }
  return 0;
}

int probe_entry_setsockopt(struct pt_regs* ctx, int socket, int level, int option_name,
       const void *option_value, socklen_t option_len) {
  u64 id = bpf_get_current_pid_tgid();

  if (!should_trace_comm()) {
    return 0;
  }

  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    write_args->sock_event = true;
  }
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    read_args->sock_event = true;
  }

  if(PRINT_BPF_LOGS){
    int wfd = write_args != NULL ? write_args->fd : -1;
    int rfd = read_args != NULL ? read_args->fd : -1;
    bpf_trace_printk("probe_entry_setsockopt: pid=%d wfd=%d rfd=%d", id >> 32, wfd, rfd);
  }
  return 0;
}

struct node_tlswrap_symaddrs_t {
  u32 TLSWrapStreamListenerOffset;
	u32 StreamListenerStreamOffset;
	u32 StreamBaseStreamResourceOffset;
	u32 LibuvStreamWrapStreamBaseOffset;
	u32 LibuvStreamWrapStreamOffset;
	u32 UVStreamSIOWatcherOffset;
	u32 UVIOSFDOffset;
};

BPF_HASH(node_tlswrap_symaddrs_map, u32, struct node_tlswrap_symaddrs_t);
BPF_HASH(active_TLSWrap_memfn_this, uint64_t, void*);
BPF_HASH(node_ssl_tls_wrap_map, void*, void*);

static __inline int32_t get_fd_from_tlswrap_ptr(const struct node_tlswrap_symaddrs_t* symaddrs,
                                                void* tlswrap) {
  void* stream_ptr =
      tlswrap + symaddrs->TLSWrapStreamListenerOffset + symaddrs->StreamListenerStreamOffset;
  void* stream = NULL;

  bpf_probe_read(&stream, sizeof(stream), stream_ptr);

  if (stream == NULL) {
    return 0;
  }

  void* uv_stream_ptr = stream - symaddrs->StreamBaseStreamResourceOffset -
                        symaddrs->LibuvStreamWrapStreamBaseOffset +
                        symaddrs->LibuvStreamWrapStreamOffset;

  void* uv_stream = NULL;
  bpf_probe_read(&uv_stream, sizeof(uv_stream), uv_stream_ptr);

  if (uv_stream == NULL) {
    return 0;
  }

  int32_t* fd_ptr =
      uv_stream + symaddrs->UVStreamSIOWatcherOffset + symaddrs->UVIOSFDOffset;

  int32_t fd = 0;

  if (bpf_probe_read(&fd, sizeof(fd), fd_ptr) != 0) {
    return 0;
  }

  return fd;
}

static __inline int32_t get_fd_node(uint32_t tgid, void* ssl) {
  void** tls_wrap_ptr = node_ssl_tls_wrap_map.lookup(&ssl);
  if (tls_wrap_ptr == NULL) {
    return 0;
  }

  const struct node_tlswrap_symaddrs_t* symaddrs = node_tlswrap_symaddrs_map.lookup(&tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  return get_fd_from_tlswrap_ptr(symaddrs, *tls_wrap_ptr);
}

static u32 get_fd(void *ssl, int sslVersion, bool rw) {
    int32_t SSL_rbio_offset;
    int32_t RBIO_num_offset;

        SSL_rbio_offset = 16;
    switch (sslVersion)
    {
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
    case 5:
        // OpenSSL 3.2+ : rbio moved to ssl_connection_st (ssl_st base = 64 bytes)
        // verified on OpenSSL 3.5.5: sudo gdb -batch -ex "add-symbol-file /usr/lib64/libssl.so.3.5.5" -ex "ptype /o struct ssl_connection_st" -ex "quit"
        SSL_rbio_offset = 80;
        RBIO_num_offset = 56;
        break;
    default:
        break;
    }

    const void** rbio_ptr_addr = ssl + SSL_rbio_offset;
    const void* rbio_ptr = *rbio_ptr_addr;
    const int* rbio_num_addr = rbio_ptr + RBIO_num_offset;
    u32 rbio_num = *rbio_num_addr;
    if(PRINT_BPF_LOGS){
      bpf_trace_printk("SSL fd offset: %d %d %d", rbio_num, SSL_rbio_offset, RBIO_num_offset);
    }
    return rbio_num;
}

static void set_conn_as_ssl(u32 tgid, u32 fd){
    u64 tgid_fd = gen_tgid_fd(tgid, fd);
    if(PRINT_BPF_LOGS){
      bpf_trace_printk("SSL tgid: %d", tgid_fd);
    }
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    if(PRINT_BPF_LOGS){
      bpf_trace_printk("SSL marking ssl tgid: %d", tgid_fd);
    }
    // Reclassify on the plaintext only on the false->true edge. The pre-SSL
    // handshake bytes classified as kProtoTLS; resetting to kProtoUnknown makes
    // the first DECRYPTED buffer (HTTP request or HTTP/2 preface) re-run
    // classify_protocol so Go gets the real HTTP/1-vs-HTTP/2 verdict. Guarded by
    // the edge so mid-stream SSL buffers (which don't start a message) are never
    // reclassified as kProtoOther and wrongly dropped.
    if (!conn_info->ssl) {
        conn_info->ssl = true;
        conn_info->protocol = kProtoUnknown;
    }
}

// Shared stash for all SSL entry probes (read & write, classic & _ex). The only
// difference between the read and write cores was the args map, so it's a bool
// here. len_ptr is NULL for the classic API and the *written/*readbytes pointer
// for the _ex API.
static void ssl_entry_stash(struct pt_regs *ctx, u32 fd, const size_t* len_ptr, bool is_write){
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("ssl_entry_stash: pid: %d %d fd: %d", id, tgid, fd);
  }

  struct data_args_t args = {};
  args.fd = fd;
  args.buf = (char*)PT_REGS_PARM2(ctx);
  args.len_ptr = len_ptr;
  if (is_write) {
    active_ssl_write_args_map.update(&id, &args);
  } else {
    active_ssl_read_args_map.update(&id, &args);
  }

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, fd);
}

static void probe_entry_SSL_write_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
  ssl_entry_stash(ctx, fd, NULL, /* is_write */ true);
}

// _ex variant: capture the *written out-param pointer (4th arg) for the ret probe.
static void probe_entry_SSL_write_ex_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
  ssl_entry_stash(ctx, fd, (const size_t*)PT_REGS_PARM4(ctx), /* is_write */ true);
}

int probe_entry_SSL_write_1_0(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, 1, false);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_1_0: fd: %d", fd);
  }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_write_1_1(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, 2, false);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_1_1: fd: %d", fd);
  }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_write_3_0(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, 3, false);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_3_0: fd: %d", fd);
  }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_write_3_5(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, 5, false);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_3_5: fd: %d", fd);
  }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

// SSL_write_ex(ssl, buf, num, size_t *written): same first 3 args as SSL_write,
// so fd derivation is identical; only the ex core (which grabs PARM4) differs.
int probe_entry_SSL_write_ex_3_0(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, 3, false);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_ex_3_0: fd: %d", fd);
  }
    probe_entry_SSL_write_ex_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_write_ex_3_5(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, 5, false);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_ex_3_5: fd: %d", fd);
  }
    probe_entry_SSL_write_ex_core(ctx, ssl, buf, num, fd);
  return 0;
}

// using this probe for node-openSSL only.
int probe_entry_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
    u32 fd = get_fd_node(tgid, ssl);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write: fd: %d", fd);
  }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_write_boring(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, 4, false);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_boring: fd: %d", fd);
  }
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_ret_SSL_write(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_ret_SSL_write: pid: %d", id);
  }

  const struct data_args_t* write_args = active_ssl_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_syscall_data(ctx, write_args, id, true, true, true);
  }

  active_ssl_write_args_map.delete(&id);
  return 0;
}

// SSL_write_ex return: RC is the 1/0 success flag, real length is at *written.
// Shared body for both SSL_*_ex return probes. They differ only in the args map
// and is_send; the map can't be passed as a value in this bcc C style, so it's
// selected here by is_send (same approach as ssl_entry_stash). For the _ex API
// PT_REGS_RC is the 1/0 success flag, so the real length comes from *len_ptr.
static __inline void ssl_ret_ex(struct pt_regs* ctx, u64 id, bool is_send){
  struct data_args_t* args = is_send
      ? active_ssl_write_args_map.lookup(&id)
      : active_ssl_read_args_map.lookup(&id);

  if (args != NULL && PT_REGS_RC(ctx) == 1 && args->len_ptr != NULL) {
    size_t n = 0;
    bpf_probe_read_user(&n, sizeof(n), args->len_ptr);
    if (n > MAX_MSG_SIZE) {
      n = MAX_MSG_SIZE;
    }
    args->msg_len = (int)n;
    process_syscall_data(ctx, args, id, is_send, true, true);
  }

  if (is_send) {
    active_ssl_write_args_map.delete(&id);
  } else {
    active_ssl_read_args_map.delete(&id);
  }
}

int probe_ret_SSL_write_ex(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_ret_SSL_write_ex: pid: %d", id);
  }
  ssl_ret_ex(ctx, id, /* is_send */ true);
  return 0;
}

static void probe_entry_SSL_read_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
  ssl_entry_stash(ctx, fd, NULL, /* is_write */ false);
}

// _ex variant: capture the *readbytes out-param pointer (4th arg) for the ret probe.
static void probe_entry_SSL_read_ex_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
  ssl_entry_stash(ctx, fd, (const size_t*)PT_REGS_PARM4(ctx), /* is_write */ false);
}

int probe_entry_SSL_read_1_0(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, 1, true);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_1_0: fd: %d", fd);
  }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_read_1_1(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, 2, true);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_1_1: fd: %d", fd);
  }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_read_3_0(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, 3, true);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_3_0: fd: %d", fd);
  }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_read_3_5(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, 5, true);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_3_5: fd: %d", fd);
  }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
  return 0;
}

// SSL_read_ex(ssl, buf, num, size_t *readbytes): same first 3 args as SSL_read.
int probe_entry_SSL_read_ex_3_0(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, 3, true);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_ex_3_0: fd: %d", fd);
  }
    probe_entry_SSL_read_ex_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_read_ex_3_5(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, 5, true);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_ex_3_5: fd: %d", fd);
  }
    probe_entry_SSL_read_ex_core(ctx, ssl, buf, num, fd);
  return 0;
}

// using this probe for node-openSSL only.
int probe_entry_SSL_read(struct pt_regs *ctx, void *ssl, void *buf, int num) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
    int32_t fd = get_fd_node(tgid, ssl);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read: fd: %d", fd);
  }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_read_boring(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, 4, true);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_boring: fd: %d", fd);
  }
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);

  return 0;
}

int probe_ret_SSL_read(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_ret_SSL_read: pid: %d", id);
  }

  const struct data_args_t* read_args = active_ssl_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_syscall_data(ctx, read_args, id, false, true, true);
  }

  active_ssl_read_args_map.delete(&id);
  return 0;
}

// SSL_read_ex return: RC is the 1/0 success flag, real length is at *readbytes.
int probe_ret_SSL_read_ex(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_ret_SSL_read_ex: pid: %d", id);
  }
  ssl_ret_ex(ctx, id, /* is_send */ false);
  return 0;
}

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
struct location_t{
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

BPF_PERCPU_ARRAY(regs_heap, struct go_regabi_regs, 1);

static __inline uint64_t* go_regabi_regs(const struct pt_regs* ctx) {
  uint32_t kZero = 0;
  struct go_regabi_regs* regs_heap_var = regs_heap.lookup(&kZero);
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

BPF_HASH(go_symaddrs_table, u32, struct go_symaddrs_t);
BPF_HASH(active_tls_conn_op_map, struct tgid_goid_t, struct go_tls_conn_args);

static inline uint64_t get_goid(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  struct go_symaddrs_t* common_symaddrs = go_symaddrs_table.lookup(&tgid);
  if (common_symaddrs == NULL) {
    return 0;
  }

  // Get fsbase from `struct task_struct`.
  const struct task_struct* task_ptr = (struct task_struct*)bpf_get_current_task();
  if (!task_ptr) {
    return 0;
  }

#if defined(TARGET_ARCH_X86_64)
  const void* fs_base = (void*)task_ptr->thread.fsbase;
#elif defined(TARGET_ARCH_AARCH64)
  const void* fs_base = (void*)task_ptr->thread.uw.tp_value;
#else
#error Target architecture not supported
#endif

  // Get ptr to `struct g` from 8 bytes before fsbase and then access the goID.
  int32_t g_addr_offset = -8;
  uint64_t goid;
  size_t g_addr;
  bpf_probe_read_user(&g_addr, sizeof(void*), (void*)(fs_base + g_addr_offset));
  bpf_probe_read_user(&goid, sizeof(void*), (void*)(g_addr + common_symaddrs->GIDOffset));
  return goid;
}

static __inline void assign_arg(void* arg, size_t arg_size, struct location_t loc, const void* sp,
                                uint64_t* regs) {
  if (loc.type == kLocationTypeStack) {
    bpf_probe_read(arg, arg_size, sp + loc.offset);
  } else if (loc.type == kLocationTypeRegisters) {
    if (loc.offset >= 0) {
      bpf_probe_read(arg, arg_size, (char*)regs + loc.offset);
    }
  }
}

static __inline int32_t get_fd_from_conn_intf_core(struct go_interface conn_intf,
                                                   const struct go_symaddrs_t* symaddrs) {

    bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_intf.ptr + symaddrs->TLSConnOffset);

    if (conn_intf.type != symaddrs->TCPConnOffset) {
        return 0;
    }

    void* fd_ptr;
    bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);
    __u64 sysfd;
    bpf_probe_read(&sysfd, sizeof(sysfd), fd_ptr + symaddrs->FDSysFDOffset);
    return sysfd;
}

int probe_entry_tls_conn_write(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_tls_conn_write 1 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }

  struct go_symaddrs_t* symaddrs = go_symaddrs_table.lookup(&tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  const void* sp = (const void*)ctx->sp;
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_tls_conn_write 2 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }
  
  struct go_tls_conn_args args = {};
  assign_arg(&args.conn_ptr, sizeof(args.conn_ptr), symaddrs->WriteConnectionLoc, sp, regs);
  assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr), symaddrs->WriteBufferLoc, sp, regs);

  active_tls_conn_op_map.update(&tgid_goid, &args);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_tls_conn_write 3 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }
  return 0;
}

static __inline int probe_return_tls_conn_write_core(struct pt_regs* ctx, uint64_t id,
                                                     uint32_t tgid, struct go_tls_conn_args* args) {
  struct go_symaddrs_t* symaddrs = go_symaddrs_table.lookup(&tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  const void* sp = (const void*)ctx->sp;
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  int64_t retval0 = 0;
  assign_arg(&retval0, sizeof(retval0), symaddrs->WriteRet0Loc, sp, regs);

  struct go_interface retval1 = {};
  assign_arg(&retval1, sizeof(retval1), symaddrs->WriteRet1Loc, sp, regs);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_write 2.1 %llu %lu", id, tgid);
  }
  // If function returns an error, then there's no data to trace.
  if (retval1.ptr != 0) {
    return 0;
  }

  // To call get_fd_from_conn_intf, cast the conn_ptr into a go_interface.
  struct go_interface conn_intf;
  conn_intf.type = 1;
  conn_intf.ptr = args->conn_ptr;
  int fd = get_fd_from_conn_intf_core(conn_intf, symaddrs);
  u32 fdu = (u32)fd;
  
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("TLS : %lu", fdu);
  }

  set_conn_as_ssl(tgid, fdu);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_write 2.2 %llu %lu", id, tgid);
  }

  struct data_args_t data_args;
  data_args.source_fn = kGoTLSWrite;
  data_args.buf = args->plaintext_ptr;
  data_args.fd = fd;

  process_syscall_data(ctx, &data_args, id, true, /* ssl */ true, true);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_write 2.3 %llu %lu", id, tgid);
  }

  return 0;
}

int probe_return_tls_conn_write(struct pt_regs* ctx) {

  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_write 1 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }

  struct go_tls_conn_args* args = active_tls_conn_op_map.lookup(&tgid_goid);
  if (args == NULL) {
    return 0;
  }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_write 2 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }

  probe_return_tls_conn_write_core(ctx, id, tgid, args);

  active_tls_conn_op_map.delete(&tgid_goid);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_write 3 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }
  return 0;
}

int probe_entry_tls_conn_read(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_tls_conn_read 1 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }

  struct go_symaddrs_t* symaddrs = go_symaddrs_table.lookup(&tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  const void* sp = (const void*)ctx->sp;
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_tls_conn_read 2 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }
  
  struct go_tls_conn_args args = {};
  assign_arg(&args.conn_ptr, sizeof(args.conn_ptr), symaddrs->ReadConnectionLoc, sp, regs);
  assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr), symaddrs->ReadBufferLoc, sp, regs);

  active_tls_conn_op_map.update(&tgid_goid, &args);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_tls_conn_read 3 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }

  return 0;
}

static __inline int probe_return_tls_conn_read_core(struct pt_regs* ctx, uint64_t id,
                                                     uint32_t tgid, struct go_tls_conn_args* args) {
  struct go_symaddrs_t* symaddrs = go_symaddrs_table.lookup(&tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  const void* sp = (const void*)ctx->sp;
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  int64_t retval0 = 0;
  assign_arg(&retval0, sizeof(retval0), symaddrs->ReadRet0Loc, sp, regs);

  struct go_interface retval1 = {};
  assign_arg(&retval1, sizeof(retval1), symaddrs->ReadRet1Loc, sp, regs);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_read 2.1 %llu %lu", id, tgid);
  }

  // If function returns an error, then there's no data to trace.
  if (retval1.ptr != 0) {
    return 0;
  }

  // To call get_fd_from_conn_intf, cast the conn_ptr into a go_interface.
  struct go_interface conn_intf;
  conn_intf.type = 1;
  conn_intf.ptr = args->conn_ptr;
  int fd = get_fd_from_conn_intf_core(conn_intf, symaddrs);
  u32 fdu = (u32)fd;
  
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("TLS : %lu", fdu);
  }

  set_conn_as_ssl(tgid, fdu);
  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_read 2.2 %llu %lu", id, tgid);
  }

  struct data_args_t data_args;
  data_args.source_fn = kGoTLSRead;
  data_args.buf = args->plaintext_ptr;
  data_args.fd = fd;

  process_syscall_data(ctx, &data_args, id, false, /* ssl */ true, true);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_read 2.3 %llu %lu", id, tgid);
  }

  return 0;
}

int probe_return_tls_conn_read(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_read 1 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }

  struct go_tls_conn_args* args = active_tls_conn_op_map.lookup(&tgid_goid);
  if (args == NULL) {
    return 0;
  }

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_read 2 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }

  probe_return_tls_conn_read_core(ctx, id, tgid, args);

  active_tls_conn_op_map.delete(&tgid_goid);

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_return_tls_conn_read 3 %lu %llu", tgid_goid.tgid, tgid_goid.goid);
  }
  return 0;
}

static __inline void* get_tls_wrap_for_memfn() {
  uint64_t id = bpf_get_current_pid_tgid();
  void** args = active_TLSWrap_memfn_this.lookup(&id);
  if (args == NULL) {
    return NULL;
  }
  return *args;
}

static __inline void update_node_ssl_tls_wrap_map(void* ssl) {
  void* tls_wrap = get_tls_wrap_for_memfn();
  if (tls_wrap == NULL) {
    return;
  }
  node_ssl_tls_wrap_map.update(&ssl, &tls_wrap);
}

int probe_ret_SSL_new(struct pt_regs* ctx) {
  void* ssl = (void*)PT_REGS_RC(ctx);
  if (ssl == NULL) {
    return 0;
  }
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;

  struct node_tlswrap_symaddrs_t* symaddrs = node_tlswrap_symaddrs_map.lookup(&tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  update_node_ssl_tls_wrap_map(ssl);

  return 0;
}

int probe_entry_TLSWrap_memfn(struct pt_regs* ctx) {
  void* tls_wrap = (void*)PT_REGS_PARM1(ctx);
  uint64_t id = bpf_get_current_pid_tgid();
  active_TLSWrap_memfn_this.update(&id, &tls_wrap);
  return 0;
}

int probe_ret_TLSWrap_memfn(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  active_TLSWrap_memfn_this.delete(&id);
  return 0;
}
