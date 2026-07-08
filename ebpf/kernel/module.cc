#include <bcc/proto.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/sock.h>

#define socklen_t size_t
#define MAX_MSG_SIZE 30720
#define CHUNK_LIMIT CHUNK_SIZE_LIMIT
#define LOOP_LIMIT 10

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


static __inline enum message_type_t infer_http_message(const char* buf, size_t count) {
    if (count < 16) return kUnknown;
    char b[8];
    bpf_probe_read(&b, sizeof(b), buf);
    if (b[0]=='H' && b[1]=='T' && b[2]=='T' && b[3]=='P') return kResponse;
    if (b[0]=='G' && b[1]=='E' && b[2]=='T')               return kRequest;
    if (b[0]=='P' && b[1]=='O' && b[2]=='S' && b[3]=='T') return kRequest;
    if (b[0]=='P' && b[1]=='U' && b[2]=='T')               return kRequest;
    if (b[0]=='H' && b[1]=='E' && b[2]=='A' && b[3]=='D') return kRequest;
    if (b[0]=='D' && b[1]=='E' && b[2]=='L' && b[3]=='E') return kRequest;
    if (b[0]=='P' && b[1]=='A' && b[2]=='T' && b[3]=='C') return kRequest;
    return kUnknown;
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
    conn_info.role = isConnect ? kRoleClient : kRoleServer;

    conn_info.readEventsCount = 0;
    conn_info.writeEventsCount = 0;

    if (PRINT_BPF_LOGS) {
      u32 fd_assigned = isConnect ? args->fd : (u32)ret_fd;
      u32 dip = conn_info.raddr;
      u32 sip = srcIp;
      bpf_trace_printk("new_conn: type=%s", isConnect ? "connect" : "accept");
      bpf_trace_printk("new_conn: ret_fd=%d assigned_fd=%d", ret_fd, fd_assigned);
      bpf_trace_printk("new_conn: local_ip=%d.%d", (sip) & 0xFF, (sip >> 8) & 0xFF);
      bpf_trace_printk("new_conn: local_ip=%d.%d local_port=%d", (sip >> 16) & 0xFF, (sip >> 24) & 0xFF, lport);
      bpf_trace_printk("new_conn: remote_ip=%d.%d", (dip) & 0xFF, (dip >> 8) & 0xFF);
      bpf_trace_printk("new_conn: remote_ip=%d.%d remote_port=%d", (dip >> 16) & 0xFF, (dip >> 24) & 0xFF, bpf_ntohs(conn_info.rport));
      bpf_trace_printk("new_conn: role=%d", conn_info.role);
    }

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

static __inline void process_syscall_data(struct pt_regs* ret, const struct data_args_t* args, u64 id, bool is_send, bool ssl) {
    int bytes_exchanged = PT_REGS_RC(ret);

    if(args->iovlen > 0 && args->buf_size > 0){
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

    if (conn_info->role == kRoleUnknown && args->buf != NULL) {
        enum message_type_t msg_type = infer_http_message(args->buf, bytes_exchanged);
        if (msg_type != kUnknown) {
            conn_info->role = ((direction == kEgress) ^ (msg_type == kResponse))
                                  ? kRoleClient : kRoleServer;
        }
    }

    socket_data_event->role      = conn_info->role;
    socket_data_event->direction = direction;

    if (PRINT_BPF_LOGS){
      bpf_trace_printk("data_loop_start: pid=%d fd=%d total_bytes=%d", id >> 32, conn_info->fd, bytes_exchanged);
      u32 ip = conn_info->raddr;
      bpf_trace_printk("data: remote_ip=%d.%d", (ip) & 0xFF, (ip >> 8) & 0xFF);
      bpf_trace_printk("data: remote_ip=%d.%d port=%d", (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, bpf_ntohs(conn_info->rport));
      u32 sip = conn_info->laddr;
      bpf_trace_printk("data: local_ip=%d.%d", (sip) & 0xFF, (sip >> 8) & 0xFF);
      bpf_trace_printk("data: local_ip=%d.%d port=%d", (sip >> 16) & 0xFF, (sip >> 24) & 0xFF, conn_info->lport);
      bpf_trace_printk("data: role=%d direction=%d", conn_info->role, direction);
    }

    int bytes_sent = 0;
    size_t size_to_save = 0;
    int i =0;
  // #pragma unroll
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
        process_syscall_data(ret, args, id, is_send, false);
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
        process_syscall_data(ctx, read_args, id, false, false);
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
        process_syscall_data(ctx, write_args, id, true, false);
    }

    active_write_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_recv(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
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
        process_syscall_data(ctx, read_args, id, false, false);
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
      process_syscall_data(ctx, read_args, id, false, false);
    } else if (read_args != NULL) {
      if(PRINT_BPF_LOGS){
        bpf_trace_printk("syscall__probe_ret_read pid=%d fd=%d sock_event=0 skipping", id >> 32, read_args->fd);
      }
    }

    active_read_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_recvmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msghdr) {
    u64 id = bpf_get_current_pid_tgid();

    if (!should_trace_comm()) {
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
        process_syscall_data(ctx, write_args, id, true, false);
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
      process_syscall_data(ctx, write_args, id, true, false);
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