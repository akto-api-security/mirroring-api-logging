#include <bcc/proto.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/sock.h>

#define socklen_t size_t
#define MAX_MSG_SIZE 30720
#define LOOP_LIMIT 42

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

union sockaddr_t {
    struct sockaddr sa;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
};

struct accept_args_t {
    struct sockaddr* addr;
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
    bool ssl;
    int bytes_sent;
    u32 readEventsCount;
    u32 writeEventsCount;
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


static __inline u64 gen_tgid_fd(u32 tgid, int fd) {
  return ((u64)tgid << 32) | (u32)fd;
}

static __inline void process_syscall_accept(struct pt_regs* ret, const struct accept_args_t* args, u64 id, bool isConnect) {
    int ret_fd = PT_REGS_RC(ret);

    if(!isConnect && ret_fd < 0){
        return;
    }
    union sockaddr_t* addr;

    struct conn_info_t conn_info = {};
    bool socketConn = false;

    if(args->addr != NULL){
        addr = (union sockaddr_t*)args->addr;
    } else if(args->sock_alloc_socket !=NULL){
        socketConn = true;
        struct sock* sk = NULL;
        bpf_probe_read_kernel(&sk, sizeof(sk),  &(args->sock_alloc_socket)->sk);
        struct sock_common* sk_common = &sk->__sk_common;
        uint16_t family = -1;
        uint16_t lport = -1;
        u32 ip = 0;
        bpf_probe_read_kernel(&family, sizeof(family), &sk_common->skc_family);
        bpf_probe_read_kernel(&lport, sizeof(lport), &sk_common->skc_num);
        conn_info.port = lport;
        if (family == AF_INET) {
          bpf_probe_read_kernel(&(conn_info.ip), sizeof(conn_info.ip), &sk_common->skc_rcv_saddr);
        } else if (family == AF_INET6) {
          struct in6_addr in_addr;
          bpf_probe_read_kernel(&(in_addr), sizeof(in_addr), &sk_common->skc_v6_rcv_saddr);
          conn_info.ip = (in_addr.s6_addr32)[3];
        } else {
          return;
        }
    }

    if ( !socketConn && addr->sa.sa_family != AF_INET && addr->sa.sa_family != AF_INET6 ) {
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
        conn_info.port = sock_in->sin_port;
        struct in_addr *in_addr_ptr = &(sock_in->sin_addr);
        conn_info.ip = in_addr_ptr->s_addr;
    } else {
        struct sockaddr_in6* sock_in = (struct sockaddr_in6 *)addr;
        conn_info.port = sock_in->sin6_port;
        struct in6_addr *in_addr_ptr = &(sock_in->sin6_addr);
        conn_info.ip = (in_addr_ptr->s6_addr32)[3];
    }
    }

    conn_info.ssl = false;

    conn_info.readEventsCount = 0;
    conn_info.writeEventsCount = 0;

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
    socket_open_event.port = conn_info.port;
    socket_open_event.ip = conn_info.ip;

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
    socket_close_event.port = conn_info->port;
    socket_close_event.ip = conn_info->ip;

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

    if (PRINT_BPF_LOGS){
      bpf_trace_printk("SSL data 1 %d", id);
    }
    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    if (PRINT_BPF_LOGS){
      bpf_trace_printk("SSL data 2 %d %llu %lu", id, tgid_fd, tgid);
    }
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    if (PRINT_BPF_LOGS){
      bpf_trace_printk("SSL data 3 %d %llu %lu", id, tgid_fd, tgid);
    }
    
    if (conn_info->ssl != ssl) {
        return;
    }

    if (PRINT_BPF_LOGS){
      bpf_trace_printk("SSL data 4 %llu %llu %d", id, tgid_fd, ssl);
    }

    u32 kZero = 0;
    struct socket_data_event_t* socket_data_event = socket_data_event_buffer_heap.lookup(&kZero);
    if (socket_data_event == NULL) {
        return;
    }

    socket_data_event->id = conn_info->id;
    socket_data_event->fd = conn_info->fd;
    socket_data_event->conn_start_ns = conn_info->conn_start_ns;
    socket_data_event->port = conn_info->port;
    socket_data_event->ip = conn_info->ip; 
    socket_data_event->bytes_sent = is_send ? 1 : -1;
    socket_data_event->ssl = conn_info->ssl;

    if (is_send){
      conn_info->writeEventsCount = (conn_info->writeEventsCount) + 1u;
    } else {
      conn_info->readEventsCount = (conn_info->readEventsCount) + 1u;
    }

    socket_data_event->writeEventsCount = conn_info->writeEventsCount;
    socket_data_event->readEventsCount = conn_info->readEventsCount;


  if(PRINT_BPF_LOGS){
    bpf_trace_printk("pid: %d conn-id:%d, fd: %d", id, conn_info->id, conn_info->fd);
    unsigned long tdfd = ((id & 0xffff) << 32) + conn_info->fd;
    bpf_trace_printk("rwc: %d tdfd: %llu data: %s", (socket_data_event->readEventsCount*10000 + socket_data_event->writeEventsCount%10000),tgid_fd, socket_data_event->msg);
  }
    
    size_t bytes_exchanged_minus_1 = bytes_exchanged - 1;
    asm volatile("" : "+r"(bytes_exchanged_minus_1) :);
    bytes_exchanged = bytes_exchanged_minus_1 + 1;

    size_t size_to_save = 0;
    if (bytes_exchanged_minus_1 < MAX_MSG_SIZE) {
        bpf_probe_read(&socket_data_event->msg, bytes_exchanged, args->buf);
        size_to_save = bytes_exchanged;
        socket_data_event->msg[size_to_save] = '\\0';
    } else if (bytes_exchanged_minus_1 < 0x7fffffff) {
        bpf_probe_read(&socket_data_event->msg, MAX_MSG_SIZE, args->buf);
        size_to_save = MAX_MSG_SIZE;
    }

    
    socket_data_event->bytes_sent *= size_to_save;
    
    socket_data_events.perf_submit(ret, socket_data_event, sizeof(struct socket_data_event_t) - MAX_MSG_SIZE + size_to_save);

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

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_accept: pid: %d", id);
  }

    struct accept_args_t accept_args = {};
    accept_args.addr = addr;
    active_accept_args_map.update(&id, &accept_args);
    
    return 0;
}

int syscall__probe_ret_accept(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_accept: pid: %d", id);
  }

    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);

    if (accept_args != NULL) {
        process_syscall_accept(ctx, accept_args, id, false);
    }

    active_accept_args_map.delete(&id);
    return 0;
}

int probe_ret_sock_alloc(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  
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

int syscall__probe_entry_connect(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    u64 id = bpf_get_current_pid_tgid();

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_connect: pid: %d", id);
  }

    struct accept_args_t accept_args = {};
    accept_args.fd = sockfd;
    accept_args.addr = addr;
    active_accept_args_map.update(&id, &accept_args);
    
    return 0;
}

int syscall__probe_ret_connect(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_connect: pid: %d", id);
  }

    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);

    if (accept_args != NULL) {
        process_syscall_accept(ctx, accept_args, id, true);
    }

    active_accept_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_close(struct pt_regs* ctx, int fd) {
    u64 id = bpf_get_current_pid_tgid();

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_close: pid: %d", id);
  }

    struct close_args_t close_args = {};
    close_args.fd = fd;
    active_close_args_map.update(&id, &close_args);
    
    return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_close: pid: %d", id);
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

    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_writev: pid: %d", id);
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
  
    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_writev: pid: %d", id);
  }

    struct data_args_t* write_args = active_write_args_map.lookup(&id);
    if (write_args != NULL && write_args->sock_event) {
        if(PRINT_BPF_LOGS){
            bpf_trace_printk("syscall__probe_ret_writev data process: pid: %d", id);
        }
      process_syscall_data_vecs(ctx, write_args, id, true);
    }
    
    active_write_args_map.delete(&id);
    return 0;
  }

int syscall__probe_entry_sendmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msghdr){
    u64 id = bpf_get_current_pid_tgid();

	if (msghdr != NULL) {
      if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_sendmsg: pid: %d", id);
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

      if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_sendmsg: pid: %d", id);
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
  
      if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_readv: pid: %d", id);
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
  
    if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_readv: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    struct data_args_t* read_args_1 = active_read_args_map.lookup(&id);

    if (read_args_1 != NULL){
      bpf_trace_printk("syscall__probe_entry_recvfrom: pid: %llu fd: %d read args : %d", id, fd, read_args_1->fd);
    } else {
      bpf_trace_printk("syscall__probe_entry_recvfrom: pid: %llu fd: %d read args : NULL", id, fd);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_recvfrom: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
        struct data_args_t* write_args_1 = active_write_args_map.lookup(&id);

    if (write_args_1 != NULL) {
      bpf_trace_printk("syscall__probe_entry_sendto: pid: %llu fd: %d write args : %d", id, fd, write_args_1->fd);
    } else {
      bpf_trace_printk("syscall__probe_entry_sendto: pid: %llu fd: %d write args : NULL", id, fd);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_sendto: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_recv: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_recv: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
      struct data_args_t* read_args_1 = active_read_args_map.lookup(&id);

    if (read_args_1 != NULL)
    {
      bpf_trace_printk("syscall__probe_entry_read: pid: %llu fd: %d read args : %d", id, fd, read_args_1->fd);
    }
    else
    {
      bpf_trace_printk("syscall__probe_entry_read: pid: %llu fd: %d read args : NULL", id, fd);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_read: pid: %d", id);
  }

    struct data_args_t* read_args = active_read_args_map.lookup(&id);

    if (read_args != NULL && read_args->sock_event) {
        process_syscall_data(ctx, read_args, id, false, false);
    }

    active_read_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_recvmsg(struct pt_regs* ctx, int fd, struct user_msghdr* msghdr) {
    u64 id = bpf_get_current_pid_tgid();

	if (msghdr != NULL) {

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_recvmsg: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_recvmsg: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_send: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_send: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_entry_write: pid: %d", id);
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

  if(PRINT_BPF_LOGS){
    struct data_args_t* write_args_1 = active_write_args_map.lookup(&id);

    if (write_args_1 != NULL) {
      bpf_trace_printk("syscall__probe_ret_write: pid: %llu write args : %d", id, write_args_1->fd);
    } else {
      bpf_trace_printk("syscall__probe_ret_write: pid: %llu write args : NULL", id);
    }
  }

    struct data_args_t* write_args = active_write_args_map.lookup(&id);

    if (write_args != NULL && write_args->sock_event) {

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("syscall__probe_ret_write data process: pid: %d", id);
  }

    process_syscall_data(ctx, write_args, id, true, false);
    }

    active_write_args_map.delete(&id);
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
    conn_info->ssl = true;
}

static void probe_entry_SSL_write_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_write_core: pid: %d %d %d", id, tgid, fd);
  }

  char* bufc = (char*)PT_REGS_PARM2(ctx);

  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.buf = bufc;
  active_ssl_write_args_map.update(&id, &write_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, write_args.fd);
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
    process_syscall_data(ctx, write_args, id, true, true);
  }

  active_ssl_write_args_map.delete(&id);
  return 0;
}

static void probe_entry_SSL_read_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
    u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_SSL_read_core: pid: %d %d %d", id, tgid, fd);
  }

  char* bufc = (char*)PT_REGS_PARM2(ctx);

  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.buf = bufc;
  active_ssl_read_args_map.update(&id, &read_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, read_args.fd);
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
    process_syscall_data(ctx, read_args, id, false, true);
  }

  active_ssl_read_args_map.delete(&id);
  return 0;
}

// Trace kernel function:
// int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
// which is called by write/writev
int probe_entry_security_socket_sendmsg(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_security_socket_sendmsg: pid: %d", id);
  }
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    write_args->sock_event = true;
  }
  return 0;
}

// Trace kernel function:
// int security_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size)
int probe_entry_security_socket_recvmsg(struct pt_regs* ctx) {
  u64 id = bpf_get_current_pid_tgid();

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_security_socket_recvmsg: pid: %d", id);
  }
  
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    read_args->sock_event = true;
  }
  return 0;
}

int probe_entry_setsockopt(struct pt_regs* ctx, int socket, int level, int option_name,
       const void *option_value, socklen_t option_len) {
  u64 id = bpf_get_current_pid_tgid();

  if(PRINT_BPF_LOGS){
    bpf_trace_printk("probe_entry_setsockopt: pid: %d", id);
  }

  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    write_args->sock_event = true;
  }
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    read_args->sock_event = true;
  }
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

  process_syscall_data(ctx, &data_args, id, true, /* ssl */ true);

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

  process_syscall_data(ctx, &data_args, id, false, /* ssl */ true);

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