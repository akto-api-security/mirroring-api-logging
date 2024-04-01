#include <bcc/proto.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/sock.h>

#define socklen_t size_t
#define MAX_MSG_SIZE 30720
#define LOOP_LIMIT 42

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
    int bytes_sent;
    u32 readEventsCount;
    u32 writeEventsCount;
    char msg[MAX_MSG_SIZE];
};

// u32 counter = 0;

BPF_HASH(conn_info_map, u64, struct conn_info_t, 131072); // 128 * 1024

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

static __inline u64 gen_tgid_fd(u32 tgid, int fd) {
  return ((u64)tgid << 32) | (u32)fd;
}


static __inline bool isMyIp(u32 ip) {
      return true;
}

static __inline void process_syscall_accept(struct pt_regs* ret, const struct accept_args_t* args, u64 id, bool isConnect) {
    int ret_fd = PT_REGS_RC(ret);

    if(!isConnect && ret_fd < 0){
        return;
    }
    union sockaddr_t* addr;

    if(args->addr != NULL){
        addr = (union sockaddr_t*)args->addr;
    } else {
        return;
    }

    if ( addr->sa.sa_family != AF_INET && addr->sa.sa_family != AF_INET6 ) {
        return;
    }

    struct conn_info_t conn_info = {};
    conn_info.id = id;
    if(isConnect){
        conn_info.fd = args->fd;
    } else {
        conn_info.fd = ret_fd;
    }
    conn_info.conn_start_ns = bpf_ktime_get_ns();

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

    if (!isMyIp(conn_info.ip)) {
      return;
    }

    conn_info.ssl = false;

    conn_info.readEventsCount = 0;
    conn_info.writeEventsCount = 0;

    u32 tgid = id >> 32;
    if(isConnect){
        u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
        conn_info_map.update(&tgid_fd, &conn_info);
    } else {
        u64 tgid_fd = gen_tgid_fd(tgid, ret_fd);
        conn_info_map.update(&tgid_fd, &conn_info);
    }

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

    if (!isMyIp(conn_info->ip)) {
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

    if (args->fd < 0) {
        return;
    }

    u32 tgid = id >> 32;
    u64 tgid_fd = gen_tgid_fd(tgid, args->fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    
    if (conn_info->ssl != ssl) {
        return;
    }

    if (!isMyIp(conn_info->ip)) {
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
    socket_data_event->port = conn_info->port;
    socket_data_event->ip = conn_info->ip; 
    socket_data_event->bytes_sent = is_send ? 1 : -1;

    if (is_send){
      conn_info->writeEventsCount = (conn_info->writeEventsCount) + 1u;
    } else {
      conn_info->readEventsCount = (conn_info->readEventsCount) + 1u;
    }

    socket_data_event->writeEventsCount = conn_info->writeEventsCount;
    socket_data_event->readEventsCount = conn_info->readEventsCount;


    // if(counter%50 == 0 ){
    //       bpf_trace_printk("pid abc: %d conn-id:%d, fd: %d", id, conn_info->id, conn_info->fd);
    // unsigned long tdfd = ((id & 0xffff) << 32) + conn_info->fd;
    // bpf_trace_printk("rwc abc: %d tdfd: %llu data: %s", (socket_data_event->readEventsCount*10000 + socket_data_event->writeEventsCount%10000),tgid_fd, socket_data_event->msg);
    // }
    //   counter = counter % 10000;
    //   counter++;
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

static u32 get_fd(void *ssl, bool isBoringSSL) {
    int32_t SSL_rbio_offset;
    int32_t RBIO_num_offset;
    
    if(isBoringSSL){
        SSL_rbio_offset = 0x18;
        RBIO_num_offset = 0x18;
    } else {
        SSL_rbio_offset = 0x10;
        RBIO_num_offset = RBIO_NUM_OFFSET;
    }

    const void** rbio_ptr_addr = ssl + SSL_rbio_offset;
    const void* rbio_ptr = *rbio_ptr_addr;
    const int* rbio_num_addr = rbio_ptr + RBIO_num_offset;
    u32 rbio_num = *rbio_num_addr;
    return rbio_num;
}

static void set_conn_as_ssl(u32 tgid, u32 fd){
    u64 tgid_fd = gen_tgid_fd(tgid, fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        return;
    }
    conn_info->ssl = true;
}

static void probe_entry_SSL_write_core(struct pt_regs *ctx, void *ssl, void *buf, int num, u32 fd){
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;

  char* bufc = (char*)PT_REGS_PARM2(ctx);

  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.buf = bufc;
  active_ssl_write_args_map.update(&id, &write_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, write_args.fd);
}

int probe_entry_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, false);
    probe_entry_SSL_write_core(ctx, ssl, buf, num, fd);
  return 0;
}

int probe_entry_SSL_write_boring(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u32 fd = get_fd(ssl, true);
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

  char* bufc = (char*)PT_REGS_PARM2(ctx);

  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.buf = bufc;
  active_ssl_read_args_map.update(&id, &read_args);

  // Mark connection as SSL right away, so encrypted traffic does not get traced.
  set_conn_as_ssl(tgid, read_args.fd);
}

int probe_entry_SSL_read(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, false);
    probe_entry_SSL_read_core(ctx, ssl, buf, num, fd);

  return 0;
}

int probe_entry_SSL_read_boring(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int32_t fd = get_fd(ssl, true);
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