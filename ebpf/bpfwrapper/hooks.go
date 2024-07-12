package bpfwrapper

var (
	Level1hooks = []Kprobe{
		{
			FunctionToHook: "connect",
			HookName:       "syscall__probe_entry_connect",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "connect",
			HookName:       "syscall__probe_ret_connect",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept",
			HookName:       "syscall__probe_entry_accept",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept",
			HookName:       "syscall__probe_ret_accept",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_entry_accept",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "accept4",
			HookName:       "syscall__probe_ret_accept",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sock_alloc",
			HookName:       "probe_ret_sock_alloc",
			Type:           ReturnType,
			IsSyscall:      false,
		},
	}

	Level1hooksType2 = []Kprobe{
		{
			FunctionToHook: "security_socket_sendmsg",
			HookName:       "probe_entry_security_socket_sendmsg",
			Type:           EntryType,
			IsSyscall:      false,
		},
		{
			FunctionToHook: "security_socket_recvmsg",
			HookName:       "probe_entry_security_socket_recvmsg",
			Type:           EntryType,
			IsSyscall:      false,
		},
		{
			FunctionToHook: "setsockopt",
			HookName:       "probe_entry_setsockopt",
			Type:           EntryType,
			IsSyscall:      true,
		},
	}

	Level2hooks = []Kprobe{
		{
			FunctionToHook: "recvfrom",
			HookName:       "syscall__probe_entry_recvfrom",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recvfrom",
			HookName:       "syscall__probe_ret_recvfrom",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recv",
			HookName:       "syscall__probe_entry_recv",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recv",
			HookName:       "syscall__probe_ret_recv",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_entry_read",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_ret_read",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "readv",
			HookName:       "syscall__probe_entry_readv",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "readv",
			HookName:       "syscall__probe_ret_readv",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recvmsg",
			HookName:       "syscall__probe_entry_recvmsg",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recvmsg",
			HookName:       "syscall__probe_ret_recvmsg",
			Type:           ReturnType,
			IsSyscall:      true,
		},
	}

	Level2hooksEgress = []Kprobe{
		{
			FunctionToHook: "sendto",
			HookName:       "syscall__probe_entry_recvfrom",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sendto",
			HookName:       "syscall__probe_ret_recvfrom",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "send",
			HookName:       "syscall__probe_entry_recv",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "send",
			HookName:       "syscall__probe_ret_recv",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_entry_read",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_ret_read",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "writev",
			HookName:       "syscall__probe_entry_readv",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "writev",
			HookName:       "syscall__probe_ret_readv",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sendmsg",
			HookName:       "syscall__probe_entry_recvmsg",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sendmsg",
			HookName:       "syscall__probe_ret_recvmsg",
			Type:           ReturnType,
			IsSyscall:      true,
		},
	}

	Level3hooks = []Kprobe{
		{
			FunctionToHook: "sendto",
			HookName:       "syscall__probe_entry_sendto",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sendto",
			HookName:       "syscall__probe_ret_sendto",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "send",
			HookName:       "syscall__probe_entry_send",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "send",
			HookName:       "syscall__probe_ret_send",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_entry_write",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "write",
			HookName:       "syscall__probe_ret_write",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "writev",
			HookName:       "syscall__probe_entry_writev",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "writev",
			HookName:       "syscall__probe_ret_writev",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sendmsg",
			HookName:       "syscall__probe_entry_sendmsg",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "sendmsg",
			HookName:       "syscall__probe_ret_sendmsg",
			Type:           ReturnType,
			IsSyscall:      true,
		},
	}

	Level3hooksEgress = []Kprobe{
		{
			FunctionToHook: "recvfrom",
			HookName:       "syscall__probe_entry_sendto",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recvfrom",
			HookName:       "syscall__probe_ret_sendto",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recv",
			HookName:       "syscall__probe_entry_send",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recv",
			HookName:       "syscall__probe_ret_send",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_entry_write",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "read",
			HookName:       "syscall__probe_ret_write",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "readv",
			HookName:       "syscall__probe_entry_writev",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "readv",
			HookName:       "syscall__probe_ret_writev",
			Type:           ReturnType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recvmsg",
			HookName:       "syscall__probe_entry_sendmsg",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "recvmsg",
			HookName:       "syscall__probe_ret_sendmsg",
			Type:           ReturnType,
			IsSyscall:      true,
		},
	}

	Level4hooks = []Kprobe{
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_entry_close",
			Type:           EntryType,
			IsSyscall:      true,
		},
		{
			FunctionToHook: "close",
			HookName:       "syscall__probe_ret_close",
			Type:           ReturnType,
			IsSyscall:      true,
		},
	}

	SslHooks = []Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_write",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_read",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_entry_SSL_write",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_entry_SSL_read",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
	}

	SslHooksEgress = []Uprobe{
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_write",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_read",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_entry_SSL_write",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_entry_SSL_read",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
	}

	BoringsslHooks = []Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_write_boring",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_read_boring",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
	}
)
