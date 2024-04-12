package bpfwrapper

var (
	SslHooks_1_0 = []Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_write_1_0",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_read_1_0",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
	}
	SslHooks_1_1 = []Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_write_1_1",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_read_1_1",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
	}
	SslHooks_3_0 = []Uprobe{
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_entry_SSL_write_3_0",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_entry_SSL_read_3_0",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
	}
	SslHooks_3_0_ex = []Uprobe{
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_entry_SSL_write_3_0",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_write_ex",
			HookName:       "probe_ret_SSL_write",
			Type:           ReturnType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_entry_SSL_read_3_0",
			Type:           EntryType,
		},
		{
			FunctionToHook: "SSL_read_ex",
			HookName:       "probe_ret_SSL_read",
			Type:           ReturnType,
		},
	}
)
