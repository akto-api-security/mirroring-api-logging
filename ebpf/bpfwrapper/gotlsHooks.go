package bpfwrapper

var (
	GoTlsHooks = []Uprobe{
		{
			FunctionToHook: "crypto/tls.(*Conn).Write",
			HookName:       "probe_entry_tls_conn_write",
			Type:           EntryType_Matching_Suf,
		},
		{
			FunctionToHook: "crypto/tls.(*Conn).Read",
			HookName:       "probe_entry_tls_conn_read",
			Type:           EntryType_Matching_Suf,
		},
	}

	GoTlsRetHooks = []Uprobe{
		{
			FunctionToHook: "crypto/tls.(*Conn).Write",
			HookName:       "probe_return_tls_conn_write",
			Type:           ReturnType_Matching_Suf,
		},
		{
			FunctionToHook: "crypto/tls.(*Conn).Read",
			HookName:       "probe_return_tls_conn_read",
			Type:           ReturnType_Matching_Suf,
		},
	}
)
