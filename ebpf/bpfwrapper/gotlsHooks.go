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

	// GoTlsRetHooks is intentionally empty.  Return probes for crypto/tls.(*Conn).Write
	// and crypto/tls.(*Conn).Read are attached dynamically in ssl.TryGoTLSProbes using
	// ReturnType_Matching_Suf_Addr, which places a separate uprobe at every RET
	// instruction in the function body.  This is more reliable than a uretprobe for Go
	// binaries because Go's growable stacks can confuse the kernel's uretprobe trampoline.
	GoTlsRetHooks = []Uprobe{}
)
