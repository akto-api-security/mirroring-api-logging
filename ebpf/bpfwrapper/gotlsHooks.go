package bpfwrapper

var (
	// GoTLS entry probes use EntryType so cilium/ebpf resolves the symbol
	// directly via its own ELF parser (which handles Go's .gopclntab) and
	// attaches at the function entry with no explicit offset.
	//
	// EntryType_Matching_Suf relied on findMatchingSymbols (debug/elf.Symbols)
	// which does not find Go symbols — so the probe was never attached.
	// ReturnType_Matching_Suf_Addr with Addresses=[0] triggered a cilium/ebpf
	// edge case where Offset=0 was treated as "no offset" differently from a
	// plain symbol-name lookup, causing silent attachment failures.
	GoTlsHooks = []Uprobe{
		{
			FunctionToHook: "crypto/tls.(*Conn).Write",
			HookName:       "probe_entry_tls_conn_write",
			Type:           EntryType,
		},
		{
			FunctionToHook: "crypto/tls.(*Conn).Read",
			HookName:       "probe_entry_tls_conn_read",
			Type:           EntryType,
		},
	}

	GoTlsRetHooks = []Uprobe{
		{
			FunctionToHook: "crypto/tls.(*Conn).Write",
			HookName:       "probe_return_tls_conn_write",
			Type:           ReturnType_Matching_Suf_Addr,
		},
		{
			FunctionToHook: "crypto/tls.(*Conn).Read",
			HookName:       "probe_return_tls_conn_read",
			Type:           ReturnType_Matching_Suf_Addr,
		},
	}
)
