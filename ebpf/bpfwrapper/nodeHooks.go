package bpfwrapper

var (
	NodeSSLHooks = []Uprobe{
		{
			FunctionToHook: "SSL_new",
			HookName:       "probe_ret_SSL_new",
			Type:           ReturnType,
		},
	}

	NodeTLSMemHooks_12_3_1  = []Uprobe{
		{
			FunctionToHook: "_ZN4node7TLSWrapC2E",
			HookName:       "probe_entry_TLSWrap_memfn",
			Type:           EntryType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node7TLSWrapC2E",
			HookName:       "probe_ret_TLSWrap_memfn",
			Type:           ReturnType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node7TLSWrap7ClearInE",
			HookName:       "probe_entry_TLSWrap_memfn",
			Type:           EntryType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node7TLSWrap7ClearInE",
			HookName:       "probe_ret_TLSWrap_memfn",
			Type:           ReturnType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node7TLSWrap8ClearOutE",
			HookName:       "probe_entry_TLSWrap_memfn",
			Type:           EntryType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node7TLSWrap8ClearOutE",
			HookName:       "probe_ret_TLSWrap_memfn",
			Type:           ReturnType_Matching_Pre,
		},
	}
	NodeTLSMemHooks_15_0_0 = []Uprobe{
		{
			FunctionToHook: "_ZN4node6crypto7TLSWrapC2E",
			HookName:       "probe_entry_TLSWrap_memfn",
			Type:           EntryType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node6crypto7TLSWrapC2E",
			HookName:       "probe_ret_TLSWrap_memfn",
			Type:           ReturnType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node6crypto7TLSWrap7ClearInE",
			HookName:       "probe_entry_TLSWrap_memfn",
			Type:           EntryType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node6crypto7TLSWrap7ClearInE",
			HookName:       "probe_ret_TLSWrap_memfn",
			Type:           ReturnType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node6crypto7TLSWrap8ClearOutE",
			HookName:       "probe_entry_TLSWrap_memfn",
			Type:           EntryType_Matching_Pre,
		},
		{
			FunctionToHook: "_ZN4node6crypto7TLSWrap8ClearOutE",
			HookName:       "probe_ret_TLSWrap_memfn",
			Type:           ReturnType_Matching_Pre,
		},
	}
)
