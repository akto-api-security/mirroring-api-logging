package structs

type ConnID struct {
	Id            uint64
	Fd            uint32
	Padding1      [4]byte
	Conn_start_ns uint64
	// this is destination port / remote port
	Port    uint16
	Padding [2]byte
	// this is destination IP / remote IP
	Ip uint32
}

type SocketDataEventAttr struct {
	ConnId           ConnID
	Bytes_sent       int32
	ReadEventsCount  uint32
	WriteEventsCount uint32
	Ssl              bool
}

/*
u64 id;
u32 fd;
u64 conn_start_ns;
unsigned short port;
u32 ip;
int bytes_sent;
u32 readEventsCount;
u32 writeEventsCount;
char msg[MAX_MSG_SIZE];
*/

// MAX_MSG_SIZE is defined in C++ ebpf code.

type SocketDataEvent struct {
	Attr SocketDataEventAttr
	Msg  [30720]byte
}

type SocketOpenEvent struct {
	ConnId ConnID
	// source IP and port
	SrcIp          uint32
	SrcPort        uint16
	Padding        [2]byte
	Socket_open_ns uint64
}

type SocketCloseEvent struct {
	ConnId         ConnID
	Socket_open_ns uint64
}

// ProbeType represents whether the probe is an entry or a return.
type ProbeType int

const (
	EntryType ProbeType = iota
	ReturnType
	EntryType_Matching_Suf
	ReturnType_Matching_Suf_Addr
	EntryType_Matching_Pre
	ReturnType_Matching_Pre
)

type Kprobe struct {
	// The name of the function to hook.
	FunctionToHook string
	// The name of the hook function.
	HookName string
	// Whether a Kprobe or ret-Kprobe.
	Type ProbeType
	// Whether the function to hook is syscall or not.
	IsSyscall bool
}


// Uprobe represents a single uprobe hook.
type Uprobe struct {
	// The name of the function to hook.
	FunctionToHook string
	// The name of the hook function.
	HookName string
	// Whether an uprobe or ret-uprobe.
	Type ProbeType
	// Whether the function to hook is syscall or not.
	BinaryPath string
	Addresses  []uint64
}