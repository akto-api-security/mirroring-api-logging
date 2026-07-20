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

// SocketDataPayload is one socket_data perf sample: decoded attr plus an owned
// payload slice (one copy from the perf ring). Chunks are merged at flush in the tracker.
type SocketDataPayload struct {
	Attr SocketDataEventAttr
	Data []byte
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

// ConnInfoT matches the C struct conn_info_t layout for BPF map population
// C struct:
//
//	u64 id;
//	u32 fd;
//	u64 conn_start_ns;
//	unsigned short port;
//	u32 ip;
//	bool ssl;
//	u32 readEventsCount;
//	u32 writeEventsCount;
type ConnInfoT struct {
	Id              uint64
	Fd              uint32
	Padding1        [4]byte // alignment padding for conn_start_ns
	ConnStartNs     uint64
	Port            uint16
	Padding2        [2]byte // alignment padding for ip
	Ip              uint32
	Ssl             bool
	Padding3        [3]byte // alignment padding for readEventsCount
	ReadEventsCount  uint32
	WriteEventsCount uint32
}