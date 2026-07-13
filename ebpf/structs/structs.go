package structs

type ConnID struct {
	Id            uint64
	Fd            uint32
	Padding1      [4]byte
	Conn_start_ns uint64
	// remote port
	Rport   uint16
	Padding [2]byte
	// remote IP
	Raddr uint32
}

type SocketDataEventAttr struct {
	ConnId           ConnID
	Laddr            uint32
	Lport            uint16
	Padding2         [2]byte
	Bytes_sent       int32
	ReadEventsCount  uint32
	WriteEventsCount uint32
	Ssl              bool
	Padding3         [3]byte // alignment padding before role
	Role             uint32  // endpoint_role_t: 0=unknown, 1=client, 2=server
	Direction        uint32  // traffic_direction_t: 0=egress, 1=ingress
	MsgSeq           uint32  // msg_seq: increments on direction change
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
	// local IP and port
	Laddr          uint32
	Lport          uint16
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
	Id               uint64
	Fd               uint32
	Padding1         [4]byte // alignment padding for conn_start_ns
	ConnStartNs      uint64
	Rport            uint16
	Padding2         [2]byte // alignment padding for raddr
	Raddr            uint32
	Laddr            uint32
	Lport            uint16
	Ssl              bool
	Padding3         [1]byte // alignment padding for readEventsCount
	ReadEventsCount  uint32
	WriteEventsCount uint32
	Role             uint32 // endpoint_role_t: 0=unknown, 1=client, 2=server
	MsgSeq           uint32 // msg_seq: persisted for conntrack prefill
	PrevDirection    uint32 // prev_direction: persisted for conntrack prefill
}
