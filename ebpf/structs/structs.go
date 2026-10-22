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
	Protocol         uint32  // protocol_t: kernel classification verdict (0=unknown,1=http,2=http2,3=tls,4=other)
}

// MsgOffset is the byte offset at which the payload (msg[]) begins inside a
// submitted socket_data_event record. Adding Protocol (u32) after MsgSeq fills
// the former 4-byte trailing pad, so now unsafe.Sizeof(SocketDataEventAttr) == 72
// == MsgOffset (no dropped padding). Kept next to the attr struct so the two stay
// in sync if the layout ever changes; asserted in structs_test.go.
const MsgOffset = 72

// endpoint_role_t (from kernel/module.cc): whether the traced process is the
// client (did connect) or server (did accept) on a connection. Populated on
// SocketDataEventAttr.Role.
const (
	RoleUnknown uint32 = 0
	RoleClient  uint32 = 1
	RoleServer  uint32 = 2
)

// protocol_t (from kernel/module.cc classify_protocol): the wire-protocol verdict
// stamped on SocketDataEventAttr.Protocol. HTTP2 covers gRPC (the grpc-vs-h2 split
// happens in the parser). TLS is a transient handshake state; the plaintext is
// reclassified to HTTP/HTTP2 after the SSL flip.
const (
	ProtoUnknown uint32 = 0
	ProtoHTTP1   uint32 = 1
	ProtoHTTP2   uint32 = 2
	ProtoTLS     uint32 = 3
	ProtoOther   uint32 = 4
)

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
	Protocol         uint32 // protocol_t: kernel classification verdict; 0 for prefilled conns (reclassified on first data)
}
