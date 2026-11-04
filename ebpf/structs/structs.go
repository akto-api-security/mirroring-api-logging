package structs

// ConnID is the common prefix of every record on a socket_data_events_N ring.
type ConnID struct {
	Id   uint64
	Fd   uint32
	Kind uint32 // EventData / EventOpen / EventClose; zeroed in map keys
	// conn_start_ns
	Conn_start_ns uint64
	// this is destination port / remote port
	Port    uint16
	Padding [2]byte
	// this is destination IP / remote IP
	Ip uint32
}

// Record kinds (event_kind_t in module.bpf.c).
const (
	EventData  uint32 = 0
	EventOpen  uint32 = 1
	EventClose uint32 = 2
)

// Key returns the identity of the connection with the record kind and
// padding cleared, so open, data and close records map to the same entry.
func (c ConnID) Key() ConnID {
	return ConnID{Id: c.Id, Fd: c.Fd, Conn_start_ns: c.Conn_start_ns, Port: c.Port, Ip: c.Ip}
}

func ConnIDLogArgs(id ConnID) []any {
	return []any{"fd", id.Fd, "id", id.Id, "timestamp", id.Conn_start_ns, "ip", id.Ip, "port", id.Port}
}

/*
u64 id;
u32 fd;
u32 kind;
u64 conn_start_ns;
unsigned short port;
pad 2
u32 ip;
int bytes_sent;
u32 readEventsCount;
u32 writeEventsCount;
bool ssl;
pad 3
u32 lost;
u32 lost_run;
char msg[MAX_MSG_SIZE];   // starts at MsgPayloadOffset
*/
type SocketDataEventAttr struct {
	ConnId           ConnID
	Bytes_sent       int32
	ReadEventsCount  uint32
	WriteEventsCount uint32
	Ssl              bool
	_                [3]byte
	// Lost is how many bytes of this direction were not delivered right
	// before this chunk (ring full, failed read, chunk-limit cut, paused).
	Lost uint32
	// LostRun is the part of Lost that fell in this chunk's own run (since
	// the socket last changed direction). 0 means nothing of this run is
	// missing before this chunk.
	LostRun uint32
	// Laddr, Lport: the socket's local address (host-order port), as in the
	// open record, so it is known even without the open record.
	Laddr uint32
	Lport uint32
}

// MsgPayloadOffset is the byte offset of msg[] in socket_data_event_t (C
// layout); it equals the Go size of SocketDataEventAttr.
const MsgPayloadOffset = 64

// MAX_MSG_SIZE must match the C define in module.bpf.c (30720).

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
	// Final counters at close(); Lost* are bytes never delivered since the
	// last delivered chunk of each direction (a lost tail).
	ReadEventsCount  uint32
	WriteEventsCount uint32
	LostRead         uint32
	LostWrite        uint32
}
