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

func ConnIDLogArgs(id ConnID) []any {
	return []any{"fd", id.Fd, "id", id.Id, "timestamp", id.Conn_start_ns, "ip", id.Ip, "port", id.Port}
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

// MAX_MSG_SIZE must match the C define in module.bpf.c (32768).

type SocketDataEvent struct {
	Attr SocketDataEventAttr
	Msg  [32768]byte
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
