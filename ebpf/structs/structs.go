package structs

type ConnID struct {
	Id            uint64
	Fd            uint32
	Padding1      [4]byte
	Conn_start_ns uint64
	Port          uint16
	Padding       [2]byte
	Ip            uint32
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
	ConnId         ConnID
	Socket_open_ns uint64
}

type SocketCloseEvent struct {
	ConnId         ConnID
	Socket_open_ns uint64
}
