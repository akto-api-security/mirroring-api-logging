
package structs

type ConnID struct {
	Id             uint64
	Fd             uint32
	Conn_start_ns  uint64
	Port           uint16
	Ip             uint32
}

type SocketDataEventAttr struct {
	ConnId         ConnID
	Bytes_sent     int64
}

/*
u64 id;
u32 fd;
u64 conn_start_ns;
unsigned short port;
u32 ip;
int bytes_sent;
char msg[MAX_MSG_SIZE];
*/

// MAX_MSG_SIZE is defined in C++ ebpf code.

type SocketDataEvent struct {
	Attr SocketDataEventAttr
	Msg            [30720]byte
}

type SocketOpenEvent struct {
	ConnId         ConnID
	Socket_open_ns uint64
}

type SocketCloseEvent struct {
	ConnId         ConnID
	Socket_open_ns uint64
}