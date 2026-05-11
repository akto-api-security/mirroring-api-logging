package connections

import "github.com/akto-api-security/mirroring-api-logging/ebpf/structs"

// SocketDataPayload is one socket_data perf sample: small header + a single owned
// payload slice (one copy from the perf ring in the callback). The tracker stores
// references to Data in [][]byte until flush, avoiding a second copy into a fixed Msg buffer.
type SocketDataPayload struct {
	Attr structs.SocketDataEventAttr
	Data []byte
}
