package fastparser

// Encoder turns a parsed request/response pair + Meta into a single contiguous
// frame. The returned bytes are a view into the encoder's reused buffer, valid
// only until the next Encode call on the same encoder. NOT concurrency-safe —
// one encoder per goroutine.
//
// Switching wire formats is a single string: NewEncoder("json" | "flatbuffers").
type Encoder interface {
	Encode(req *Request, resp *Response, m *Meta) []byte
}

// Both encoders satisfy the interface.
var (
	_ Encoder = (*JSONEncoder)(nil) // hand-rolled JSON
	_ Encoder = (*FBEncoder)(nil)   // FlatBuffers
)

// Encoders is the registry of available wire formats.
var Encoders = map[string]func() Encoder{
	"json":        func() Encoder { return NewJSONEncoder() },
	"flatbuffers": func() Encoder { return NewFBEncoder() },
}

// Meta holds the non-parsed fields (from TrafficContext + globals), shared by
// every encoder. Emitted as strings to match the legacy map[string]string payload.
type Meta struct {
	SourceIP      string // -> "ip"
	DestIP        string // -> "destIp"
	TimeUnix      int64  // -> "time"
	AktoAccountID string // -> "akto_account_id"
	VxlanID       int    // -> "akto_vxlan_id"
	IsPending     bool   // -> "is_pending"
	Source        string // -> "source"
	Direction     int    // -> "direction"
	ProcessID     uint32 // -> "process_id"
	SocketID      uint32 // -> "socket_id"
	DaemonsetID   string // -> "daemonset_id"
	ProcessName   string // -> "process_name"
	EnableGraph   bool   // -> "enable_graph"
	Tag           string // -> "tag" (omitted if empty)
}

// NewEncoder returns a fresh encoder for the named format, or nil if unknown.
func NewEncoder(kind string) Encoder {
	if f, ok := Encoders[kind]; ok {
		return f()
	}
	return nil
}

// ValidEncoder reports whether kind names a registered encoder.
func ValidEncoder(kind string) bool {
	_, ok := Encoders[kind]
	return ok
}
