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
	_ Encoder = (*Builder)(nil)   // hand-rolled JSON
	_ Encoder = (*FBEncoder)(nil) // FlatBuffers
)

// Encoders is the registry of available wire formats.
var Encoders = map[string]func() Encoder{
	"json":        func() Encoder { return NewBuilder() },
	"flatbuffers": func() Encoder { return NewFBEncoder() },
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
