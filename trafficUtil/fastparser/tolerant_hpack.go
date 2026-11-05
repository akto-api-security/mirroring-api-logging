package fastparser

// Tolerant HPACK decoding, for a connection the agent joined mid-stream.
//
// The stock decoder is all-or-nothing: one index it cannot resolve discards the
// whole header block, and the caller then abandons the connection. Joining an
// already-established connection guarantees unresolvable indices, because the
// peer's dynamic table was built from insertions we never saw. Pooled gRPC
// connections live for hours, so every one of them lands in exactly that state.
//
// Every HPACK representation is self-delimiting — its length is computable
// without resolving its value (RFC 7541 §6) — so an unresolvable index can be
// SKIPPED rather than being fatal. The static table and every literal still
// decode, which is what makes :method, :scheme, :status and any spelled-out
// header available from the first request.
//
// Correctness rests on three facts:
//
//  1. Dynamic indices count from the NEWEST entry (62) backwards. We witness
//     every insertion in the byte stream, in order, so our newest j entries are
//     the peer's newest j entries regardless of what is behind them.
//  2. An entry whose name came from an index that predates us has an unknowable
//     size (len(name)+len(value)+32), so our size accounting under-counts and we
//     evict LATER than the peer. That leaves extra stale entries at the tail,
//     which only a deeper index could reach — and the peer cannot send one,
//     having already evicted them. Over-counting would instead put an index out
//     of range, which is refused. Either way the error is never a wrong value.
//  3. The one thing that would break alignment is missing a block's insertions.
//     A block we cannot walk returns an error, and the caller abandons the
//     connection rather than drifting silently.
//
// Entries inserted with an unresolvable name are still inserted — positions must
// stay aligned with the peer — but flagged, and a later reference to one is
// reported unresolvable rather than emitted under an empty name.
//
// As the peer keeps inserting, every entry that predates us is evicted, after
// which every index it sends refers to something we watched go in. Measured on
// grpc-go, that takes roughly 30-180 requests depending on insertion rate.

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// TolerantHPACKEnabled turns the tolerant decoder on. Off by default: it changes
// which header sets reach the pipeline, so it is opted into per deployment.
var TolerantHPACKEnabled = strings.EqualFold(os.Getenv("AKTO_H2_TOLERANT_HPACK"), "true")

// hpackStaticTable is RFC 7541 Appendix A. Index i in HPACK is this[i-1].
var hpackStaticTable = [...]hpack.HeaderField{
	{Name: ":authority"}, {Name: ":method", Value: "GET"}, {Name: ":method", Value: "POST"},
	{Name: ":path", Value: "/"}, {Name: ":path", Value: "/index.html"},
	{Name: ":scheme", Value: "http"}, {Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "200"}, {Name: ":status", Value: "204"}, {Name: ":status", Value: "206"},
	{Name: ":status", Value: "304"}, {Name: ":status", Value: "400"}, {Name: ":status", Value: "404"},
	{Name: ":status", Value: "500"}, {Name: "accept-charset"},
	{Name: "accept-encoding", Value: "gzip, deflate"}, {Name: "accept-language"},
	{Name: "accept-ranges"}, {Name: "accept"}, {Name: "access-control-allow-origin"},
	{Name: "age"}, {Name: "allow"}, {Name: "authorization"}, {Name: "cache-control"},
	{Name: "content-disposition"}, {Name: "content-encoding"}, {Name: "content-language"},
	{Name: "content-length"}, {Name: "content-location"}, {Name: "content-range"},
	{Name: "content-type"}, {Name: "cookie"}, {Name: "date"}, {Name: "etag"},
	{Name: "expect"}, {Name: "expires"}, {Name: "from"}, {Name: "host"},
	{Name: "if-match"}, {Name: "if-modified-since"}, {Name: "if-none-match"},
	{Name: "if-range"}, {Name: "if-unmodified-since"}, {Name: "last-modified"},
	{Name: "link"}, {Name: "location"}, {Name: "max-forwards"},
	{Name: "proxy-authenticate"}, {Name: "proxy-authorization"}, {Name: "range"},
	{Name: "referer"}, {Name: "refresh"}, {Name: "retry-after"}, {Name: "server"},
	{Name: "set-cookie"}, {Name: "strict-transport-security"}, {Name: "transfer-encoding"},
	{Name: "user-agent"}, {Name: "vary"}, {Name: "via"}, {Name: "www-authenticate"},
}

type tolerantEntry struct {
	hf hpack.HeaderField
	// unknown marks a slot whose NAME came from an index that predates us. The
	// slot is kept so positions stay aligned with the peer's table, but it can
	// never be emitted, because we would be inventing the name.
	unknown bool
}

// TolerantDecoder holds one direction's dynamic table. Not concurrency-safe: it
// is owned by the connection that created it, like hpack.Decoder.
type TolerantDecoder struct {
	dyn     []tolerantEntry // index 0 == most recent == HPACK index 62
	size    uint32
	maxSize uint32

	// Unresolved counts representations skipped because their index predates us.
	// It falls to zero once the peer has evicted everything older than our join.
	Unresolved uint64
}

func NewTolerantDecoder(maxSize uint32) *TolerantDecoder {
	return &TolerantDecoder{maxSize: maxSize}
}

func tolerantEntrySize(f hpack.HeaderField) uint32 {
	return uint32(len(f.Name) + len(f.Value) + 32) // RFC 7541 §4.1
}

func (d *TolerantDecoder) insert(e tolerantEntry) {
	sz := tolerantEntrySize(e.hf)
	if sz > d.maxSize {
		d.dyn = d.dyn[:0] // RFC 7541 §4.4: an oversized entry empties the table
		d.size = 0
		return
	}
	d.dyn = append(d.dyn, tolerantEntry{})
	copy(d.dyn[1:], d.dyn)
	d.dyn[0] = e
	d.size += sz
	d.evict()
}

func (d *TolerantDecoder) evict() {
	for d.size > d.maxSize && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.size -= tolerantEntrySize(last.hf)
		d.dyn = d.dyn[:len(d.dyn)-1]
	}
}

// at resolves an HPACK index. ok is false when it names a dynamic entry inserted
// before we joined — the case that makes the stock decoder abort.
func (d *TolerantDecoder) at(i uint64) (hpack.HeaderField, bool) {
	if i == 0 {
		return hpack.HeaderField{}, false
	}
	if i <= uint64(len(hpackStaticTable)) {
		return hpackStaticTable[i-1], true
	}
	j := i - uint64(len(hpackStaticTable)) - 1
	if j >= uint64(len(d.dyn)) {
		return hpack.HeaderField{}, false // older than our join
	}
	if e := d.dyn[j]; !e.unknown {
		return e.hf, true
	}
	return hpack.HeaderField{}, false
}

// readInt decodes an N-bit-prefix integer (RFC 7541 §5.1).
func tolerantReadInt(b []byte, n uint8) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, fmt.Errorf("hpack: truncated integer")
	}
	mask := byte(1<<n) - 1
	v := uint64(b[0] & mask)
	b = b[1:]
	if v < uint64(mask) {
		return v, b, nil
	}
	var m uint
	for {
		if len(b) == 0 {
			return 0, nil, fmt.Errorf("hpack: truncated integer continuation")
		}
		c := b[0]
		b = b[1:]
		v += uint64(c&0x7f) << m
		if c&0x80 == 0 {
			break
		}
		if m += 7; m > 56 {
			return 0, nil, fmt.Errorf("hpack: integer overflow")
		}
	}
	return v, b, nil
}

// readString decodes a length-prefixed, optionally Huffman-coded string (§5.2).
func tolerantReadString(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, fmt.Errorf("hpack: truncated string")
	}
	huff := b[0]&0x80 != 0
	n, b, err := tolerantReadInt(b, 7)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(b)) < n {
		return "", nil, fmt.Errorf("hpack: string length %d exceeds %d remaining", n, len(b))
	}
	raw, rest := b[:n], b[n:]
	if huff {
		s, err := hpack.HuffmanDecodeToString(raw)
		if err != nil {
			return "", nil, err
		}
		return s, rest, nil
	}
	return string(raw), rest, nil
}

// readLiteral returns the field plus whether its NAME is known. The value is
// always a literal and so always parseable; only the name can be unresolvable.
func (d *TolerantDecoder) readLiteral(b []byte, prefix uint8) (hpack.HeaderField, bool, []byte, error) {
	idx, b, err := tolerantReadInt(b, prefix)
	if err != nil {
		return hpack.HeaderField{}, false, nil, err
	}
	var name string
	known := true
	if idx == 0 {
		if name, b, err = tolerantReadString(b); err != nil {
			return hpack.HeaderField{}, false, nil, err
		}
		// RFC 9113 8.2.1 forbids an empty field name. Treat it the same as an
		// unresolvable one: the peer still inserted it, so we must insert too to
		// stay aligned, but it can never be emitted.
		if name == "" {
			known = false
		}
	} else if f, ok := d.at(idx); ok {
		name = f.Name
	} else {
		// Name index predates us. The VALUE is still a literal and still
		// parseable, so consume it and keep walking; we just cannot label it.
		known = false
		d.Unresolved++
	}
	val, b, err := tolerantReadString(b)
	if err != nil {
		return hpack.HeaderField{}, false, nil, err
	}
	return hpack.HeaderField{Name: name, Value: val}, known, b, nil
}

// Decode parses a complete header block, emitting every field it can resolve.
// An unresolvable index is skipped, not fatal. A block whose representations
// cannot be delimited returns an error, because from that point the byte stream
// cannot be walked and our table would silently drift out of step with the peer.
func (d *TolerantDecoder) Decode(block []byte) ([]hpack.HeaderField, error) {
	var out []hpack.HeaderField
	b := block
	for len(b) > 0 {
		c := b[0]
		switch {
		case c&0x80 != 0: // 1xxxxxxx  indexed
			idx, rest, err := tolerantReadInt(b, 7)
			if err != nil {
				return out, err
			}
			b = rest
			if f, ok := d.at(idx); ok {
				out = append(out, f)
			} else {
				d.Unresolved++
			}

		case c&0xc0 == 0x40: // 01xxxxxx  literal with incremental indexing: INSERTS
			f, known, rest, err := d.readLiteral(b, 6)
			if err != nil {
				return out, err
			}
			b = rest
			// Insert even when the name was unresolvable: the peer inserted here
			// too, so our positions must stay aligned with its table.
			d.insert(tolerantEntry{hf: f, unknown: !known})
			if known {
				out = append(out, f)
			}

		case c&0xe0 == 0x20: // 001xxxxx  dynamic table size update
			n, rest, err := tolerantReadInt(b, 5)
			if err != nil {
				return out, err
			}
			b = rest
			if n > uint64(h2DefaultHeaderTable) {
				return out, fmt.Errorf("hpack: table size update %d exceeds max", n)
			}
			d.maxSize = uint32(n)
			d.evict()

		default: // 0000xxxx / 0001xxxx  literal without indexing / never indexed
			f, known, rest, err := d.readLiteral(b, 4)
			if err != nil {
				return out, err
			}
			b = rest
			if known {
				out = append(out, f)
			}
		}
	}
	return out, nil
}
