package fastparser

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func encodeBlock(t *testing.T, enc *hpack.Encoder, buf *bytes.Buffer, fields []hpack.HeaderField) []byte {
	t.Helper()
	buf.Reset()
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	return append([]byte(nil), buf.Bytes()...)
}

func fieldMap(fs []hpack.HeaderField) map[string]string {
	m := make(map[string]string, len(fs))
	for _, f := range fs {
		m[f.Name] = f.Value
	}
	return m
}

func TestStaticTableAndLiteralsDecodeWithoutAnyDynamicState(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	block := encodeBlock(t, enc, &buf, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/svc/Method"},
	})

	got, err := NewTolerantDecoder(h2DefaultHeaderTable).Decode(block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := fieldMap(got)
	if m[":method"] != "POST" || m[":scheme"] != "http" || m[":path"] != "/svc/Method" {
		t.Fatalf("want method/scheme/path, got %v", m)
	}
}

// Joining mid-stream must never be fatal, and must never invent a value.
func TestMidStreamJoinSkipsUnresolvableIndicesInsteadOfFailing(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	// The encoder builds a dynamic table the joiner never saw.
	for i := 0; i < 5; i++ {
		encodeBlock(t, enc, &buf, []hpack.HeaderField{
			{Name: "x-trace", Value: fmt.Sprintf("v%d", i)},
			{Name: ":authority", Value: "svc.internal"},
		})
	}
	// This block references those entries by index.
	block := encodeBlock(t, enc, &buf, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":authority", Value: "svc.internal"},
	})

	got, err := NewTolerantDecoder(h2DefaultHeaderTable).Decode(block)
	if err != nil {
		t.Fatalf("a mid-stream join must not be fatal, got %v", err)
	}
	for _, f := range got {
		if f.Name == "" {
			t.Fatalf("emitted a field with no name: %+v", got)
		}
	}
	if m := fieldMap(got); m[":method"] != "POST" {
		t.Fatalf(":method comes from the static table and must survive, got %v", m)
	}
}

// The property that matters: across a long connection joined at every possible
// offset, the decoder may omit fields but must never report a wrong value.
func TestNeverEmitsAValueThePeerDidNotSend(t *testing.T) {
	const blocks = 200
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)

	wire := make([][]byte, 0, blocks)
	truth := make([]map[string]string, 0, blocks)
	for i := 0; i < blocks; i++ {
		fs := []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "http"},
			{Name: ":path", Value: fmt.Sprintf("/pkg.Svc/M%02d", i%20)},
			{Name: ":authority", Value: "svc.internal:8080"},
			{Name: "content-type", Value: "application/grpc"},
			{Name: "x-request-id", Value: fmt.Sprintf("req-%d", i)},
		}
		wire = append(wire, encodeBlock(t, enc, &buf, fs))
		truth = append(truth, fieldMap(fs))
	}

	for join := 0; join < blocks; join += 7 {
		d := NewTolerantDecoder(h2DefaultHeaderTable)
		for i := join; i < blocks; i++ {
			got, err := d.Decode(wire[i])
			if err != nil {
				t.Fatalf("join=%d block=%d: %v", join, i, err)
			}
			for _, f := range got {
				if f.Name == "" {
					t.Fatalf("join=%d block=%d: nameless field", join, i)
				}
				if want, ok := truth[i][f.Name]; ok && want != f.Value {
					t.Fatalf("join=%d block=%d: WRONG %s=%q, peer sent %q",
						join, i, f.Name, f.Value, want)
				}
			}
		}
	}
}

// Once the peer has evicted everything older than the join, recovery is total.
func TestConvergesToFullRecoveryOnceTheTableTurnsOver(t *testing.T) {
	const blocks = 400
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	wire := make([][]byte, 0, blocks)
	for i := 0; i < blocks; i++ {
		wire = append(wire, encodeBlock(t, enc, &buf, []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":path", Value: "/pkg.Svc/Method"},
			{Name: ":authority", Value: "svc.internal:8080"},
			{Name: "x-request-id", Value: fmt.Sprintf("req-%d", i)},
		}))
	}
	d := NewTolerantDecoder(h2DefaultHeaderTable)
	lastMissing := -1
	for i := blocks / 2; i < blocks; i++ {
		got, err := d.Decode(wire[i])
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		if _, ok := fieldMap(got)[":path"]; !ok {
			lastMissing = i
		}
	}
	if lastMissing == blocks-1 {
		t.Fatal(":path never recovered; the table never turned over")
	}
	t.Logf("joined at %d, last block missing :path was %d", blocks/2, lastMissing)
}

func TestUndecodableBlockIsReportedSoTheConnectionIsAbandoned(t *testing.T) {
	for name, block := range map[string][]byte{
		"truncated literal length": {0x40, 0x7f},
		"string longer than block": {0x00, 0x7f, 0x05, 'a'},
		"truncated integer":        {0x1f},
	} {
		if _, err := NewTolerantDecoder(h2DefaultHeaderTable).Decode(block); err == nil {
			t.Fatalf("%s: expected an error so the caller abandons the connection", name)
		}
	}
}

func TestOversizedEntryEmptiesTheTable(t *testing.T) {
	d := NewTolerantDecoder(64)
	d.insert(tolerantEntry{hf: hpack.HeaderField{Name: "a", Value: "b"}})
	if len(d.dyn) != 1 {
		t.Fatalf("want 1 entry, got %d", len(d.dyn))
	}
	d.insert(tolerantEntry{hf: hpack.HeaderField{Name: "big", Value: string(make([]byte, 128))}})
	if len(d.dyn) != 0 || d.size != 0 {
		t.Fatalf("RFC 7541 4.4: oversized entry must empty the table, got %d entries", len(d.dyn))
	}
}

// The walker parses attacker-influenced bytes; it may error but must not panic.
func FuzzTolerantDecode(f *testing.F) {
	f.Add([]byte{0x82, 0x86, 0x84})
	f.Add([]byte{0x40, 0x02, 'a', 'b', 0x01, 'c'})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f})
	f.Add([]byte{0x20})
	// Found by the fuzzer: a literal whose name is a zero-length string. RFC 9113
	// 8.2.1 forbids an empty field name, and emitting one injects a nameless
	// header into the pipeline.
	f.Add([]byte{0x40, 0x00, 0x01, 0x30})
	f.Fuzz(func(t *testing.T, b []byte) {
		d := NewTolerantDecoder(h2DefaultHeaderTable)
		fields, err := d.Decode(b)
		if err == nil {
			for _, hf := range fields {
				if hf.Name == "" {
					t.Fatalf("emitted a nameless field from %x", b)
				}
			}
		}
	})
}
