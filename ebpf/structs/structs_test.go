package structs

import (
	"testing"
	"unsafe"
)

// TestSocketDataEventAttrLayout guards the wire layout shared with the C struct
// socket_data_event_t in kernel/module.cc. The payload (msg[]) begins right after
// the attr region, so MsgOffset MUST equal both the struct size and the byte just
// past Protocol. If C and Go drift, the zero-copy payload slice
// (kernelBytes[MsgOffset:]) silently reads garbage — fail loudly here instead.
func TestSocketDataEventAttrLayout(t *testing.T) {
	if got := unsafe.Sizeof(SocketDataEventAttr{}); got != MsgOffset {
		t.Fatalf("Sizeof(SocketDataEventAttr)=%d, want MsgOffset=%d", got, MsgOffset)
	}
	if MsgOffset != 72 {
		t.Fatalf("MsgOffset=%d, want 72 (after adding Protocol u32)", MsgOffset)
	}
	if got := unsafe.Offsetof(SocketDataEventAttr{}.Protocol); got != 68 {
		t.Fatalf("Offsetof(Protocol)=%d, want 68 (right after MsgSeq)", got)
	}
	if got := unsafe.Offsetof(SocketDataEventAttr{}.MsgSeq); got != 64 {
		t.Fatalf("Offsetof(MsgSeq)=%d, want 64", got)
	}
}
