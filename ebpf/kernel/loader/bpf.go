package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// BPFLoader holds the loaded BPF collection, attached links, and ring buffer reader.
type BPFLoader struct {
	Coll  *ebpf.Collection
	Links []link.Link
	RB    *ringbuf.Reader
}

// Must match enum trace_mode_t in module.bpf.c
const (
	TraceModeAll  uint32 = 0 // trace every process
	TraceModePid  uint32 = 1 // trace only PIDs in traced_pids map
	TraceModeComm uint32 = 2 // trace only comms in traced_comms map
)

// LoadOpts configures BPF loading and filtering.
// Mode is derived: pids set → TraceModePid, comms set → TraceModeComm, neither → TraceModeAll.
type LoadOpts struct {
	BpfObjPath          string
	TracePids           []uint32 // PIDs to trace (sets TraceModePid)
	TraceComms          []string // comm names to trace (sets TraceModeComm)
	Metrics             bool     // enable per-CPU metrics counters
	Debug               bool     // enable BPF kernel debug logs (bpf_printk)
	RingbufSize         uint32   // ring buffer size in bytes (0 = use BPF default, 4MB)
	MaxTrackedConns     uint32   // conn_info_map capacity (0 = use BPF default, 131072)
	MaxInflightSyscalls uint32   // temp map capacity for in-flight accept/connect (0 = use BPF default, 4096)
}

// LoadAndAttach loads the BPF object, configures filters, and attaches all probes.
func LoadAndAttach(bpfObjPath string) (*BPFLoader, error) {
	return LoadAndAttachWithOpts(LoadOpts{
		BpfObjPath: bpfObjPath,
		Metrics:    os.Getenv("ENABLE_BPF_METRICS") == "1",
		Debug:      os.Getenv("ENABLE_BPF_DEBUG") != "0", // default true
	})
}

func LoadAndAttachWithOpts(opts LoadOpts) (*BPFLoader, error) {
	spec, err := ebpf.LoadCollectionSpec(opts.BpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	// Set ENABLE_BPF_METRICS
	if v, ok := spec.Variables["ENABLE_BPF_METRICS"]; ok {
		if err := v.Set(opts.Metrics); err != nil {
			log.Printf("WARN: set ENABLE_BPF_METRICS: %v", err)
		}
	}
	if v, ok := spec.Variables["ENABLE_BPF_DEBUG"]; ok {
		if err := v.Set(opts.Debug); err != nil {
			log.Printf("WARN: set ENABLE_BPF_DEBUG: %v", err)
		}
	}
	if opts.Metrics {
		log.Println("Metrics enabled")
	}
	if opts.Debug {
		log.Println("Debug logs enabled (trace_pipe)")
	}

	// Set TRACE_MODE — must be before NewCollection (const volatile)
	traceMode := TraceModeAll
	if len(opts.TracePids) > 0 {
		traceMode = TraceModePid
	} else if len(opts.TraceComms) > 0 {
		traceMode = TraceModeComm
	}
	if v, ok := spec.Variables["TRACE_MODE"]; ok {
		if err := v.Set(traceMode); err != nil {
			return nil, fmt.Errorf("set TRACE_MODE: %w", err)
		}
	}

	// Override map sizes if specified
	if opts.RingbufSize > 0 {
		if ms, ok := spec.Maps["socket_control_events"]; ok {
			ms.MaxEntries = opts.RingbufSize
			log.Printf("Ring buffer size: %d MB", opts.RingbufSize/(1<<20))
		}
	}
	if opts.MaxTrackedConns > 0 {
		if ms, ok := spec.Maps["conn_info_map"]; ok {
			ms.MaxEntries = opts.MaxTrackedConns
			log.Printf("Max tracked connections: %d", opts.MaxTrackedConns)
		}
	}
	if opts.MaxInflightSyscalls > 0 {
		for _, name := range []string{"active_accept_args", "active_accept_sock", "active_connect_args", "active_connect_sock"} {
			if ms, ok := spec.Maps[name]; ok {
				ms.MaxEntries = opts.MaxInflightSyscalls
			}
		}
		log.Printf("Max inflight syscalls: %d", opts.MaxInflightSyscalls)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	// Populate filter maps based on trace mode
	switch traceMode {
	case TraceModeAll:
		log.Println("Tracing all processes")
	case TraceModePid:
		if m := coll.Maps["traced_pids"]; m != nil {
			for _, pid := range opts.TracePids {
				if err := m.Put(pid, uint8(1)); err != nil {
					log.Printf("WARN: add pid %d: %v", pid, err)
				} else {
					log.Printf("Tracing pid %d", pid)
				}
			}
		}
	case TraceModeComm:
		if m := coll.Maps["traced_comms"]; m != nil {
			for _, comm := range opts.TraceComms {
				var key [16]byte
				copy(key[:], comm)
				if err := m.Put(key, uint8(1)); err != nil {
					log.Printf("WARN: add comm %s: %v", comm, err)
				} else {
					log.Printf("Tracing comm %q", comm)
				}
			}
		}
	}

	loader := &BPFLoader{Coll: coll}

	// Attach tracepoints
	tps := map[string][2]string{
		"tp_sys_enter_accept4": {"syscalls", "sys_enter_accept4"},
		"tp_sys_enter_accept":  {"syscalls", "sys_enter_accept"},
		"tp_sys_exit_accept4":  {"syscalls", "sys_exit_accept4"},
		"tp_sys_exit_accept":   {"syscalls", "sys_exit_accept"},
		"tp_sys_enter_connect": {"syscalls", "sys_enter_connect"},
		"tp_sys_exit_connect":  {"syscalls", "sys_exit_connect"},
		"tp_sys_enter_close":   {"syscalls", "sys_enter_close"},
	}

	for progName, tp := range tps {
		prog, ok := coll.Programs[progName]
		if !ok {
			continue
		}
		l, err := link.Tracepoint(tp[0], tp[1], prog, nil)
		if err != nil {
			loader.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp[0], tp[1], err)
		}
		loader.Links = append(loader.Links, l)
	}

	// Attach fentry/fexit
	fexits := []string{
		"fexit_inet_csk_accept",
		"fexit_tcp_v4_connect",
		"fexit_tcp_v6_connect",
	}

	for _, progName := range fexits {
		prog, ok := coll.Programs[progName]
		if !ok {
			continue
		}
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			continue
		}
		loader.Links = append(loader.Links, l)
	}

	// Open ring buffer
	rb, err := ringbuf.NewReader(coll.Maps["socket_control_events"])
	if err != nil {
		loader.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	loader.RB = rb

	log.Printf("Attached %d probes", len(loader.Links))
	return loader, nil
}

// ReadEvent reads one ConnEvent from the ring buffer.
func (l *BPFLoader) ReadEvent() (ConnEvent, error) {
	record, err := l.RB.Read()
	if err != nil {
		return ConnEvent{}, err
	}
	var event ConnEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return ConnEvent{}, fmt.Errorf("decode: %w", err)
	}
	return event, nil
}

// Close cleans up all resources.
func (l *BPFLoader) Close() {
	if l.RB != nil {
		l.RB.Close()
	}
	for _, lnk := range l.Links {
		lnk.Close()
	}
	if l.Coll != nil {
		l.Coll.Close()
	}
}

// IPStr converts a u32 IP to dotted string.
func IPStr(ip uint32) string {
	return net.IP([]byte{
		byte(ip), byte(ip >> 8), byte(ip >> 16), byte(ip >> 24),
	}).String()
}

// PortToHost converts network byte order port to host.
func PortToHost(port uint16) uint16 {
	return (port>>8)&0xFF | (port&0xFF)<<8
}

// Must match enum metric_t in module.bpf.c
var MetricNames = []string{
	"conn_open",
	"conn_close",
	"ringbuf_drop",
	"accept_fexit_miss",
	"filtered",
	"connect_skip_non_tcp",
	"accept_failed",
	"connect_failed",
	"connmap_full",
}

// ReadMetrics reads all per-CPU counters and sums them.
func (l *BPFLoader) ReadMetrics() map[string]uint64 {
	result := make(map[string]uint64, len(MetricNames))
	m := l.Coll.Maps["metrics"]
	if m == nil {
		return result
	}

	for i, name := range MetricNames {
		key := uint32(i)
		var values []uint64
		if err := m.Lookup(key, &values); err != nil {
			continue
		}
		var total uint64
		for _, v := range values {
			total += v
		}
		result[name] = total
	}

	return result
}

// ParsePids parses a comma-separated list of PIDs.
func ParsePids(s string) []uint32 {
	if s == "" {
		return nil
	}
	var pids []uint32
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			log.Printf("WARN: invalid pid %q: %v", p, err)
			continue
		}
		pids = append(pids, uint32(v))
	}
	return pids
}

// ParseComms parses a comma-separated list of comm names.
func ParseComms(s string) []string {
	if s == "" {
		return nil
	}
	var comms []string
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			comms = append(comms, c)
		}
	}
	return comms
}
