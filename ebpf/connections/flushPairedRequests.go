package connections

// This file owns the FLUSH/DISPATCH layer: turning a Tracker's completed
// msg_seq groups into contiguous byte blobs and dispatching them onward. The
// SEQUENCING algorithm itself (drainPairs, GetFlushablePairs,
// FlushRemainingPairs — deciding WHICH groups become a pair) stays on Tracker
// in tracker.go; this file only depends on Tracker's exported methods, never
// its private fields/mutex.

import (
	"bytes"
	"log/slog"
	"slices"
	"time"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	ebpfutils "github.com/akto-api-security/mirroring-api-logging/ebpf/utils"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// How often the flush routine checks for complete pairs. Sole consumer:
// startFlushRoutine, below.
var flushTickInterval = 500 * time.Millisecond

func init() {
	utils.InitVar("MSG_SEQ_FLUSH_TICK_INTERVAL", &flushTickInterval)
}

// fragment is one chunk of a message's payload: seq is rc (ingress) or wc
// (egress) — monotonic and unique per event, but chunks are NOT guaranteed to
// ARRIVE in seq order (per-CPU perf buffers), so fragments are appended in
// arrival order and sorted by seq at flush (see fragmentsToBytes). data is a
// zero-copy view into the retained kernel event bytes.
type fragment struct {
	seq  int
	data []byte
}

type msgSeqGroup struct {
	msgSeq    uint32
	direction uint32 // kEgress=0, kIngress=1
	// fragments holds this message's chunks in ARRIVAL order (not seq order).
	// A plain growable slice instead of map[int][]byte: keys (seq) are unique
	// and monotonic, so no map/hash/bucket machinery is needed — see
	// fragmentsToBytes for the sort-by-seq + gap check done at flush time.
	fragments []fragment
}

type MsgSeqPair struct {
	ReqGroup  *msgSeqGroup
	RespGroup *msgSeqGroup
}

// fragmentsToBytes joins a msgSeqGroup's fragments into one contiguous buffer,
// in seq order. fragments arrive in whatever order the per-CPU perf buffers
// deliver them (not necessarily seq order), so they're sorted here before
// joining — same contiguity/gap semantics as convertToSingleByteArr, just over
// a []fragment (unique, monotonic seq) instead of a map.
//
// slices.SortFunc (generics, Go 1.21+) instead of sort.Slice/sort.Sort:
// sort.Slice's reflect.Swapper and sort.Sort's interface conversion both box
// the slice header onto the heap (~1+ alloc/call, at ANY length). SortFunc is
// monomorphized for `fragment` at compile time — no boxing, zero allocations,
// still O(n log n) — needed since worst case is a ~1MB message split into many
// small writes (hundreds of fragments), not just the 1-per-message case a
// single small fixture produces.
func fragmentsToBytes(fragments []fragment) []byte {
	if len(fragments) == 0 {
		return make([]byte, 0)
	}

	slices.SortFunc(fragments, func(a, b fragment) int { return a.seq - b.seq })

	total := 0
	for _, f := range fragments {
		total += len(f.data)
	}
	combined := make([]byte, 0, total) // one allocation, sized exactly — no regrow/recopy passes

	kPrev := -1
	for _, f := range fragments {
		if kPrev == -1 {
			// C sets read, write event count=0 only on new connection open
			// For requests arriving after a time gap on the same underlying connection the
			// read,write count will not be 1, they will simply continue from the last request
			// This can only be replicated when there is a time gap/inactivityThreshold between requests
			// on the same underlying connection
			if !sequenceCheckSkip && f.seq != 1 {
				slog.Warn("Bad start sequence", "key", f.seq, "value", string(f.data))
				break
			}
			kPrev = f.seq
		} else {
			if kPrev+1 != f.seq {
				slog.Warn("Missing sequence", "prev", kPrev, "current", f.seq, "value", string(f.data))
				utils.Pipeline.ChunkAssemblyGaps.Add(1)
				break
			}
			kPrev = f.seq
		}
		combined = append(combined, f.data...)
	}

	return combined
}

func startFlushRoutine(connID structs.ConnID, tracker *Tracker, done <-chan struct{}) {
	ticker := time.NewTicker(flushTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pairs := tracker.GetFlushablePairs()
			for _, pair := range pairs {
				g1Blob := fragmentsToBytes(pair.ReqGroup.fragments)
				g2Blob := fragmentsToBytes(pair.RespGroup.fragments)

				if utils.IsMsgSeqLogsEnabled() {
					slog.Info("msg_seq: processing pair (tick)",
						"fd", connID.Fd,
						"g1_msg_seq", pair.ReqGroup.msgSeq,
						"g2_msg_seq", pair.RespGroup.msgSeq,
						"g1_bytes", len(g1Blob),
						"g2_bytes", len(g2Blob))
				}

				ProcessSinglePair(connID, tracker.laddr, tracker.lport, g1Blob, g2Blob)
			}
			if len(pairs) > 0 && utils.IsMsgSeqLogsEnabled() {
				slog.Info("msg_seq: flushed pairs (tick)",
					"fd", connID.Fd,
					"pairs_flushed", len(pairs))
			}

		case <-done:
			// Final flush of all remaining pairs before exit
			if utils.IsMsgSeqLogsEnabled() {
				slog.Info("msg_seq: flush routine exiting, final flush",
					"fd", connID.Fd,
					"remaining_groups", len(tracker.msgGroups))
			}
			flushAndProcessRemainingPairs(connID, tracker)
			return
		}
	}
}

func flushAndProcessRemainingPairs(connID structs.ConnID, tracker *Tracker) {
	pairs := tracker.FlushRemainingPairs()
	for _, pair := range pairs {
		g1Blob := fragmentsToBytes(pair.ReqGroup.fragments)
		g2Blob := fragmentsToBytes(pair.RespGroup.fragments)

		if utils.IsMsgSeqLogsEnabled() {
			slog.Info("msg_seq: processing remaining pair",
				"fd", connID.Fd,
				"g1_msg_seq", pair.ReqGroup.msgSeq,
				"g2_msg_seq", pair.RespGroup.msgSeq,
				"g1_bytes", len(g1Blob),
				"g2_bytes", len(g2Blob))
		}

		ProcessSinglePair(connID, tracker.laddr, tracker.lport, g1Blob, g2Blob)
	}
	if len(pairs) > 0 && utils.IsMsgSeqLogsEnabled() {
		slog.Info("msg_seq: flushed remaining pairs",
			"fd", connID.Fd,
			"pairs_flushed", len(pairs))
	}
}

// ProcessSinglePair processes one request-response pair from msg_seq groups.
func ProcessSinglePair(connID structs.ConnID, laddrVal uint32, lportVal uint16, g1Blob, g2Blob []byte) {

	raddrStr := ebpfutils.FormatAddr(connID.Raddr, connID.Rport)
	laddrStr := ebpfutils.FormatAddr(laddrVal, lportVal)
	hostName := ""
	if kafkaUtil.PodInformerInstance != nil {
		hostName = kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(connID.Id >> 32))
	}

	// Detect which blob is the response (starts with "HTTP")
	utils.Pipeline.PairsAttempted.Add(1)
	if len(g2Blob) >= len(httpBytes) && bytes.Equal(g2Blob[:len(httpBytes)], httpBytes) {
		// g1=request, g2=response (server ingress path)
		tryReadFromBD(raddrStr, laddrStr, g1Blob, g2Blob, true, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	} else if len(g1Blob) >= len(httpBytes) && bytes.Equal(g1Blob[:len(httpBytes)], httpBytes) {
		// g1=response, g2=request (client egress path)
		if !disableEgress {
			tryReadFromBD(laddrStr, raddrStr, g2Blob, g1Blob, true, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
		}
	} else {
		utils.Pipeline.PairsParseFailure.Add(1)
		if utils.IsMsgSeqLogsEnabled() {
			slog.Warn("msg_seq: neither blob starts with HTTP",
				"fd", connID.Fd,
				"g1_preview", string(g1Blob[:min(32, len(g1Blob))]),
				"g2_preview", string(g2Blob[:min(32, len(g2Blob))]))
		}
	}
}
