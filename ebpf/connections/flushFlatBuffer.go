package connections

// This file is the OLD flat-buffer flush path (pre-msg_seq): it accumulates a
// connection's sent/recv bytes into Tracker.sentBuf/recvBuf (map[int][]byte,
// keyed by write/read event count) and, on close/inactivity, joins each into
// one contiguous buffer and dispatches it for parsing. This is the flat-buffer
// sibling of flushPairedRequests.go's msg_seq pairing + fragmentsToBytes join —
// same job, older mode, active only when UseMsgSeqFlush=false.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"

	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

// convertToSingleByteArr joins a flat sent/recv buffer (map[int][]byte, keyed
// by write/read event count) into one contiguous slice, in key order. The
// msg_seq path's equivalent is fragmentsToBytes (flushPairedRequests.go),
// which does the same contiguity/gap-detection over a []fragment instead.
func convertToSingleByteArr(bufMap map[int][]byte) []byte {

	if len(bufMap) == 0 {
		return make([]byte, 0)
	}

	var keys []int
	for k := range bufMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	// Append []byte values into a single slice
	var combined []byte

	kPrev := -1
	for _, k := range keys {
		if kPrev == -1 {
			// C sets read, write event count=0 only on new connection open
			// For requests arriving after a time gap on the same underlying connection the
			// read,write count will not be 1, they will simply continue from the last request
			// This can only be replicated when there is a time gap/inactivityThreshold between requests
			// on the same underlying connection
			if !sequenceCheckSkip && k != 1 {
				slog.Warn("Bad start sequence", "key", k, "value", string(bufMap[k]))
				break
			}
			kPrev = k
		} else {
			if kPrev+1 != k {
				slog.Warn("Missing sequence", "prev", kPrev, "current", k, "value", string(bufMap[k]), "prevValue", string(bufMap[kPrev]))
				utils.Pipeline.ChunkAssemblyGaps.Add(1)
				break
			}
			kPrev = k
		}
		combined = append(combined, bufMap[k]...)
	}

	return combined
}

// ProcessTrackerData flushes a Tracker's accumulated flat sent/recv buffers on
// close/inactivity: joins each into a contiguous blob and dispatches both
// directions for HTTP parsing. The msg_seq path's equivalent is
// ProcessSinglePair (flushPairedRequests.go).
func ProcessTrackerData(connID structs.ConnID, tracker *Tracker, isComplete bool) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	if len(tracker.sentBuf) == 0 || len(tracker.recvBuf) == 0 {
		return
	}
	receiveBuffer := convertToSingleByteArr(tracker.recvBuf)
	sentBuffer := convertToSingleByteArr(tracker.sentBuf)

	originalInt := uint32(connID.Raddr)
	// Convert integer to little-endian byte slice
	byteSlice := make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	// Convert the byte slice to an IP address
	ip := net.IP(byteSlice)
	raddrStr := ip.String() + ":" + fmt.Sprint(connID.Rport)

	originalInt = uint32(tracker.laddr)
	byteSlice = make([]byte, 4)
	binary.LittleEndian.PutUint32(byteSlice, originalInt)
	ip = net.IP(byteSlice)
	laddrStr := ip.String() + ":" + fmt.Sprint(tracker.lport)

	hostName := ""
	if kafkaUtil.PodInformerInstance != nil {
		hostName = kafkaUtil.PodInformerInstance.GetPodNameByProcessId(int32(connID.Id >> 32))
	}

	if len(sentBuffer) >= len(httpBytes) && (bytes.Equal(sentBuffer[:len(httpBytes)], httpBytes)) {
		tryReadFromBD(raddrStr, laddrStr, receiveBuffer, sentBuffer, isComplete, 1, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
	}
	if !disableEgress {
		// attempt to parse the egress as well by switching the recv and sent buffers.
		if len(receiveBuffer) >= len(httpBytes) && (bytes.Equal(receiveBuffer[:len(httpBytes)], httpBytes)) {
			tryReadFromBD(laddrStr, raddrStr, sentBuffer, receiveBuffer, isComplete, 2, connID.Id, connID.Fd, uniqueDaemonsetId, hostName)
		}
	}
}
