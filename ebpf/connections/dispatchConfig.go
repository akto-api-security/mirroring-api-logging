package connections

// Shared config for the flush/dispatch layer — consumed by BOTH
// flushFlatBuffer.go (old path) and flushPairedRequests.go (msg_seq path).
// Neither file owns these exclusively, so they live here rather than in
// either sibling.

import (
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"github.com/google/uuid"
)

var httpBytes = []byte("HTTP")

var sequenceCheckSkip = false

var disableEgress = false

// unique id of daemonset
var uniqueDaemonsetId = uuid.New().String()

func init() {
	utils.InitVar("AKTO_SKIP_SEQUENCE_CHECK", &sequenceCheckSkip)
	utils.InitVar("TRAFFIC_DISABLE_EGRESS", &disableEgress)
}
