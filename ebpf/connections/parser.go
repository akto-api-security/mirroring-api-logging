package connections

import (
	"fmt"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

func tryReadFromBD(tracker *Tracker) {
	kafkaUtil.ParseAndProduce(tracker.recvBuf, tracker.sentBuf, "", 0, false, "MIRRORING")
	fmt.Printf("Conn bytes: %v Sent: %v , Recv: %v\n", tracker.sentBytes+tracker.recvBytes, tracker.sentBytes, tracker.recvBytes)
}
