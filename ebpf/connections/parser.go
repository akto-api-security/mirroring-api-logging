package connections

import (
	"fmt"
	"os"
	"strings"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

var printToStdout bool

func init() {
	printToStdoutEnv := os.Getenv("PRINT_TRAFFIC_TO_STDOUT")
	printToStdout = len(printToStdoutEnv) > 0 && strings.EqualFold(printToStdoutEnv, "true")
}

func tryReadFromBD(ip string, destIp string, receiveBuffer []byte, sentBuffer []byte, isComplete bool, direction int, id uint64, fd uint32, daemonsetIdentifier, hostName string) {
	ctx := kafkaUtil.TrafficContext{
		SourceIP:            ip,
		DestIP:              destIp,
		VxlanID:             0,
		IsPending:           false,
		TrafficSource:       "MIRRORING",
		IsComplete:          isComplete,
		Direction:           direction,
		ProcessID:           uint32(id >> 32),
		SocketFD:            fd,
		DaemonsetIdentifier: daemonsetIdentifier,
		HostName:            hostName,
	}

	if printToStdout {
		// Print traffic summary to stdout instead of Kafka
		directionStr := "ingress"
		if direction == 2 {
			directionStr = "egress"
		}
		fmt.Printf("[TRAFFIC] direction=%s src=%s dst=%s processId=%d fd=%d daemon=%s host=%s complete=%v recvBytes=%d sentBytes=%d\n",
			directionStr, ip, destIp, uint32(id>>32), fd, daemonsetIdentifier, hostName, isComplete, len(receiveBuffer), len(sentBuffer))
		return
	}

	kafkaUtil.ParseAndProduce(receiveBuffer, sentBuffer, ctx)
}
