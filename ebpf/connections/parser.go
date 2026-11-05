package connections

import (
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

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
	kafkaUtil.ParseAndProduce(receiveBuffer, sentBuffer, ctx)
}
