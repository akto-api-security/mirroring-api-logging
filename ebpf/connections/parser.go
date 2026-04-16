package connections

import (
	"github.com/akto-api-security/mirroring-api-logging/ebpf/structs"
	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/kafkaUtil"
)

func tryReadFromBD(ip string, destIp string, receiveBuffer []byte, sentBuffer []byte, isComplete bool, direction int, id uint64, fd uint32, daemonsetIdentifier, hostName string, connID structs.ConnID) {
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
		ConnID: &kafkaUtil.TrafficConnID{
			ID:        connID.Id,
			Fd:        connID.Fd,
			Timestamp: connID.Conn_start_ns,
			Ip:        connID.Ip,
			Port:      connID.Port,
		},
	}
	kafkaUtil.ParseAndProduce(receiveBuffer, sentBuffer, ctx)
}
