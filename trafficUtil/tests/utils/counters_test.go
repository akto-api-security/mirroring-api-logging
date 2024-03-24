package utils

import (
	"strconv"
	"testing"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
)

func TestIncomingCounterKey(t *testing.T) {
	ip := "ip1"
	vxlanID := 100
	s, e := 1000, 2000

	ic := utils.IncomingCounter{VxlanID: vxlanID, Ip: ip, BucketStartEpoch: s, BucketEndEpoch: e, PacketHoursToCountMap: utils.HoursToCountMap{}}

	key := ic.IncomingCounterKey()
	key1 := strconv.Itoa(vxlanID) + "_" + ip + "_" + strconv.Itoa(s) + "_" + strconv.Itoa(e)

	if key != key1 {
		t.Errorf("Key mismatch key(%s) and key1(%s)", key, key1)
	}
}

func TestIncomingCounterIncAndReset(t *testing.T) {

	ic := utils.GenerateIncomingCounter(0, "ip")

	if len(ic.PacketHoursToCountMap) != 0 {
		t.Error("Map not empty")
	}

	ic.Inc(10)

	if len(ic.PacketHoursToCountMap) != 1 {
		t.Error("Map empty")
	}

	for _, value := range ic.PacketHoursToCountMap {
		if value != 10 {
			t.Errorf("Invalid value %d", value)
		}
	}

	ic.Inc(20)

	if len(ic.PacketHoursToCountMap) != 1 {
		t.Error("Map empty")
	}

	for _, value := range ic.PacketHoursToCountMap {
		if value != 30 {
			t.Errorf("Invalid value %d", value)
		}
	}

	ic.Reset()

	if len(ic.PacketHoursToCountMap) != 0 {
		t.Errorf("Map not empty after reset: %d", len(ic.PacketHoursToCountMap))
	}
}

func TestOutgoingCounterKey(t *testing.T) {
	ip := "ip1"
	vxlanID := 100
	s, e := 1000, 2000
	host := "host1"

	ic := utils.OutgoingCounter{VxlanID: vxlanID, Host: host, Ip: ip, BucketStartEpoch: s, BucketEndEpoch: e, PacketHoursToCountMap: utils.HoursToCountMap{}}

	key := ic.OutgoingCounterKey()
	key1 := strconv.Itoa(vxlanID) + "_" + ip + "_" + host + "_" + strconv.Itoa(s) + "_" + strconv.Itoa(e)

	if key != key1 {
		t.Errorf("Key mismatch key(%s) and key1(%s)", key, key1)
	}
}

func TestOutgoingCounterIncAndReset(t *testing.T) {

	oc := utils.GenerateOutgoingCounter(0, "ip1", "host1")

	if len(oc.PacketHoursToCountMap) != 0 {
		t.Error("Map not empty")
	}

	oc.Inc(10, 1)

	if len(oc.PacketHoursToCountMap) != 1 {
		t.Error("Packet Map empty")
	}

	if len(oc.RequestsHoursToCountMap) != 1 {
		t.Error(" Map empty")
	}

	for _, value := range oc.PacketHoursToCountMap {
		if value != 10 {
			t.Errorf("Invalid value %d", value)
		}
	}

	for _, value := range oc.RequestsHoursToCountMap {
		if value != 1 {
			t.Errorf("Invalid value %d", value)
		}
	}

	oc.Inc(20, 2)

	if len(oc.PacketHoursToCountMap) != 1 {
		t.Error("Map empty")
	}

	for _, value := range oc.PacketHoursToCountMap {
		if value != 30 {
			t.Errorf("Invalid value %d", value)
		}
	}

	for _, value := range oc.RequestsHoursToCountMap {
		if value != 3 {
			t.Errorf("Invalid value %d", value)
		}
	}

	oc.Reset()

	if len(oc.PacketHoursToCountMap) != 0 {
		t.Error("Map not empty after reset ")
	}

	if len(oc.RequestsHoursToCountMap) != 0 {
		t.Error("Map not empty after reset ")
	}
}
