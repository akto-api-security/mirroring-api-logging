package utils

import (
	"strconv"
)

type HoursToCountMap map[int]int
type IncomingCounter struct {
	VxlanID               int
	Ip                    string
	BucketStartEpoch      int
	BucketEndEpoch        int
	PacketHoursToCountMap HoursToCountMap
}

func (i *IncomingCounter) IncomingCounterKey() string {
	return strconv.Itoa(i.VxlanID) + "_" + i.Ip + "_" + strconv.Itoa(i.BucketStartEpoch) + "_" + strconv.Itoa(i.BucketEndEpoch)
}

func GenerateIncomingCounter(vxlanID int, ip string) IncomingCounter {
	d, u := EpochDays()
	return IncomingCounter{VxlanID: vxlanID, Ip: ip, BucketStartEpoch: d, BucketEndEpoch: u, PacketHoursToCountMap: make(HoursToCountMap)}
}

func (i *IncomingCounter) Inc(value int) {
	roundedDown, _ := EpochHours()
	_, exists := i.PacketHoursToCountMap[roundedDown]
	if !exists {
		i.PacketHoursToCountMap[roundedDown] = 0
	}
	i.PacketHoursToCountMap[roundedDown] += value
}

func (i *IncomingCounter) Reset() {
	i.PacketHoursToCountMap = HoursToCountMap{}
}

type OutgoingCounter struct {
	VxlanID                 int
	Ip                      string
	Host                    string
	BucketStartEpoch        int
	BucketEndEpoch          int
	PacketHoursToCountMap   HoursToCountMap
	RequestsHoursToCountMap HoursToCountMap
}

func (o *OutgoingCounter) OutgoingCounterKey() string {
	return strconv.Itoa(o.VxlanID) + "_" + o.Ip + "_" + o.Host + "_" + strconv.Itoa(o.BucketStartEpoch) + "_" + strconv.Itoa(o.BucketEndEpoch)
}

func GenerateOutgoingCounter(vxlanID int, ip string, host string) OutgoingCounter {
	d, u := EpochDays()
	return OutgoingCounter{VxlanID: vxlanID, Ip: ip, Host: host, BucketStartEpoch: d, BucketEndEpoch: u, PacketHoursToCountMap: HoursToCountMap{}, RequestsHoursToCountMap: HoursToCountMap{}}
}

func (o *OutgoingCounter) Inc(packetValue int, requestValue int) {
	roundedDown, _ := EpochHours()
	_, exists1 := o.PacketHoursToCountMap[roundedDown]
	if !exists1 {
		o.PacketHoursToCountMap[roundedDown] = 0
	}
	o.PacketHoursToCountMap[roundedDown] += packetValue

	_, exists2 := o.RequestsHoursToCountMap[roundedDown]
	if !exists2 {
		o.RequestsHoursToCountMap[roundedDown] = 0
	}
	o.RequestsHoursToCountMap[roundedDown] += requestValue
}

func (o *OutgoingCounter) Reset() {
	o.PacketHoursToCountMap = HoursToCountMap{}
	o.RequestsHoursToCountMap = HoursToCountMap{}
}