//go:build !windows

package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const bpfFilter = "tcp && not (port 9092 or port 22)"

// openLiveCapture opens the interface with libpcap. "any" captures all interfaces.
func openLiveCapture(interfaceName string) (<-chan gopacket.Packet, func(), error) {
	handle, err := pcap.OpenLive(interfaceName, 128*1024, true, pcap.BlockForever)
	if err != nil {
		return nil, nil, err
	}
	packets, err := pcapPackets(handle)
	if err != nil {
		handle.Close()
		return nil, nil, err
	}
	return packets, handle.Close, nil
}

func pcapPackets(handle *pcap.Handle) (<-chan gopacket.Packet, error) {
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil, err
	}
	return gopacket.NewPacketSource(handle, handle.LinkType()).Packets(), nil
}
