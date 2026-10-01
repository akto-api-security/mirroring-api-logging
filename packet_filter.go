package main

import (
	"encoding/binary"

	"github.com/google/gopacket/layers"
)

// Packet checks for the Windows capture, which has no libpcap and so no BPF filter. They don't
// depend on Windows so they can be tested anywhere.

// same ports as the libpcap BPF filter in capture_pcap.go
var excludedPorts = map[uint16]bool{9092: true, 22: true}

// hasIPv6Header reports whether data starts with an IPv6 header: a known next header, and a
// payload length that matches the rest of the packet, or is 0 for large send offload
func hasIPv6Header(data []byte) bool {
	if len(data) < 40 || data[0]>>4 != 6 {
		return false
	}
	next := layers.IPProtocol(data[6])
	switch next {
	case layers.IPProtocolTCP, layers.IPProtocolUDP, layers.IPProtocolICMPv6, layers.IPProtocolNoNextHeader,
		layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Routing, layers.IPProtocolIPv6Fragment, layers.IPProtocolIPv6Destination:
	default:
		return false
	}
	length := int(binary.BigEndian.Uint16(data[4:6]))
	if length == 0 {
		// see fixIPv6OffloadLength
		return next != layers.IPProtocolIPv6HopByHop
	}
	return length == len(data)-40
}

// fixIPv6OffloadLength fills in the payload length of outgoing packets that the network card
// segments itself (large send offload). Windows hands those over with a length of 0, which
// gopacket rejects. It already handles the same case for IPv4.
func fixIPv6OffloadLength(data []byte) {
	if binary.BigEndian.Uint16(data[4:6]) == 0 && data[6] != uint8(layers.IPProtocolIPv6HopByHop) && len(data)-40 <= 0xffff {
		binary.BigEndian.PutUint16(data[4:6], uint16(len(data)-40))
	}
}

// wantPacket applies the same filter as the libpcap BPF filter: "tcp && not (port 9092 or port 22)"
func wantPacket(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	var tcpOffset int
	switch data[0] >> 4 {
	case 4:
		tcpOffset = ipv4TCPOffset(data)
	case 6:
		tcpOffset = ipv6TCPOffset(data)
	default:
		return false
	}
	if tcpOffset < 0 || len(data) < tcpOffset+4 {
		return false
	}
	srcPort := binary.BigEndian.Uint16(data[tcpOffset:])
	dstPort := binary.BigEndian.Uint16(data[tcpOffset+2:])
	return !excludedPorts[srcPort] && !excludedPorts[dstPort]
}

// ipv4TCPOffset returns where the TCP header starts, or -1 if the packet doesn't carry one
func ipv4TCPOffset(data []byte) int {
	if len(data) < 20 || data[9] != uint8(layers.IPProtocolTCP) {
		return -1
	}
	// later fragments carry no TCP header
	if binary.BigEndian.Uint16(data[6:8])&0x1fff != 0 {
		return -1
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 {
		return -1
	}
	return ihl
}

// ipv6TCPOffset returns where the TCP header starts, skipping extension headers, or -1 if the
// packet doesn't carry one
func ipv6TCPOffset(data []byte) int {
	if len(data) < 40 {
		return -1
	}
	next, offset := layers.IPProtocol(data[6]), 40
	for {
		switch next {
		case layers.IPProtocolTCP:
			return offset
		case layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Routing, layers.IPProtocolIPv6Destination:
			if len(data) < offset+2 {
				return -1
			}
			next, offset = layers.IPProtocol(data[offset]), offset+(int(data[offset+1])+1)*8
		case layers.IPProtocolIPv6Fragment:
			if len(data) < offset+8 {
				return -1
			}
			// later fragments carry no TCP header
			if binary.BigEndian.Uint16(data[offset+2:offset+4])&0xfff8 != 0 {
				return -1
			}
			next, offset = layers.IPProtocol(data[offset]), offset+8
		default:
			return -1
		}
	}
}
