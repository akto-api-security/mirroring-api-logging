package main

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildPacket(t *testing.T, ipv6 bool, proto layers.IPProtocol, srcPort, dstPort uint16, payload string) []byte {
	t.Helper()
	var network gopacket.SerializableLayer
	var networkLayer gopacket.NetworkLayer
	if ipv6 {
		ip := &layers.IPv6{Version: 6, NextHeader: proto, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		network, networkLayer = ip, ip
	} else {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
		network, networkLayer = ip, ip
	}

	var transport gopacket.SerializableLayer
	if proto == layers.IPProtocolUDP {
		udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
		udp.SetNetworkLayerForChecksum(networkLayer)
		transport = udp
	} else {
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), Seq: 1, PSH: true, ACK: true, Window: 1024}
		tcp.SetNetworkLayerForChecksum(networkLayer)
		transport = tcp
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, network, transport, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// insertIPv6Extension puts an extension header between the IPv6 header and the TCP header
func insertIPv6Extension(data []byte, extension layers.IPProtocol, header []byte) []byte {
	header[0] = data[6]
	data[6] = uint8(extension)
	out := append([]byte{}, data[:40]...)
	out = append(out, header...)
	out = append(out, data[40:]...)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	return out
}

func TestWantPacket(t *testing.T) {
	destinationOptions := func(data []byte) []byte {
		return insertIPv6Extension(data, layers.IPProtocolIPv6Destination, make([]byte, 8))
	}
	firstFragment := func(data []byte) []byte {
		return insertIPv6Extension(data, layers.IPProtocolIPv6Fragment, make([]byte, 8))
	}
	laterFragment := func(data []byte) []byte {
		fragment := make([]byte, 8)
		binary.BigEndian.PutUint16(fragment[2:4], 185<<3)
		return insertIPv6Extension(data, layers.IPProtocolIPv6Fragment, fragment)
	}

	tests := []struct {
		name   string
		data   []byte
		wanted bool
	}{
		{"ipv4 http", buildPacket(t, false, layers.IPProtocolTCP, 51234, 8090, "GET / HTTP/1.1\r\n\r\n"), true},
		{"ipv4 kafka", buildPacket(t, false, layers.IPProtocolTCP, 51234, 9092, "x"), false},
		{"ipv4 ssh reply", buildPacket(t, false, layers.IPProtocolTCP, 22, 51234, "x"), false},
		{"ipv4 udp", buildPacket(t, false, layers.IPProtocolUDP, 51234, 8090, "x"), false},
		{"ipv6 http", buildPacket(t, true, layers.IPProtocolTCP, 51234, 8090, "GET / HTTP/1.1\r\n\r\n"), true},
		{"ipv6 kafka", buildPacket(t, true, layers.IPProtocolTCP, 9092, 51234, "x"), false},
		{"ipv6 udp", buildPacket(t, true, layers.IPProtocolUDP, 51234, 8090, "x"), false},
		{"ipv6 extension header before tcp", destinationOptions(buildPacket(t, true, layers.IPProtocolTCP, 51234, 8090, "x")), true},
		{"ipv6 extension header before kafka", destinationOptions(buildPacket(t, true, layers.IPProtocolTCP, 51234, 9092, "x")), false},
		{"ipv6 first fragment", firstFragment(buildPacket(t, true, layers.IPProtocolTCP, 51234, 8090, "x")), true},
		{"ipv6 later fragment", laterFragment(buildPacket(t, true, layers.IPProtocolTCP, 51234, 8090, "x")), false},
		{"truncated ipv6", buildPacket(t, true, layers.IPProtocolTCP, 51234, 8090, "x")[:41], false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wantPacket(tt.data); got != tt.wanted {
				t.Errorf("wantPacket() = %v, want %v", got, tt.wanted)
			}
		})
	}
}

func TestHasIPv6Header(t *testing.T) {
	ipv6 := buildPacket(t, true, layers.IPProtocolTCP, 51234, 8090, "GET / HTTP/1.1\r\n\r\n")
	offload := append([]byte{}, ipv6...)
	binary.BigEndian.PutUint16(offload[4:6], 0)
	// what a raw socket would return if Windows left out the IPv6 header: the TCP segment, here
	// with a source port that looks like an IPv6 version field and a sequence number that looks
	// like an offloaded length
	request := "GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
	withoutHeader := buildPacket(t, true, layers.IPProtocolTCP, 0x6000, 8090, request)[40:]

	tests := []struct {
		name   string
		data   []byte
		wanted bool
	}{
		{"ipv6 packet", ipv6, true},
		{"offloaded ipv6 packet", offload, true},
		{"ipv4 packet", buildPacket(t, false, layers.IPProtocolTCP, 51234, 8090, "x"), false},
		{"tcp segment without ip header", withoutHeader, false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasIPv6Header(tt.data); got != tt.wanted {
				t.Errorf("hasIPv6Header() = %v, want %v", got, tt.wanted)
			}
		})
	}
}

func TestFixIPv6OffloadLength(t *testing.T) {
	payload := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	data := buildPacket(t, true, layers.IPProtocolTCP, 8090, 51234, payload)
	binary.BigEndian.PutUint16(data[4:6], 0)

	if packet := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default); packet.TransportLayer() != nil {
		t.Fatal("expected gopacket to reject an IPv6 packet with length 0")
	}

	fixIPv6OffloadLength(data)
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default)
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		t.Fatalf("expected a TCP layer after the fix, got %v", packet.ErrorLayer())
	}
	if string(tcp.Payload) != payload {
		t.Errorf("payload = %q, want %q", tcp.Payload, payload)
	}
}
