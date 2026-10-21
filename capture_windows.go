//go:build windows

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
)

// Windows has no libpcap without Npcap, so we capture with raw sockets in SIO_RCVALL mode.
// A raw socket bound to one of an adapter's addresses then receives every packet of that IP
// version sent or received on the adapter, starting at the IP header. Each adapter gets one
// socket for IPv4 and one for IPv6.
const (
	sioRcvall     = 0x98000001
	rcvallOn      = 1 // promiscuous
	rcvallIPLevel = 3 // only packets for this host, for adapters that refuse promiscuous mode
)

type captureTarget struct {
	name  string
	index int // interface index, the zone of an IPv6 link-local address
	ip    net.IP
}

func (t captureTarget) isIPv6() bool {
	return t.ip.To4() == nil
}

func openLiveCapture(interfaceName string) (<-chan gopacket.Packet, func(), error) {
	targets, err := captureTargets(interfaceName)
	if err != nil {
		return nil, nil, err
	}

	var wsaData windows.WSAData
	if err := windows.WSAStartup(uint32(0x202), &wsaData); err != nil {
		return nil, nil, fmt.Errorf("WSAStartup failed: %v", err)
	}

	// same buffer size as gopacket's PacketSource used with libpcap
	packets := make(chan gopacket.Packet, 1000)
	done := make(chan struct{})
	var wg sync.WaitGroup
	opened := 0
	for _, t := range targets {
		sock, err := openRawSocket(t)
		if err != nil {
			log.Printf("skipping interface %q (%s): %v", t.name, t.ip, err)
			continue
		}
		log.Printf("capturing on interface %q (%s)", t.name, t.ip)
		opened++
		wg.Add(1)
		go func() {
			defer wg.Done()
			readRawSocket(sock, t, packets, done)
		}()
	}

	if opened == 0 {
		windows.WSACleanup()
		return nil, nil, fmt.Errorf("could not capture on any interface")
	}

	stopped := make(chan struct{})
	go func() {
		wg.Wait()
		close(packets)
		close(stopped)
	}()

	var once sync.Once
	closeCapture := func() {
		once.Do(func() {
			close(done)
			// readers notice within a second thanks to the receive timeout, the limit only
			// guarantees the main loop can always reopen the capture
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				log.Println("raw socket readers did not stop in time, reopening anyway")
			}
			windows.WSACleanup()
		})
	}

	return packets, closeCapture, nil
}

// captureTargets resolves MIRRORING_INTERFACE. "any" means every interface that is up, otherwise
// it is a comma separated list of interface names (as shown by Get-NetAdapter) or IP addresses.
func captureTargets(interfaceName string) ([]captureTarget, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces failed: %v", err)
	}

	var wanted map[string]bool
	if !strings.EqualFold(interfaceName, "any") {
		wanted = make(map[string]bool)
		for _, w := range strings.Split(interfaceName, ",") {
			if w = strings.TrimSpace(w); w != "" {
				wanted[strings.ToLower(w)] = true
			}
		}
	}

	var targets []captureTarget
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ipv4, ipv6, ipv6LinkLocal net.IP
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if wanted != nil && !wanted[strings.ToLower(iface.Name)] && !wanted[ip.String()] {
				continue
			}
			switch {
			case ip.To4() != nil:
				// 169.254.x.x means the adapter never got an address
				if ipv4 == nil && (wanted != nil || !ip.IsLinkLocalUnicast()) {
					ipv4 = ip.To4()
				}
			case ip.IsLinkLocalUnicast():
				// every IPv6 adapter has an fe80:: address, only used when there is no other
				if ipv6LinkLocal == nil {
					ipv6LinkLocal = ip
				}
			default:
				if ipv6 == nil {
					ipv6 = ip
				}
			}
		}
		if ipv6 == nil {
			ipv6 = ipv6LinkLocal
		}

		// one socket per interface and IP version, SIO_RCVALL already sees every packet on the adapter
		if ipv4 != nil {
			targets = append(targets, captureTarget{name: iface.Name, index: iface.Index, ip: ipv4})
		}
		if ipv6 != nil {
			targets = append(targets, captureTarget{name: iface.Name, index: iface.Index, ip: ipv6})
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no interface matches MIRRORING_INTERFACE=%q", interfaceName)
	}
	return targets, nil
}

func openRawSocket(t captureTarget) (windows.Handle, error) {
	family := windows.AF_INET
	var sa windows.Sockaddr
	if t.isIPv6() {
		family = windows.AF_INET6
		sa6 := &windows.SockaddrInet6{}
		copy(sa6.Addr[:], t.ip.To16())
		if t.ip.IsLinkLocalUnicast() {
			sa6.ZoneId = uint32(t.index)
		}
		sa = sa6
	} else {
		sa4 := &windows.SockaddrInet4{}
		copy(sa4.Addr[:], t.ip.To4())
		sa = sa4
	}

	sock, err := windows.Socket(family, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("creating raw socket failed (is it running as Administrator?): %v", err)
	}

	if err := windows.Bind(sock, sa); err != nil {
		windows.Closesocket(sock)
		return windows.InvalidHandle, fmt.Errorf("bind failed: %v", err)
	}

	// a large buffer avoids drops during bursts, the timeout lets the reader notice shutdown
	windows.SetsockoptInt(sock, windows.SOL_SOCKET, windows.SO_RCVBUF, 16*1024*1024)
	windows.SetsockoptInt(sock, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 1000)

	if err := setRcvall(sock, rcvallOn); err != nil {
		if err2 := setRcvall(sock, rcvallIPLevel); err2 != nil {
			windows.Closesocket(sock)
			return windows.InvalidHandle, fmt.Errorf("enabling SIO_RCVALL failed: %v", err)
		}
		log.Printf("promiscuous mode not supported on %s, capturing only this host's traffic", t.ip)
	}
	return sock, nil
}

func setRcvall(sock windows.Handle, mode uint32) error {
	var returned uint32
	return windows.WSAIoctl(sock, sioRcvall, (*byte)(unsafe.Pointer(&mode)), uint32(unsafe.Sizeof(mode)), nil, 0, &returned, nil, 0)
}

func readRawSocket(sock windows.Handle, t captureTarget, packets chan<- gopacket.Packet, done <-chan struct{}) {
	defer windows.Closesocket(sock)

	// not every Windows version includes the IPv6 header in what a raw socket receives,
	// without it the packets can't be matched to connections
	headerChecked := !t.isIPv6()

	buf := make([]byte, 65536)
	for {
		select {
		case <-done:
			return
		default:
		}

		n, _, err := windows.Recvfrom(sock, buf, 0)
		if err != nil {
			if errors.Is(err, windows.WSAETIMEDOUT) || errors.Is(err, windows.WSAEMSGSIZE) {
				continue
			}
			log.Printf("raw socket read failed on %q (%s), stopping it: %v", t.name, t.ip, err)
			return
		}

		if !headerChecked {
			if !hasIPv6Header(buf[:n]) {
				log.Printf("IPv6 packets on %q (%s) arrive without their IP header, IPv6 capture is not supported on this system", t.name, t.ip)
				return
			}
			headerChecked = true
		}

		if !wantPacket(buf[:n]) {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		firstLayer := layers.LayerTypeIPv4
		if data[0]>>4 == 6 {
			firstLayer = layers.LayerTypeIPv6
			fixIPv6OffloadLength(data)
		}
		packet := gopacket.NewPacket(data, firstLayer, gopacket.DecodeOptions{NoCopy: true})
		metadata := packet.Metadata()
		metadata.Timestamp = time.Now()
		metadata.CaptureLength = n
		metadata.Length = n

		select {
		case packets <- packet:
		case <-done:
			return
		}
	}
}
