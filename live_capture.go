package main
/*
import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "log"
    "time"
	"github.com/google/gopacket/layers"

)

var (
    device       string = "eth0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

func main() {
    // Open device
	if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	  } else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {  // optional
		panic(err)
	  } else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			udpContent := packet.TransportLayer().(*layers.UDP)
			// log.Println("%v", udpContent.Payload)
	
			innerPacket := gopacket.NewPacket(udpContent.Payload[8:], layers.LayerTypeEthernet, gopacket.Default)
	
			// log.Println("%v", innerPacket)
	
			if innerPacket.NetworkLayer() == nil || innerPacket.TransportLayer() == nil || innerPacket.TransportLayer().LayerType() != layers.LayerTypeTCP {
				// log.Println("not a tcp payload")
				continue
			} else {
				tcp := innerPacket.TransportLayer().(*layers.TCP)
				log.Println(string(tcp.Payload))
			}
			}
	  }
}

*/