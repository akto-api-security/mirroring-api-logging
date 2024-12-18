package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

//fd: 4 id: 19121194406244 ip: 3885957130 port: 48267 startns: 58269939225740

type ConnID struct {
	Id            uint64
	Fd            uint32
	Padding1      [4]byte
	Conn_start_ns uint64
	Port          uint16
	Padding       [2]byte
	Ip            uint32
}

type SocketDataEventAttr struct {
	ConnId           ConnID
	Bytes_sent       int32
	ReadEventsCount  uint32
	WriteEventsCount uint32
	Ssl              bool
}

type SocketDataEvent struct {
	Attr SocketDataEventAttr
	Msg  [30720]byte
}

type SocketOpenEvent struct {
	ConnId         ConnID
	Dip            uint32
	DPort          uint16
	Padding        [2]byte
	Socket_open_ns uint64
}

type SocketCloseEvent struct {
	ConnId         ConnID
	Socket_open_ns uint64
}

func Abs(x int32) int32 {
	if x < 0 {
		return -x
	}
	return x
}

// func main() {
// 	inputChan := make(chan []byte, 1)

// 	// eventAttributesSize := int(unsafe.Sizeof(SocketDataEventAttr{}))

// 	// Simulate incoming data
// 	data := []byte{
// 		3, 55, 15, 0, 245, 54, 15, 0,
// 		15, 0, 0, 0,
// 		0, 0, 0, 0,
// 		129, 92, 38, 102, 132, 177, 0, 0,
// 		21, 56,
// 		0, 0,
// 		10, 0, 197, 220,
// 		10, 244, 3, 64,
// 		126, 142,
// 		0, 0,
// 		129, 92, 38, 102, 132, 177, 0, 0,
// 		0, 0, 0, 0}
// 	inputChan <- data

// 	close(inputChan)

// 	eventAttributesSize := int(unsafe.Sizeof(SocketDataEventAttr{}))
// 	fmt.Printf("%v\n", eventAttributesSize)

// 	for data := range inputChan {
// 		// fmt.Printf("%v\n", data)
// 		var event SocketOpenEvent
// 		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event); err != nil {
// 			log.Printf("Failed to decode received data: %+v", err)
// 			continue
// 		}

// 		fmt.Printf("Id: %d\n", event.ConnId.Id)
// 		fmt.Printf("Fd: %d\n", event.ConnId.Fd)
// 		fmt.Printf("Conn_start_ns: %d\n", event.ConnId.Conn_start_ns)
// 		fmt.Printf("Port: %d\n", event.ConnId.Port)
// 		fmt.Printf("Ip: %d\n", (event.ConnId.Ip))
// 		fmt.Printf("dip: %d\n", (event.Dip))
// 		fmt.Printf("dport: %d\n", (event.DPort))
// 		fmt.Printf("socket ts: %d\n", (event.Socket_open_ns))
// 		// fmt.Printf("ssl: %v\n", (event.Ssl))

// 		x := net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&event.ConnId.Ip)))[:]).String()
// 		fmt.Printf("%v", x)
// 		// eventAttributesLogicalSize := 45
// 		// bytesSent := event.Attr.Bytes_sent

// 		// if len(data) > eventAttributesLogicalSize {
// 		// 	copy(event.Msg[:], data[eventAttributesLogicalSize:eventAttributesLogicalSize+int(Abs(bytesSent))])
// 		// }

// 		// // dataStr := string(event.Msg[:Abs(bytesSent)])
// 		// fmt.Printf("\n%v\n", string(event.Msg[:]))

// 	}
// 	// originalInt := uint32(2861694986)

// 	// // Convert integer to little-endian byte slice
// 	// byteSlice := make([]byte, 4)
// 	// binary.LittleEndian.PutUint32(byteSlice, originalInt)

// 	// // Convert the byte slice to an IP address
// 	// ip := net.IP(byteSlice)

// 	// // Print the IP address
// 	// fmt.Println(ip.String())
// }

// func main() {
// 	bpfVal := 67166218
// 	x := net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&bpfVal)))[:]).String()
// 	fmt.Printf("%v", x)
// }

/*

"destIp":"10.224.0.9:45790","direction":"1","ip":"10.244.3.167:443"
"destIp":"10.224.0.8:35764","direction":"1","ip":"10.244.3.167:443"
"destIp":"10.224.0.12:4151","direction":"1","ip":"10.244.3.167:443"
"destIp":"10.224.0.12:58092","direction":"2","ip":"142.251.111.138:20480"

tcp module
"destIp":"10.244.3.82","direction":"1","ip":"10.224.0.9",

ebpf module
"destIp":"10.244.3.82:9080","direction":"1","ip":"10.224.0.7:26839"

"destIp":"10.244.3.181:443","direction":"1","ip":"10.224.0.4:46520"

*/

/*

 10.244 -> 10.244
 shivansh -> lb
 google -> 10.244

*/

/*
2024-07-20T08:10:58.559091700Z ParseAndProduce: receiveBuffer: GET /123/1123/123 HTTP/1.1
2024-07-20T08:10:58.559227701Z Host: 51.8.200.50:9080
2024-07-20T08:10:58.559234501Z User-Agent: curl/8.5.0
2024-07-20T08:10:58.559237401Z Accept: *
2024-07-20T08:10:58.559240001Z x-debug-token:11444
2024-07-20T08:10:58.559242201Z
2024-07-20T08:10:58.559244801Z  , sentBuffer: HTTP/1.1 200 123
2024-07-20T08:10:58.559247201Z Content-type: application/json
2024-07-20T08:10:58.559249901Z Date: Sat, 20 Jul 2024 08:10:58 GMT
2024-07-20T08:10:58.559256101Z Connection: keep-alive
2024-07-20T08:10:58.559262601Z Keep-Alive: timeout=5
2024-07-20T08:10:58.559267501Z Transfer-Encoding: chunked
2024-07-20T08:10:58.559188101Z 2024/07/20 08:10:58 HTTP-request error: invalid method "HTTP/1.1"
2024-07-20T08:10:58.559287701Z
2024-07-20T08:10:58.559272201Z
2024-07-20T08:10:58.559301701Z 2024/07/20 08:10:58 HTTP-request error: invalid method "HTTP/1.1"
2024-07-20T08:10:58.559306201Z 1e
2024-07-20T08:10:58.559314301Z {"token":"123","hello":"word"}
2024-07-20T08:10:58.559318601Z 0
2024-07-20T08:10:58.559323101Z
2024-07-20T08:10:58.559327101Z
2024-07-20T08:10:58.559331701Z ParseAndProduce: Found count of requests: 1
2024-07-20T08:10:58.559336301Z ParseAndProduce: Found count of responses: 1
2024-07-20T08:10:58.559343501Z req-resp.String() {"akto_account_id":"1000000","akto_vxlan_id":"0","destIp":"10.244.3.82:9080","direction":"1","ip":"10.224.0.12:31002","is_pending":"false","method":"GET","path":"/123/1123/123","requestHeaders":"{\"Accept\":\"**\",\"User-Agent\":\"curl/8.5.0\",\"X-Debug-Token\":\"11444\",\"host\":\"51.8.200.50:9080\"}","requestPayload":"","responseHeaders":"{\"Connection\":\"keep-alive\",\"Content-Type\":\"application/json\",\"Date\":\"Sat, 20 Jul 2024 08:10:58 GMT\",\"Keep-Alive\":\"timeout=5\"}","responsePayload":"{\"token\":\"123\",\"hello\":\"word\"}","source":"MIRRORING","status":"200 123","statusCode":"200","time":"1721463058","type":"HTTP/1.1"}
2024-07-20T08:10:58.559362502Z Good requests: 0 , Bad requests: 1
2024-07-20T08:10:58.559368402Z ParseAndProduce: receiveBuffer: GET /123/1123/123 HTTP/1.1
2024-07-20T08:10:58.559373102Z Host: 51.8.200.50:9080
2024-07-20T08:10:58.559379902Z User-Agent: curl/8.5.0
2024-07-20T08:10:58.559387602Z Accept: **
2024-07-20T08:10:58.559392402Z x-debug-token:11444
2024-07-20T08:10:58.559396802Z
2024-07-20T08:10:58.559401002Z  , sentBuffer: HTTP/1.1 200 123
2024-07-20T08:10:58.559406102Z Content-type: application/json
2024-07-20T08:10:58.559410902Z Date: Sat, 20 Jul 2024 08:10:58 GMT
2024-07-20T08:10:58.559415002Z Connection: keep-alive
2024-07-20T08:10:58.559419402Z Keep-Alive: timeout=5
2024-07-20T08:10:58.559423902Z Transfer-Encoding: chunked
2024-07-20T08:10:58.559428002Z
2024-07-20T08:10:58.559432302Z 1e
2024-07-20T08:10:58.559436402Z {"token":"123","hello":"word"}
2024-07-20T08:10:58.559440502Z 0
2024-07-20T08:10:58.559444402Z
2024-07-20T08:10:58.559448302Z
2024-07-20T08:10:58.559452302Z ParseAndProduce: Found count of requests: 1
2024-07-20T08:10:58.559456702Z ParseAndProduce: Found count of responses: 1
2024-07-20T08:10:58.559468102Z req-resp.String() {"akto_account_id":"1000000","akto_vxlan_id":"0","destIp":"51.8.200.50:30755","direction":"2","ip":"10.224.0.12:40928","is_pending":"false","method":"GET","path":"/123/1123/123","requestHeaders":"{\"Accept\":\"**\",\"User-Agent\":\"curl/8.5.0\",\"X-Debug-Token\":\"11444\",\"host\":\"51.8.200.50:9080\"}","requestPayload":"","responseHeaders":"{\"Connection\":\"keep-alive\",\"Content-Type\":\"application/json\",\"Date\":\"Sat, 20 Jul 2024 08:10:58 GMT\",\"Keep-Alive\":\"timeout=5\"}","responsePayload":"{\"token\":\"123\",\"hello\":\"word\"}","source":"MIRRORING","status":"200 123","statusCode":"200","time":"1721463058","type":"HTTP/1.1"}
2024-07-20T08:10:58.559472702Z Good requests: 0 , Bad requests: 2



*/

func main() {

	// sum := 0
	// for i := 0; i < 10; i++ {
	// 	sum += i
	// 	switch sum {
	// 	case 3:
	// 		fmt.Printf("Hello %v\n", sum)
	// 		continue
	// 	default:
	// 		fmt.Printf("Hello default %v\n", sum)
	// 	}
	// 	fmt.Printf("Hello out %v\n", sum)
	// }

	// originalInt := uint32(994685748)
	// // Convert integer to little-endian byte slice
	// byteSlice := make([]byte, 4)
	// binary.LittleEndian.PutUint32(byteSlice, originalInt)
	// // Convert the byte slice to an IP address
	// ip := net.IP(byteSlice)
	// destIpStr := ip.String()
	// fmt.Printf("%v", destIpStr)

	// var IgnoreIpTraffic = false
	// var IgnoreCloudMetadataCalls = false

	// InitVar("AKTO_IGNORE_IP_TRAFFIC", &IgnoreIpTraffic)
	// InitVar("AKTO_IGNORE_CLOUD_METADATA_CALLS", &IgnoreCloudMetadataCalls)

	// memCheckInterval := 500
	// requestProcessCount := 0
	// lastMemCheck := time.Now().UnixMilli()
	// time.Sleep(501 * time.Millisecond)
	// log.Printf("Core log : %v %v %v %v\n", requestProcessCount, lastMemCheck, (time.Now().UnixMilli())-lastMemCheck > int64(memCheckInterval), memCheckInterval)

	path := "/Users/shivanshagrawal/akto_code/mirroring-api-logging/test/file.txt"

	fmt.Print(checkKubeProcess(path))
}

func checkKubeProcess(exePath string) string {
	cmd := exec.Command("sh", "-c", "strings "+exePath+" | grep cri-containerd | head -n 1")
	// cmd := exec.Command("strings", exePath, "|", "grep", "cri-containerd", "|", "head", "-n", "1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing command in checkKubeProcess: %v\n", err)
		return ""
	}
	return string(output)
}

func InitVar(envVarName string, targetVar interface{}) {
	envVar := os.Getenv(envVarName)
	if len(envVar) > 0 {
		switch v := targetVar.(type) {
		case *bool:
			*v = strings.ToLower(envVar) == "true"
			log.Printf("%s: %t\n", envVarName, *v)
		case *string:
			*v = envVar
			log.Printf("%s: %v\n", envVarName, *v)
		case *time.Duration:
			temp, err := time.ParseDuration(envVar + "s")
			if err == nil {
				*v = temp
				log.Printf("%s: %v\n", envVarName, *v)
			}
		case *int:
			temp, err := strconv.Atoi(envVar)
			if err == nil {
				*v = temp
				log.Printf("%s: %v\n", envVarName, *v)
			}
		default:
			log.Printf("Unsupported type for targetVar: %T\n", v)
		}
	} else {
		log.Printf("%s: missing. using default value %v\n", envVarName, &targetVar)
	}
}
