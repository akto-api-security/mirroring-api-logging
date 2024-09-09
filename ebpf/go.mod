module github.com/akto-api-security/mirroring-api-logging/ebpf

go 1.21

require (
	github.com/akto-api-security/mirroring-api-logging/trafficUtil v0.0.0-00010101000000-000000000000
	github.com/iovisor/gobpf v0.2.1-0.20221005153822-16120a1bf4d4
	github.com/shirou/gopsutil v3.21.11+incompatible
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/klauspost/compress v1.17.7 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/pierrec/lz4 v2.6.0+incompatible // indirect
	github.com/segmentio/kafka-go v0.4.25 // indirect
	github.com/tklauser/go-sysconf v0.3.13 // indirect
	github.com/tklauser/numcpus v0.7.0 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.mongodb.org/mongo-driver v1.14.0 // indirect
	golang.org/x/arch v0.7.0
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/akto-api-security/mirroring-api-logging/trafficUtil => ../trafficUtil
