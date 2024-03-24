module github.com/akto-api-security/mirroring-api-logging

go 1.17

require (
	github.com/google/gopacket v1.1.19
	go.mongodb.org/mongo-driver v1.11.3
)

require (
	github.com/akto-api-security/mirroring-api-logging/trafficUtil v0.0.0-00010101000000-000000000000
	github.com/golang/snappy v0.0.1 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe // indirect
	github.com/pierrec/lz4 v2.6.0+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/segmentio/kafka-go v0.4.25 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.1 // indirect
	github.com/xdg-go/stringprep v1.0.3 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	golang.org/x/text v0.3.7 // indirect
)

replace github.com/akto-api-security/mirroring-api-logging/trafficUtil => ./trafficUtil