package utils

import (
	"strconv"
)

func Abs(x int32) int32 {
	if x < 0 {
		return -x
	}
	return x
}

func FormatAddr(addr uint32, port uint16) string {
	b := make([]byte, 0, 21) // "255.255.255.255:65535"
	b = strconv.AppendUint(b, uint64(addr&0xff), 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, uint64(addr>>8&0xff), 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, uint64(addr>>16&0xff), 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, uint64(addr>>24&0xff), 10)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(port), 10)
	return string(b)
}
