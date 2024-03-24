package utils

import (
	"net"
	"strings"
)

func CheckIfIpHost(host string) bool {
	return strings.ToLower(host) == strings.ToUpper(host)
}

func CheckIfIp(host string) bool {
	if len(host) == 0 {
		return true
	}
	chunks := strings.Split(host, ":")
	return net.ParseIP(chunks[0]) != nil
}
