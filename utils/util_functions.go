package utils

import "strings"

func CheckIfIpHost(host string) bool {
	return strings.ToLower(host) == strings.ToUpper(host)
}
