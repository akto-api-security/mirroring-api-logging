package kafkaUtil

import (
	"strings"
	"time"
)

func getTimeBucket() uint8 {
	minutes := time.Now().Unix() / int64(timeBucketDuration.Seconds())
	return uint8(minutes % 256)
}

func isTimeBucketExpired(storedBucket uint8) bool {
	currentBucket := getTimeBucket()

	var diff int
	if currentBucket >= storedBucket {
		diff = int(currentBucket) - int(storedBucket)
	} else {
		diff = (256 - int(storedBucket)) + int(currentBucket)
	}

	return diff >= 1
}

func buildSignatureKey(method, host, path string) string {
	var sb strings.Builder
	sb.Grow(len(method) + len(host) + len(path) + 2)
	sb.WriteString(method)
	sb.WriteByte('|')
	sb.WriteString(host)
	sb.WriteByte('|')
	sb.WriteString(path)
	return sb.String()
}
