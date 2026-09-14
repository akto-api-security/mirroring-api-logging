package kafkaUtil

import (
	"strings"
	"time"
)

// getTimeBucket converts current time to a uint8 bucket (0-255)
// Each bucket represents a 10-minute interval
// Wraps around every ~42 hours (256 * 10 min)
func getTimeBucket() uint8 {
	minutes := time.Now().Unix() / int64(timeBucketDuration.Seconds())
	return uint8(minutes % 256)
}

// isTimeBucketExpired checks if a time bucket is older than the interval
// Accounts for wrap-around (255 -> 0)
func isTimeBucketExpired(storedBucket uint8) bool {
	currentBucket := getTimeBucket()

	// Calculate difference accounting for wrap-around
	var diff int
	if currentBucket >= storedBucket {
		diff = int(currentBucket) - int(storedBucket)
	} else {
		// Wrapped around: e.g., stored=250, current=5
		diff = (256 - int(storedBucket)) + int(currentBucket)
	}

	// If diff >= 1, it's been at least 10 minutes
	return diff >= 1
}

// buildSignatureKey creates a unique key from method, host, and path.
// Format: "METHOD|HOST|PATH"
// Uses strings.Builder for efficient concatenation.
// Examples:
//   - buildSignatureKey("GET", "example.com", "/api/users") -> "GET|example.com|/api/users"
//   - buildSignatureKey("POST", "api.example.com", "/v1/data") -> "POST|api.example.com|/v1/data"
func buildSignatureKey(method, host, path string) string {
	var sb strings.Builder
	// Pre-allocate capacity: method(4) + host(20) + path(20) + separators(2) ≈ 46
	sb.Grow(len(method) + len(host) + len(path) + 2)
	sb.WriteString(method)
	sb.WriteByte('|')
	sb.WriteString(host)
	sb.WriteByte('|')
	sb.WriteString(path)
	return sb.String()
}
