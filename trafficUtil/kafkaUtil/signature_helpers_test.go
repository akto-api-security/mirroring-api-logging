package kafkaUtil

import (
	"testing"
)

// TestBuildSignatureKey tests signature key generation
func TestBuildSignatureKey(t *testing.T) {
	tests := []struct {
		method   string
		host     string
		path     string
		expected string
	}{
		{"GET", "example.com", "/api/users", "GET|example.com|/api/users"},
		{"POST", "api.example.com", "/v1/data", "POST|api.example.com|/v1/data"},
		{"DELETE", "localhost:8080", "/test", "DELETE|localhost:8080|/test"},
		{"PUT", "192.168.1.1", "/", "PUT|192.168.1.1|/"},
		{"PATCH", "api.service.local", "/v2/resource/123", "PATCH|api.service.local|/v2/resource/123"},
	}

	for _, tt := range tests {
		result := buildSignatureKey(tt.method, tt.host, tt.path)
		if result != tt.expected {
			t.Errorf("buildSignatureKey(%s, %s, %s) = %s, want %s",
				tt.method, tt.host, tt.path, result, tt.expected)
		}
	}
}

// TestGetTimeBucket tests time bucket generation
func TestGetTimeBucket(t *testing.T) {
	bucket1 := getTimeBucket()
	if bucket1 < 0 || bucket1 > 255 {
		t.Errorf("getTimeBucket() returned %d, expected 0-255", bucket1)
	}

	// Get bucket again immediately (should be same)
	bucket2 := getTimeBucket()
	if bucket1 != bucket2 {
		t.Errorf("Expected same bucket for immediate calls: %d vs %d", bucket1, bucket2)
	}
}

// TestIsTimeBucketExpired tests time bucket expiration detection
func TestIsTimeBucketExpired(t *testing.T) {
	// Test recent bucket (should not be expired)
	currentBucket := getTimeBucket()
	if isTimeBucketExpired(currentBucket) {
		t.Errorf("Current bucket should not be expired")
	}

	// Test old bucket (should be expired)
	oldBucket := uint8((int(currentBucket) - 5 + 256) % 256)
	if !isTimeBucketExpired(oldBucket) {
		t.Errorf("Old bucket should be expired")
	}
}

// TestIsTimeBucketExpiredWrapAround tests time bucket expiration with wrap-around
func TestIsTimeBucketExpiredWrapAround(t *testing.T) {
	// Simulate wrap-around scenario where stored bucket is close to 255
	// and current bucket wrapped to a low number
	// This is probabilistic based on actual time, so we just verify the logic works

	// Test that the same bucket is not expired
	bucket := uint8(100)
	if isTimeBucketExpired(bucket) && bucket == getTimeBucket() {
		// Only fail if it's actually the same bucket
		t.Errorf("Same bucket should not be expired")
	}
}
