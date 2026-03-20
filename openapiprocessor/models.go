package openapiprocessor

import (
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// Constants for OpenAPI discovery
const (
	DISCOVERY_POLL_DURATION = 15 * time.Minute // 15 minutes polling interval
	API_TYPE_REST           = "REST_API"
	API_TYPE_HTTP           = "HTTP_API"
	EXPORT_FORMAT_OAS30     = "oas30" // OpenAPI 3.0 format
)

// ClientSet holds both API Gateway client types (v1 and v2)
type ClientSet struct {
	RestClient *apigateway.Client   // For REST APIs (v1)
	HttpClient *apigatewayv2.Client // For HTTP APIs (v2)
}

// DiscoveredAPI tracks discovered endpoints for deduplication
type DiscoveredAPI struct {
	APIID          string
	APIName        string
	Stage          string // Empty for HTTP APIs (no stages)
	SpecChecksum   string // MD5 hash of spec content for change detection
	LastDiscovered int64  // Unix timestamp
}

// DiscoveryTracker manages global deduplication state
// Similar to logprocesser's globalTimestampTracker pattern
type DiscoveryTracker struct {
	mu             sync.RWMutex
	discoveredAPIs map[string]*DiscoveredAPI // Key: "roleArn|apiId|stage"
}

// Global tracker instance for deduplication across goroutines
var globalDiscoveryTracker = &DiscoveryTracker{
	discoveredAPIs: make(map[string]*DiscoveredAPI),
}

// GetTracker returns the global discovery tracker instance
func GetTracker() *DiscoveryTracker {
	return globalDiscoveryTracker
}

// RemoveDiscoveredAPI drops the cache entry for this API/stage so a failed upload can be retried on the next poll.
func (t *DiscoveryTracker) RemoveDiscoveredAPI(roleArn, apiID, stage string) {
	key := fmt.Sprintf("%s|%s|%s", roleArn, apiID, stage)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.discoveredAPIs, key)
}
