package accountconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akto-api-security/api-gateway-logging/trafficUtil/utils"
)

// AccountMapping represents a single AWS→Akto account mapping
type AccountMapping struct {
	AktoAccountId int    `json:"aktoAccountId"`
	AwsAccountId  string `json:"awsAccountId"`
	Type          string `json:"type"`
}

// AccountMappingManager manages AWS→Akto account ID mappings
type AccountMappingManager struct {
	mu                  sync.RWMutex
	awsToAktoMapping    map[string]int // awsAccountId → aktoAccountId
	cyborgBaseURL       string
	databaseAbstractorToken string
	lastFetchTime       time.Time
	fetchIntervalMinutes int
}

var globalAccountMappingManager *AccountMappingManager

// Initialize initializes the global account mapping manager
func Initialize(cyborgBaseURL, databaseAbstractorToken string, fetchIntervalMinutes int) {
	globalAccountMappingManager = &AccountMappingManager{
		awsToAktoMapping:        make(map[string]int),
		cyborgBaseURL:           cyborgBaseURL,
		databaseAbstractorToken: databaseAbstractorToken,
		fetchIntervalMinutes:    fetchIntervalMinutes,
	}

	// Fetch mappings immediately on startup
	globalAccountMappingManager.FetchMappings()

	// Start periodic refresh in background
	go func() {
		ticker := time.NewTicker(time.Duration(fetchIntervalMinutes) * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			globalAccountMappingManager.FetchMappings()
		}
	}()
}

// FetchMappings fetches AWS→Akto account mappings from Cyborg
func (m *AccountMappingManager) FetchMappings() {
	if m.databaseAbstractorToken == "" {
		utils.LogToCyborg("warn", "DATABASE_ABSTRACTOR_TOKEN not set, skipping account mapping fetch")
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	url := strings.TrimRight(m.cyborgBaseURL, "/") + "/api/fetchAwsAccountIdMappings"
	utils.LogToCyborg("info", fmt.Sprintf("Fetching account mappings from: %s", url))

	// Send POST request with empty JSON body (Akto convention)
	body := strings.NewReader("{}")
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		utils.LogToCyborg("error", fmt.Sprintf("Error creating request for account mappings: %v", err))
		return
	}

	req.Header.Set("Authorization", m.databaseAbstractorToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		utils.LogToCyborg("error", fmt.Sprintf("Error fetching account mappings from %s: %v", url, err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		utils.LogToCyborg("error", fmt.Sprintf("Account mapping API returned %d: %s", resp.StatusCode, string(body)))
		return
	}

	var mappings []AccountMapping
	if err := json.NewDecoder(resp.Body).Decode(&mappings); err != nil {
		utils.LogToCyborg("error", fmt.Sprintf("Error decoding account mappings: %v", err))
		return
	}

	utils.LogToCyborg("info", fmt.Sprintf("Received %d total mappings from Cyborg", len(mappings)))

	// Update the mapping
	m.mu.Lock()
	defer m.mu.Unlock()

	m.awsToAktoMapping = make(map[string]int)
	for _, mapping := range mappings {
		if mapping.Type == "AWS-ACCOUNTS" {
			m.awsToAktoMapping[mapping.AwsAccountId] = mapping.AktoAccountId
			utils.LogToCyborg("info", fmt.Sprintf("Mapped AWS account %s → Akto account %d", mapping.AwsAccountId, mapping.AktoAccountId))
		}
	}
	m.lastFetchTime = time.Now()

	utils.LogToCyborg("info", fmt.Sprintf("Successfully fetched %d AWS→Akto account mappings", len(m.awsToAktoMapping)))
}

// GetAktoAccountId retrieves the Akto account ID for a given AWS account ID
// Returns the aktoAccountId if found, otherwise returns the default account ID (1000000)
func GetAktoAccountId(awsAccountId string) int {
	if globalAccountMappingManager == nil {
		return 1000000
	}

	globalAccountMappingManager.mu.RLock()
	defer globalAccountMappingManager.mu.RUnlock()

	if aktoAccountId, exists := globalAccountMappingManager.awsToAktoMapping[awsAccountId]; exists {
		return aktoAccountId
	}

	// Log when AWS account is not found in mappings (uses default)
	if awsAccountId != "" {
		utils.LogToCyborg("warn", fmt.Sprintf("AWS account ID %s not found in mappings, using default account 1000000", awsAccountId))
	}
	return 1000000
}

// GetAllMappings returns a copy of all current mappings (for debugging/monitoring)
func GetAllMappings() map[string]int {
	if globalAccountMappingManager == nil {
		return make(map[string]int)
	}

	globalAccountMappingManager.mu.RLock()
	defer globalAccountMappingManager.mu.RUnlock()

	mappingsCopy := make(map[string]int)
	for k, v := range globalAccountMappingManager.awsToAktoMapping {
		mappingsCopy[k] = v
	}
	return mappingsCopy
}

// ExtractAwsAccountIdFromLogGroupArn extracts AWS account ID from API Gateway log group ARN
// ARN format: arn:aws:logs:region:account-id:log-group:API-Gateway-Execution-Logs_...
// Returns empty string if not found
func ExtractAwsAccountIdFromLogGroupArn(logGroupArn string) string {
	// Example ARN: arn:aws:logs:us-east-1:123456789012:log-group:API-Gateway-Execution-Logs_xyz/Prod
	parts := strings.Split(logGroupArn, ":")
	if len(parts) >= 5 {
		// AWS account ID is at index 4 (0-indexed)
		accountId := parts[4]
		// Validate it's numeric
		if _, err := strconv.ParseInt(accountId, 10, 64); err == nil {
			return accountId
		}
	}
	return ""
}
