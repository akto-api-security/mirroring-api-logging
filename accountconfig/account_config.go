package accountconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	fmt.Println("[ACCOUNT_CONFIG] Initialize() called - setting up account mapping manager")
	os.Stdout.Sync()

	globalAccountMappingManager = &AccountMappingManager{
		awsToAktoMapping:        make(map[string]int),
		cyborgBaseURL:           cyborgBaseURL,
		databaseAbstractorToken: databaseAbstractorToken,
		fetchIntervalMinutes:    fetchIntervalMinutes,
	}

	fmt.Println("[ACCOUNT_CONFIG] About to call FetchMappings() immediately")
	os.Stdout.Sync()

	// Fetch mappings immediately on startup
	globalAccountMappingManager.FetchMappings()
	os.Stdout.Sync()

	fmt.Println("[ACCOUNT_CONFIG] FetchMappings() completed, starting background refresh")
	os.Stdout.Sync()

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
	fmt.Println("[ACCOUNT_CONFIG] FetchMappings() called")
	os.Stdout.Sync()

	if m.databaseAbstractorToken == "" {
		fmt.Println("[ACCOUNT_CONFIG] DATABASE_ABSTRACTOR_TOKEN is empty, skipping")
		os.Stdout.Sync()
		utils.LogToCyborg("warn", "DATABASE_ABSTRACTOR_TOKEN not set, skipping account mapping fetch")
		return
	}
	fmt.Println("[ACCOUNT_CONFIG] DATABASE_ABSTRACTOR_TOKEN is set")
	os.Stdout.Sync()

	client := &http.Client{Timeout: 10 * time.Second}
	url := strings.TrimRight(m.cyborgBaseURL, "/") + "/api/fetchAwsAccountIdMappings"
	fmt.Printf("[ACCOUNT_CONFIG] Fetching account mappings from: %s\n", url)
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("Fetching account mappings from: %s", url))

	// Send POST request with empty JSON body (Akto convention)
	fmt.Println("[ACCOUNT_CONFIG] Creating HTTP request")
	os.Stdout.Sync()

	body := strings.NewReader("{}")
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		fmt.Printf("[ACCOUNT_CONFIG] ERROR: Failed to create request: %v\n", err)
		os.Stdout.Sync()
		utils.LogToCyborg("error", fmt.Sprintf("Error creating request for account mappings: %v", err))
		return
	}
	fmt.Println("[ACCOUNT_CONFIG] HTTP request created successfully")
	os.Stdout.Sync()

	fmt.Println("[ACCOUNT_CONFIG] Setting request headers...")
	os.Stdout.Sync()
	req.Header.Set("Authorization", m.databaseAbstractorToken)
	fmt.Println("[ACCOUNT_CONFIG] Authorization header set")
	os.Stdout.Sync()
	req.Header.Set("Content-Type", "application/json")
	fmt.Println("[ACCOUNT_CONFIG] Content-Type header set to application/json")
	os.Stdout.Sync()

	fmt.Println("[ACCOUNT_CONFIG] Request details:")
	fmt.Printf("[ACCOUNT_CONFIG]   Method: POST\n")
	fmt.Printf("[ACCOUNT_CONFIG]   URL: %s\n", url)
	fmt.Printf("[ACCOUNT_CONFIG]   Body: {}\n")
	fmt.Printf("[ACCOUNT_CONFIG]   Headers: Authorization=<set>, Content-Type=application/json\n")
	os.Stdout.Sync()

	fmt.Println("[ACCOUNT_CONFIG] Sending HTTP request to Cyborg...")
	os.Stdout.Sync()
	startTime := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(startTime)

	if err != nil {
		fmt.Printf("[ACCOUNT_CONFIG] ERROR: HTTP request failed after %v: %v\n", elapsed, err)
		os.Stdout.Sync()
		utils.LogToCyborg("error", fmt.Sprintf("Error fetching account mappings from %s: %v", url, err))
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[ACCOUNT_CONFIG] HTTP request completed in %v\n", elapsed)
	os.Stdout.Sync()
	fmt.Printf("[ACCOUNT_CONFIG] Response Status Code: %d\n", resp.StatusCode)
	os.Stdout.Sync()

	fmt.Println("[ACCOUNT_CONFIG] Response Headers:")
	for headerName, headerValues := range resp.Header {
		for _, headerValue := range headerValues {
			if headerName == "Authorization" {
				fmt.Printf("[ACCOUNT_CONFIG]   %s: <redacted>\n", headerName)
			} else {
				fmt.Printf("[ACCOUNT_CONFIG]   %s: %s\n", headerName, headerValue)
			}
		}
	}
	os.Stdout.Sync()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		respBodyStr := string(respBody)
		fmt.Printf("[ACCOUNT_CONFIG] ERROR: Account mapping API returned status %d\n", resp.StatusCode)
		os.Stdout.Sync()
		fmt.Printf("[ACCOUNT_CONFIG] Response body: %s\n", respBodyStr)
		os.Stdout.Sync()
		utils.LogToCyborg("error", fmt.Sprintf("Account mapping API returned %d: %s", resp.StatusCode, respBodyStr))
		return
	}

	fmt.Println("[ACCOUNT_CONFIG] Response status is 200 OK, parsing JSON...")
	os.Stdout.Sync()

	var mappings []AccountMapping
	if err := json.NewDecoder(resp.Body).Decode(&mappings); err != nil {
		fmt.Printf("[ACCOUNT_CONFIG] ERROR: Failed to decode JSON response: %v\n", err)
		os.Stdout.Sync()
		utils.LogToCyborg("error", fmt.Sprintf("Error decoding account mappings: %v", err))
		return
	}
	fmt.Println("[ACCOUNT_CONFIG] JSON response decoded successfully")
	os.Stdout.Sync()

	fmt.Printf("[ACCOUNT_CONFIG] Received %d total mappings from Cyborg\n", len(mappings))
	os.Stdout.Sync()
	utils.LogToCyborg("info", fmt.Sprintf("Received %d total mappings from Cyborg", len(mappings)))

	if len(mappings) == 0 {
		fmt.Println("[ACCOUNT_CONFIG] WARNING: Response contained 0 mappings")
		os.Stdout.Sync()
	} else {
		fmt.Println("[ACCOUNT_CONFIG] Response mappings:")
		for i, m := range mappings {
			fmt.Printf("[ACCOUNT_CONFIG]   [%d] awsAccountId=%s, aktoAccountId=%d, type=%s\n", i, m.AwsAccountId, m.AktoAccountId, m.Type)
		}
		os.Stdout.Sync()
	}

	// Update the mapping
	fmt.Println("[ACCOUNT_CONFIG] Acquiring lock to update mappings...")
	os.Stdout.Sync()
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Println("[ACCOUNT_CONFIG] Lock acquired, clearing old mappings")
	os.Stdout.Sync()

	m.awsToAktoMapping = make(map[string]int)
	successCount := 0
	for _, mapping := range mappings {
		if mapping.Type == "AWS-ACCOUNTS" {
			m.awsToAktoMapping[mapping.AwsAccountId] = mapping.AktoAccountId
			successCount++
			fmt.Printf("[ACCOUNT_CONFIG] [SUCCESS] Mapped AWS account %s → Akto account %d\n", mapping.AwsAccountId, mapping.AktoAccountId)
			os.Stdout.Sync()
			utils.LogToCyborg("info", fmt.Sprintf("Mapped AWS account %s → Akto account %d", mapping.AwsAccountId, mapping.AktoAccountId))
		} else {
			fmt.Printf("[ACCOUNT_CONFIG] [SKIP] Skipping mapping with type=%s (expected AWS-ACCOUNTS)\n", mapping.Type)
			os.Stdout.Sync()
		}
	}
	m.lastFetchTime = time.Now()
	fmt.Printf("[ACCOUNT_CONFIG] Updated lastFetchTime to: %v\n", m.lastFetchTime)
	os.Stdout.Sync()

	fmt.Printf("[ACCOUNT_CONFIG] ===== FETCH COMPLETE =====\n")
	fmt.Printf("[ACCOUNT_CONFIG] Total mappings received: %d\n", len(mappings))
	fmt.Printf("[ACCOUNT_CONFIG] Mappings processed: %d\n", successCount)
	fmt.Printf("[ACCOUNT_CONFIG] Current awsToAktoMapping size: %d\n", len(m.awsToAktoMapping))
	fmt.Println("[ACCOUNT_CONFIG] ===== END FETCH =====")
	os.Stdout.Sync()
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
